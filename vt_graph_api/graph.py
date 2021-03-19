"""vt_graph_api.graph.

This module provides the Python object wrapper for
VirusTotal Graph representation.

Documentation:
  VT API: https://virustotal.github.io/vt-graph-api/
"""


import collections
import functools
import json
import logging
import os
import threading

import concurrent.futures
import requests
import six
import shutil
import vt_graph_api.errors
import vt_graph_api.helpers
import vt_graph_api.node
import vt_graph_api.version


class VTGraph(object):
  """Python object wrapper for Virustotal Graph representation.

  Attributes:
    api_key (str): VT API Key.
    graph_id (str): graph identifier for VT.
    name (str): graph title.
    api_calls (int): total api calls consumed by graph.
    private (bool): whether graph is private or not.
    user_editors ([str]): list with users that can edit graph.
    user_viewers ([str]): list with users that can see graph.
    group_editors ([str]): list with groups that can edit graph.
    group_viewers ([str]): list with groups that can see graph.
    verbose (bool): if True log will be displayed.
    nodes (dict): graph nodes.
    links (dict): graph links.
  """

  MAX_CHARACTERS = 100
  MIN_API_EXPANSION_NUMBER = 10
  MAX_API_EXPANSION_LIMIT = 40
  MAX_PARALLEL_REQUESTS = 1000
  REQUEST_TIMEOUT = 40

  @staticmethod
  def is_viewer(vt_user, graph_id, api_key):
    """Check if the given vt_user can view the graph with the given graph_id.

    Args:
        vt_user (str): VirusTotal user/group name.
        graph_id (str): VirusTotal Graph ID.
        api_key (str): VirusTotal Api key.

    Returns:
      bool: whether the given vt_user can view the graph.
    """
    graph = VTGraph(api_key)
    graph.graph_id = graph_id
    graph._pull_viewers()
    return vt_user in graph.user_viewers or vt_user in graph.group_viewers

  @staticmethod
  def is_editor(vt_user, graph_id, api_key):
    """Check if the given vt_user can edit the graph with the given graph_id.

    Args:
        vt_user (str): VirusTotal user/group name.
        graph_id (str): VirusTotal Graph ID.
        api_key (str): VirusTotal Api key.

    Returns:
      bool: whether the given vt_user can edit the graph.
    """
    graph = VTGraph(api_key)
    graph.graph_id = graph_id
    graph._pull_editors()
    return vt_user in graph.user_editors or vt_user in graph.group_editors

  @staticmethod
  def load_graph(graph_id, api_key):
    """Load the graph using the given VirusTotal graph id.

    Args:
      graph_id (str): VirusTotal Graph ID.
      api_key (str): VirusTotal API key.

    Raises:
      vt_graph_api.errors.LoadError: whether the given graph_id cannot be
        found or JSON does not have the correct structure.
      vt_graph_api.errors.InvalidJSONError: if the JSON response is invalid.

    Returns:
      VTGraph: the imported graph.
    """
    graph = None
    headers = {"x-apikey": api_key, "x-tool": vt_graph_api.version.__x_tool__}

    # Get graph data.
    graph_data_url = (
        "https://www.virustotal.com/api/v3/graphs/{graph_id}"
        .format(graph_id=graph_id))
    graph_data_response = requests.get(graph_data_url, headers=headers)
    if graph_data_response.status_code != 200:
      raise vt_graph_api.errors.LoadError(
          ("Error to find graph with id: {graph_id}. Response code: " +
           "{status_code}.").format(
               graph_id=graph_id, status_code=graph_data_response.status_code))

    try:
      data = graph_data_response.json()
    except json.JSONDecodeError:
      raise vt_graph_api.errors.LoadError(
          "Malformed JSON response: {json_response}"
          .format(json_response=graph_data_response.text))

    try:
      graph_name = data["data"]["attributes"]["graph_data"]["description"]
      private = data["data"]["attributes"]["private"]
      nodes = data["data"]["attributes"]["nodes"]
      links = data["data"]["attributes"]["links"]
    except KeyError as e:
      raise vt_graph_api.errors.InvalidJSONError(
          "Unexpected error in json structure at load_graph: {msg}."
          .format(msg=str(e)))

    # Creates empty graph.
    graph = vt_graph_api.graph.VTGraph(
        api_key=api_key, name=graph_name, private=private)
    graph.graph_id = graph_id
    # Adds users/group viewers and editors.
    graph._pull_viewers()
    graph._pull_editors()
    # Adds nodes to the graph.
    graph._add_nodes_from_json_graph_data(nodes)
    # Adds links to the graph.
    graph._add_links_from_json_graph_data(links)
    return graph

  @staticmethod
  def clone_graph(graph_id, api_key, name="", private=False, user_editors=None,
                  user_viewers=None, group_editors=None, group_viewers=None):
    """Clone VirusTotal Graph and make it yours according the given parameters.

    Args:
      graph_id (str): VirusTotal Graph ID.
      api_key (str): VT API Key
      name (str, optional): graph title. Defaults to "".
      private (bool, optional): true for private graphs. You need to have
        Private Graph premium feature enabled in your subscription. Defaults
        to False.
      user_editors ([str], optional): usernames that can edit the graph.
        Defaults to None.
      user_viewers ([str], optional): usernames that can view the graph.
        Defaults to None.
      group_editors ([str], optional): groups that can edit the graph.
        Defaults to None.
      group_viewers ([str], optional): groups that can view the graph.
        Defaults to None.

    Raises:
      vt_graph_api.errors.LoadError: whether the given graph_id cannot be
        found or JSON does not have the correct structure.

    Returns:
      VTGraph: the cloned graph.
    """
    graph = VTGraph.load_graph(graph_id, api_key)
    graph.private = private
    graph.graph_id = ""
    graph.name = name
    graph.user_editors = user_editors or []
    graph.user_viewers = user_viewers or []
    graph.group_editors = group_editors or []
    graph.group_viewers = group_viewers or []
    return graph

  def __init__(self, api_key, name="", private=False, user_editors=None,
               user_viewers=None, group_editors=None, group_viewers=None,
               verbose=False):
    """Creates a VT Graph Instance.

    Args:
      api_key (str): VT API Key
      name (str, optional): graph title. Defaults to "".
      private (bool, optional): true for private graphs. You need to have
        Private Graph premium feature enabled in your subscription. Defaults
        to False.
      user_editors ([str], optional): usernames that can edit the graph.
        Defaults to None.
      user_viewers ([str], optional): usernames that can view the graph.
        Defaults to None.
      group_editors ([str], optional): groups that can edit the graph.
        Defaults to None.
      group_viewers ([str], optional): groups that can view the graph.
        Defaults to None.
      verbose (bool, optional): true for printing log messages.
        Defaults to False.

    This call does NOT consume API quota.
    """
    self.api_key = api_key

    self.graph_id = ""
    self.name = name
    self._api_calls = 0
    self.private = private
    self.user_editors = user_editors or []
    self.user_viewers = user_viewers or []
    self.group_editors = group_editors or []
    self.group_viewers = group_viewers or []
    self.verbose = verbose

    self.nodes = {}
    self.links = {}

    self._id_references = {}
    self._api_calls_lock = threading.Lock()
    self._nodes_lock = threading.Lock()
    self._index = 0
    self._logger = logging.getLogger("vt_graph")
    self._logger.addHandler(logging.StreamHandler())
    self._logger.setLevel(logging.INFO)

  def _log(self, msg, level=logging.INFO):
    """Prints if verbose is enabled.

    Args:
      msg (str): message.
      level (str, optional): logging debug level. Defaults to info.
    """
    if self.verbose:
      self._logger.setLevel(level)
      self._logger.info(msg)

  def _increment_api_counter(self):
    """Increments api counter in thread safe mode."""
    with self._api_calls_lock:
      self._api_calls += 1
      new_api_calls_value = self._api_calls

    self._log("API counter incremented. Total value: {api_calls}".format(
        api_calls=new_api_calls_value))

  def _get_headers(self):
    """Returns the request headers."""
    return {"x-apikey": self.api_key, "x-tool": vt_graph_api.version.__x_tool__}

  def _get_api_endpoint(self, node_type):
    """Returns the api end point."""
    if node_type == "ip_address":
      return "ip_addresses"
    else:
      return node_type + "s"

  def _add_node_to_output(self, output, node_id):
    """Add the node with the given node_id to the output.

    Args:
      output (dict): graph structure in a json representation.
      node_id (str): node ID.
    """

    node = self.nodes.get(node_id)
    node_type = node.node_type if node else "relationship"
    node_data = {
        "type": node_type,
        "entity_id": node_id,
        "index": self._index,
        "x": node.x if node is not None else 0,
        "y": node.y if node is not None else 0,
    }

    if node:

      if node.label:
        node_data["text"] = node.label

      if node.attributes:
        if node.node_type == "file":
          entity_attributes = {
              "has_detections": node.get_detections(),
          }

          if "type_tag" in node.attributes:
            entity_attributes["type_tag"] = node.attributes["type_tag"]

          node_data["entity_attributes"] = entity_attributes

        # Ip Address.
        elif (node.node_type == "ip_address" and
              "country" in node.attributes):
          entity_attributes = {
              "country": node.attributes["country"],
          }
          node_data["entity_attributes"] = entity_attributes

        # Urls.
        elif node.node_type == "url":
          entity_attributes = {
              "has_detections": node.get_detections(),
          }
          node_data["entity_attributes"] = entity_attributes

      if node.node_type not in vt_graph_api.node.Node.SUPPORTED_NODE_TYPES:
        self._log(
            "Node: {node_id} has custom-type: {node_type}".format(
                node_id=node.node_id, node_type=node.node_type),
            logging.WARNING
        )
        node_data["type"] = "custom"
        node_data["entity_attributes"] = {
            "custom_type": node.node_type
        }

    output["data"]["attributes"]["nodes"].append(node_data)
    self._index += 1

  def _add_nodes_from_json_graph_data(self, json_graph_data_nodes):
    """Add all the nodes from the given data.

    json_graph_data_nodes are the responses from querying VT.

    Raises:
      InvalidJSONError: whether the API response does not have the correct
        structure.

    Args:
      json_graph_data_nodes ([dict]): list of node's data with the following
      structure => {
          "entity_attributes": "",
          "entity_id": "",
          "index": "",
          "type": "",
          "x": "",
          "y": ""
      }
    """
    try:
      non_relationship_nodes = (
          node for node in json_graph_data_nodes
          if node["type"] != "relationship")
      nodes_to_add = []
      for node_data in non_relationship_nodes:
        node_type = node_data["type"]
        if node_type not in vt_graph_api.node.Node.SUPPORTED_NODE_TYPES:
          node_type = node_data["entity_attributes"]["custom_type"]
        nodes_to_add.append({
            "node_id": node_data["entity_id"],
            "node_type": node_type,
            "label": node_data.get("text", ""),
            "attributes": node_data.get("entity_attributes"),
            "x_position": node_data.get("x"),
            "y_position": node_data.get("y")
        })
      # Add all nodes concurrently
      self.add_nodes(nodes_to_add, False, False)
    except KeyError:
      raise vt_graph_api.errors.InvalidJSONError(
          "This is implementation details, the error is coming from the node " +
          "field in the VT response.")

  def _add_links_from_json_graph_data(self, json_graph_data_links):
    """Add all the nodes from the given data.

    json_graph_data_links are the responses from querying VT.

    Raises:
      InvalidJSONError: whether the API response does not have the correct
        structure.

    Args:
      json_graph_data_links ([dict]): list of link's data with the following
      structure => {
          "connection_type": "",
          "source": "",
          "target": ""
      }
    """
    try:
      # It is necessary to clean the given links because they have relationship
      # nodes
      replace_nodes = {}
      relationship_links = (
          link_ for link_ in json_graph_data_links
          if link_["source"].startswith("relationship"))
      for link in relationship_links:
        if link["source"] not in replace_nodes:
          replace_nodes[link["source"]] = [link["target"]]
        else:
          replace_nodes[link["source"]].append(link["target"])

      non_relationship_links = (
          link for link in json_graph_data_links
          if not link["source"].startswith("relationship"))

      for link_data in non_relationship_links:
        linked_nodes = replace_nodes.get(
            link_data["target"], [link_data["target"]])
        for node in linked_nodes:
          self.add_link(link_data["source"], node, link_data["connection_type"])

    except KeyError:
      raise vt_graph_api.errors.InvalidJSONError(
          "This is implementation details, the error is coming from the link " +
          "field in the VT response."
      )

  def _pull_viewers(self):
    """Pull graph's users and groups viewers from VT API.

    It is necessary to call _push_viewers in order to save changes.

    Raises:
      InvalidJSONError: whether the API response does not have the correct
        structure.
      LoadError: if there is any problem while querying VirusTotal API.
    """
    if not self.graph_id:
      return

    user_viewers = []
    group_viewers = []
    viewers_data_url = (
        "https://www.virustotal.com/api/v3/graphs/{graph_id}"
        .format(graph_id=self.graph_id) + "/relationships/viewers")
    viewers_data_response = requests.get(
        viewers_data_url, headers=self._get_headers())
    if viewers_data_response.status_code != 200:
      raise vt_graph_api.errors.LoadError(
          "Error while pulling viewers; code: {code}".format(
              code=viewers_data_response.status_code))
    try:
      viewers_data = viewers_data_response.json()
      for viewer in viewers_data["data"]:
        if viewer["type"] == "group":
          group_viewers.append(viewer["id"])
        else:
          user_viewers.append(viewer["id"])
    except KeyError as e:
      raise vt_graph_api.errors.InvalidJSONError(
          "Unexpected error in json structure at get_graph_viewers: {msg}"
          .format(msg=str(e)))
    self.user_viewers.extend(user_viewers)
    self.group_viewers.extend(group_viewers)

  def _push_viewers(self):
    """Push graph's viewers to VT.

    Raises:
      CollaboratorNotFoundError: if any of the collaborators does not exist.
    """
    data = []
    for editor in self.user_viewers:
      data.append({
          "id": editor,
          "type": "user"
      })
    for editor in self.group_viewers:
      data.append({
          "id": editor,
          "type": "group"
      })

    if not data:
      return

    url = "https://www.virustotal.com/api/v3/graphs/{graph_id}/viewers".format(
        graph_id=self.graph_id)
    response = requests.post(
        url, headers=self._get_headers(), data=json.dumps({"data": data}))

    if response.status_code != requests.codes.ok:
      raise vt_graph_api.errors.CollaboratorNotFoundError()

  def _pull_editors(self):
    """Pull graph's users and groups editors from VT API.

    It is necessary to call _push_editors in order to save changes.

    Raises:
      InvalidJSONError: whether the API response does not have the correct
        structure.
      LoadError: if there is any problem while querying VirusTotal API.
    """
    if not self.graph_id:
      return

    user_editors = []
    group_editors = []
    editors_data_url = (
        "https://www.virustotal.com/api/v3/graphs/{graph_id}"
        .format(graph_id=self.graph_id) + "/relationships/editors")
    editors_data_response = requests.get(
        editors_data_url, headers=self._get_headers())
    if editors_data_response.status_code != 200:
      raise vt_graph_api.errors.LoadError(
          "Error while pulling editors; code: {code}".format(
              code=editors_data_response.status_code))
    try:
      editors_data = editors_data_response.json()
      for editor in editors_data["data"]:
        if editor["type"] == "group":
          group_editors.append(editor["id"])
        else:
          user_editors.append(editor["id"])
    except KeyError as e:
      raise vt_graph_api.errors.InvalidJSONError(
          "Unexpected error in json structure at get_graph_editors: {msg}"
          .format(msg=str(e)))

    self.user_editors.extend(user_editors)
    self.group_editors.extend(group_editors)

  def _push_editors(self):
    """Push graph's editors to VT.

    Raises:
      CollaboratorNotFoundError: if any of the collaborators does not exist.
    """
    data = []
    for editor in self.user_editors:
      data.append({
          "id": editor,
          "type": "user"
      })
    for editor in self.group_editors:
      data.append({
          "id": editor,
          "type": "group"
      })

    if not data:
      return

    url = "https://www.virustotal.com/api/v3/graphs/{graph_id}/editors".format(
        graph_id=self.graph_id)
    response = requests.post(
        url, headers=self._get_headers(), data=json.dumps({"data": data}))

    if response.status_code != requests.codes.ok:
      raise vt_graph_api.errors.CollaboratorNotFoundError()

  def _push_graph_to_vt(self, output):
    """Push the computed graph to VT.

    Args:
      output (dict): graph in the VT api readable format.

    Raises:
        SaveGraphError: if something went bad when saving the graph.
    """
    self._log("Saving local graph")
    if self.graph_id:
      url = "https://www.virustotal.com/api/v3/graphs/{graph_id}".format(
          graph_id=self.graph_id)
      response = requests.patch(
          url, headers=self._get_headers(), data=json.dumps(output))
    else:
      url = "https://www.virustotal.com/api/v3/graphs"
      response = requests.post(
          url, headers=self._get_headers(), data=json.dumps(output))
    if response.status_code != 200:
      self._log(
          "Saving graph error: {status_code} status code."
          .format(status_code=response.status_code))
      raise vt_graph_api.errors.SaveGraphError(
          "Saving graph error: {status_code} status code."
          .format(status_code=response.status_code)
      )

    data = response.json()
    if "data" not in data:
      self._log("Saving graph error: {data}".format(data=data))
      raise vt_graph_api.errors.SaveGraphError(str(data))
    self.graph_id = data["data"]["id"]

  def _fetch_node_information(self, node):
    """Fetch VT to get the node information.

    Args:
        node (Node): node to be searched in VT.

    It consumes API quota.
    """
    data = {}
    end_point = self._get_api_endpoint(node.node_type)
    url = "https://www.virustotal.com/api/v3/{end_point}/{node_id}".format(
        end_point=end_point, node_id=node.node_id)
    self._increment_api_counter()
    response = requests.get(url, headers=self._get_headers())
    if response.status_code != 200:
      self._log(
          "Request to '{url}' with '{status_code}' status code"
          .format(url=url, status_code=response.status_code)
      )
      return

    data = response.json()
    if "data" in data and "attributes" in data.get("data"):
      node.add_attributes(data["data"]["attributes"])

  def _compute_common_relationship_ids(self):
    """Compute the relationship ids for each node of the current graph.

    It is necessary in order to minimize the graph.
    """
    nodes = list(six.itervalues(self.nodes))
    # First, node.relationship_ids will be reseted for each
    # node in self.nodes in order to compute them again
    for node in nodes:
      node.reset_relationship_ids()

    calculated_nodes = set()
    for node in nodes:
      to_minimize = []
      calculated_nodes.add(node.node_id)
      not_visited_node = (
          node for node in nodes
          if node.node_id not in calculated_nodes)
      for node_ in not_visited_node:
        # The intersection between possible expansion of each node give
        # us the common expansions
        shared_expansions = (
            set(node.children)
            .intersection(set(node_.children)))
        # Two nodes could be minimized if they have the same children in the
        # same expansion and they have at least one child.
        for expansion in shared_expansions:
          if (node.children[expansion] and
              collections.Counter(node.children[expansion]) ==
              collections.Counter(node_.children[expansion])):
            to_minimize.append((node_, expansion))

      # Once the possible minimizations are computed, it is time to
      # generate the relationship id and set it to the minimized nodes.
      for node_to_minimize, expansion in to_minimize:
        # If no one have relationship id yet, it will be create and added,
        # otherwise the relationship id will be getted from the one which
        # has it.
        if (not node.relationship_ids.get(expansion) and
            not node_to_minimize.relationship_ids.get(expansion)):
          relationship_id = "relationships_{expansion}_{node_id}".format(
              expansion=expansion,
              node_id=node.pretty_id)
          node.relationship_ids[expansion] = relationship_id
          node_to_minimize.relationship_ids[expansion] = relationship_id
        elif not node.relationship_ids.get(expansion):
          relationship_id = node_to_minimize.relationship_ids.get(expansion)
          node.relationship_ids[expansion] = relationship_id
        else:
          relationship_id = node.relationship_ids.get(expansion)
          node_to_minimize.relationship_ids[expansion] = relationship_id

      # Finally generate single relationship_id for each expansion for
      # each node of the graph.
      singles_expansion_relationship = (
          set(node.children) -
          set(node.relationship_ids))
      for expansion in singles_expansion_relationship:
        relationship_id = "relationships_{expansion}_{node_id}".format(
            expansion=expansion,
            node_id=node.pretty_id)
        node.relationship_ids[expansion] = relationship_id

  def _get_file_sha_256(self, node_id, is_filename=False):
    """Return the sha256 hash for node_id.

    Return sha256 if matches found in VT, otherwise return node_id.
    If is_filename=True, the name will be searched in VT Enterprise. If the
    data returned by intelligence API give more than one result, we cannot
    infer which one of them is the node we are looking for.

    Args:
      node_id (str): identifier of the node. See the top level documentation
        to understand IDs.
      is_filename (str): whether de given node_id belongs to file without hash.
        If it is True, the name will be searched in VT Enterprise. Defaults
        to False.

    Returns:
      str: sha256 of the given file node_id.

    It consumes API quota.
    """
    if is_filename:
      url = ("https://www.virustotal.com/api/v3/intelligence/search?query=" +
             "{query}".format(query=node_id))
      response = requests.get(url, headers=self._get_headers())
      if response.status_code == 200:
        data = response.json()
        total_hits = vt_graph_api.helpers.safe_get(
            data, "meta", "total_hits", default=0)
        node_type = vt_graph_api.helpers.safe_get(
            data, "data", 0, "type")
        if (total_hits == 1 and node_type == "file"):
          node_id = data["data"][0]["id"]
    else:
      url = "https://www.virustotal.com/api/v3/files/{node_id}".format(
          node_id=node_id)
      response = requests.get(url, headers=self._get_headers())
      if response.status_code != 200:
        return node_id

      data = response.json()
      node_id = vt_graph_api.helpers.safe_get(
          data, "data", "attributes", "sha256", default=node_id)

    self._increment_api_counter()
    return node_id

  def _get_url_id(self, node_id):
    """Return the correct identifier in case of url instead of sha256.

    Args:
      node_id (str): identifier of the node. See the top level documentation
        to understand IDs.

    Returns:
      str: url identifier for the VT api.

    It consumes API quota.
    """
    url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(
        url, data={"url": node_id}, headers=self._get_headers())
    if response.status_code == 200:
      data = response.json()
      default_node_id = "u-'{node_id}'-u".format(node_id=node_id)
      node_id = vt_graph_api.helpers.safe_get(
          data, "data", "id", default=default_node_id).split("-")
      if len(node_id) > 1:
        node_id = node_id[1]
    self._increment_api_counter()
    return node_id

  def _get_node_id(self, node_id, fetch_vt_enterprise=False):
    """Return the correct node_id.

    It only changes the given node_id in case of a file node with no sha256
    hash, url instead of an VT url identifier, or if the given node_id belongs
    to a unknown identifier.

    Args:
      node_id (str): identifier of the node. See the top level documentation
        to understand IDs.
      fetch_vt_enterprise (bool, optional): if True, the graph will search any
        available information using VT intelligence for the node if there
        is no normal information for it. Defaults to False.

    Returns:
      str: the correct node_id for the given identifier.

    This call consumes API Quota.
    """
    found = False
    valid_node_id = node_id
    # Make this function thread safe.
    with self._nodes_lock:
      if node_id in self.nodes:
        found = True
      # Maybe it has been referenced before.
      elif node_id in self._id_references:
        found = True
        valid_node_id = self._id_references[node_id]

    if found:
      return valid_node_id

    if vt_graph_api.node.Node.is_url(node_id):
      valid_node_id = self._get_url_id(node_id)
    elif (vt_graph_api.node.Node.is_sha1(node_id) or
          vt_graph_api.node.Node.is_md5(node_id)):
      valid_node_id = self._get_file_sha_256(node_id)
    # If the node is totally unknow we will search it in intelligence
    elif (not vt_graph_api.node.Node.is_domain(node_id) and
          not vt_graph_api.node.Node.is_ipv4(node_id) and
          not vt_graph_api.node.Node.is_sha256(node_id) and
          fetch_vt_enterprise):
      valid_node_id = self._get_file_sha_256(node_id, True)
    self._id_references[node_id] = valid_node_id
    return valid_node_id

  def _query_expansion_nodes(self, node, expansion,
                             max_nodes_per_relationship, cursor, max_retries):
    """Get expansion nodes JSON data by querying VirusTotal API.

    Args:
      node (Node): node to be expanded
      expansion (str): expansion name. For example: compressed_parents for
        nodes of type file.
      max_nodes_per_relationship (int): max number of nodes that will
        be expanded per relationship.
      cursor (str): VT relationships cursor. Defaults to None.
      max_retries (int): maximum retries for API request.

    Raises:
        vt_graph_api.errors.MaximumConnectionRetriesError: if the maximum number
        of retries will be reached by the function.

    Returns:
        dict: VirusTotal API response.
    """
    data = {}
    end_point = self._get_api_endpoint(node.node_type)
    request_try = 0
    has_response = False
    limit = min(max_nodes_per_relationship, self.MAX_API_EXPANSION_LIMIT)
    url = (
        "https://www.virustotal.com/api/v3/" +
        "{end_point}/{node_id}/{expansion}?limit={limit}"
        .format(end_point=end_point, node_id=node.node_id, expansion=expansion,
                limit=limit))
    if cursor:
      url = "{url}&cursor={cursor}".format(url=url, cursor=cursor)

    # If the request fails, it will be retried as much as max_retries.
    while request_try < max_retries and not has_response:
      try:
        self._log(
            "Expanding node {node_id} with expansion {expansion}"
            .format(node_id=node.node_id, expansion=expansion))
        self._increment_api_counter()
        response = requests.get(
            url, headers=self._get_headers(), timeout=self.REQUEST_TIMEOUT)
        has_response = True
        if response.status_code == 200:
          data = response.json()
      except requests.ConnectionError:
        request_try += 1
        if request_try >= max_retries:
          raise vt_graph_api.errors.MaximumConnectionRetriesError()
    return data

  def _get_expansion_nodes(self, node, expansion,
                           max_nodes_per_relationship=1000, cursor=None,
                           max_retries=3, expansion_nodes=None,
                           consumed_quotas=0):
    """Returns the nodes to be attached to the given node with the given expansion.

    Args:
      node (Node): node to be expanded
      expansion (str): expansion name. For example: compressed_parents for
        nodes of type file.
      max_nodes_per_relationship (int): max number of nodes that will
        be expanded per relationship. Minimum value will be
        MIN_API_EXPANSION_NUMBER. Defaults to 1000.
      cursor (str, optional): VT relationships cursor. Defaults to None.
      max_retries (int, optional): maximum retries for API request.
      expansion_nodes ([Node], optional): list with the result's nodes for
        tail recursion. Defaults to None.
      consumed_quotas (int, optional): number of consumed quotas for tail
        recursion. Defaults to 0.

    Raises:
      MaximumConnectionRetriesError: if the maximum number of retries will be
        reached by the function.

    Returns:
      (list(Node), int): a list with the nodes produced by the given node
        expansion in the given expansion type, and a number with api
        quotas consumed.

    It consumes API quota. One for each call nedeed to achieve
    max_nodes_per_relationship.
    """
    if not expansion_nodes:
      max_nodes_per_relationship = max(
          max_nodes_per_relationship, self.MIN_API_EXPANSION_NUMBER)
    expansion_nodes = expansion_nodes or []
    parent_node_id = node.node_id
    parent_node_type = node.node_type

    data = self._query_expansion_nodes(
        node, expansion, max_nodes_per_relationship, cursor, max_retries)
    consumed_quotas += 1

    # Add cursor data.
    has_more = data.get("meta", {})
    # Some results return just one element back.
    new_nodes = data.get("data", list())
    if isinstance(new_nodes, dict):
      new_nodes = [new_nodes]
    elif new_nodes is None:
      new_nodes = []

    for node_data in new_nodes:
      child_node_id = node_data["id"]
      child_node_type = node_data["type"]

      # Translation for resolutions.
      if child_node_type == "resolution":
        child_node_id = child_node_id.replace(parent_node_id, "")
        if parent_node_type == "domain":
          child_node_type = "ip_address"
        else:
          child_node_type = "domain"
      new_node = vt_graph_api.node.Node(child_node_id, child_node_type)
      if "attributes" in node_data:
        new_node.add_attributes(node_data["attributes"])
      expansion_nodes.append(new_node)

    cursor = has_more.get("cursor")
    if cursor:
      next_max = max_nodes_per_relationship - len(new_nodes)
      if next_max > 0:
        return self._get_expansion_nodes(
            node, expansion, max_nodes_per_relationship=next_max,
            cursor=cursor, expansion_nodes=expansion_nodes,
            consumed_quotas=consumed_quotas)

    return expansion_nodes, consumed_quotas

  def _parallel_expansion(self, target_nodes, solution_paths, visited_nodes,
                          max_api_quotas, lock, max_depth, node, params):
    """Parallelize the node expansion synchronizing the api quotas consumed.

    Args:
      target_nodes ([Node]): target node.
      solution_paths ([paths]): synchronized list of paths. A path
        is a list of tuples in the form ->
        (source, target, expansion_type, source_type) where
        source (Node) -> relation parent node.
        target (Node) -> relation child node.
        expansion_type (str) -> expansion which has produced the relationship.
        source_type (str) -> relation child node type.
      visited_nodes ([Node]): synchronized list with the nodes.
      max_api_quotas ([int]): synchronized list with max api quotas value.
      lock (threading.Lock): lock.
      max_depth (int): max depth.
      node (Node): the node which will be expanded.
      params (list, int): path to node and depth.

    Returns:
      list(tuple(Node, list, int)): list with the result of the expansions.
      The elements of the returned list of tuples are:
        first element: one of the nodes of the expansion.
        second element: a list with the path to that Node.
        third element: node's depth relative to first node
          which started the search.
    """
    path, depth = params

    futures = []
    expansion_nodes = {}
    expansions = node.expansions_available

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(expansions)) as pool:

      has_quota = False

      if depth + 1 >= max_depth:
        return expansion_nodes

      for expansion in expansions:
        # Make this part thread safe.
        with lock:
          quotas_left = max_api_quotas.pop()
          quotas_left -= 1
          if quotas_left > -1:
            has_quota = True
          max_api_quotas.append(quotas_left)

        if has_quota:
          futures.append((
              pool.submit(self._get_expansion_nodes, node, expansion, 40),
              expansion))
          has_quota = False
        else:
          break

      for future, expansion in futures:

        nodes, _ = future.result()
        not_visited_nodes = (node for node in nodes
                             if node not in visited_nodes)

        for not_visited_node in not_visited_nodes:
          # Make this part thread safe.
          with lock:
            if not_visited_node in target_nodes:
              path.append((
                  node.node_id, not_visited_node.node_id, expansion,
                  not_visited_node.node_type))
              solution_paths.append(path)
              target_nodes.remove(not_visited_node)
            else:
              expansion_nodes[not_visited_node] = ((
                  path + [(node.node_id,
                           not_visited_node.node_id,
                           expansion,
                           not_visited_node.node_type)],
                  depth + 1))
    return expansion_nodes

  def _search_connection(self, source_node, target_nodes,
                         max_api_quotas, max_depth, max_qps):
    """Search connection between the node source and all of the target_nodes.

                          source_node
                             +-+
                             |-|
               +----------+-------+-----------+
               |          |   |   |           |
               |          |   |   |           |
               |          v   v   v           |
    thread 1<-+-+         X   X   X          +-+ ----> thread n
              |-|                            |-|
          +---------+                   +-----------+
          |         X                   X           |
     +---+-+       +-+                 +-+         +-+
     |   +-+       +-+                 +-+         +-+ <--- target_node
    +-+
    +-+ <--- target_node

    This algorithm is based on breadth first search.

    Args:
      source_node (Node): start node.
      target_nodes ([Node]): The nodes that will be connected with source.
      max_api_quotas (int, optional): max api quotas to be consumed.
        Defaults to 10000.
      max_depth (int, optional): max hops between nodes. Defaults to 5.
      max_qps (int): max number of queries per second as much as
        MAX_PARALLEL_REQUESTS.
    Returns:
      [[(str, str, str, str))]]: the computed path from the source_node to
        each node in target_nodes. The elements of the tuple are:
          - source node id.
          - target node id.
          - expansion name which produces that relation.
          - target node type.

    """

    max_qps = min(max_qps, self.MAX_PARALLEL_REQUESTS)
    queue = {source_node: ([], 0)}
    paths = []
    has_quota = True
    # Shared variables
    max_api_quotas = [max_api_quotas]
    lock = threading.Lock()
    solution_paths = []
    visited_nodes = [source_node]
    target_nodes = list(target_nodes)

    expand_parallel_partial_ = functools.partial(
        self._parallel_expansion, target_nodes, solution_paths, visited_nodes,
        max_api_quotas, lock, max_depth)

    while has_quota and target_nodes and queue:
      with concurrent.futures.ThreadPoolExecutor(max_workers=max_qps) as pool:
        visited_nodes.extend(six.iterkeys(queue))
        futures = []
        for node, params in six.iteritems(queue):
          futures.append(pool.submit(expand_parallel_partial_, node, params))
        queue.clear()
        for future in futures:
          queue.update(future.result())
      with lock:
        quotas_left = max_api_quotas.pop()
        has_quota = quotas_left > 0
        max_api_quotas.append(quotas_left)

    paths = list(solution_paths)
    return paths

  def _resolve_relations(self, source_node, target_nodes,
                         max_api_quotas, max_depth, max_qps,
                         fetch_info_collected_nodes):
    """Try to connect the source_node with all of the nodes in target_nodes.

    Args:
      source_node (Node): The node that will wanted to be connected.
      target_nodes ([Node]): The nodes that will be connected with source.
      max_api_quotas (int, optional): maximum number of api quotas that could
        be consumed. Defaults to 100000.
      max_depth (int, optional): maximum number of hops between the nodes.
        Defaults to 3.
      max_qps (int, optional): maximum number requests per second.
        Defaults to 1000.
      fetch_info_collected_nodes (bool, optional): if True, when a new node
        is added to graph to compute the connection, it will be fetched
        on VT for information. It consumes api quotas which are not included
        in max_api_quota. Defaults to True.

    Returns:
      bool: whether at least one relation has been found.

    This call consumes API quota (as much as max_api_quotas value), one for
    each expansion required to find the relationship.
    """
    has_link = False
    for source_, target_, _ in self.links:
      if (source_ == source_node.node_id and
          self.nodes[target_] in target_nodes or
          self.nodes[source_] in target_nodes and
          target_ == source_node.node_id):
        has_link = True
        break  # Exit if found

    if not has_link:
      links = self._search_connection(
          source_node, target_nodes, max_api_quotas, max_depth, max_qps)

      if links:
        for links_ in links:
          for source_id, target_id, connection_type, target_type in links_:
            self.add_node(target_id, target_type, fetch_info_collected_nodes)
            self.links[(source_id, target_id, connection_type)] = True
            self.nodes[source_id].add_child(target_id, connection_type)
        has_link = True
    return has_link

  def add_node(self, node_id, node_type, fetch_information=True,
               fetch_vt_enterprise=True, label="", node_attributes=None,
               x=0, y=0):
    """Adds a node with id `node_id` of `node_type` type to the graph.

    Args:
      node_id (string): node ID. Example: https://www.virustotal.com for a url.
      node_type (string): file, url, ip_address or domain.
      fetch_information (bool, optional): whether the script will fetch
        information for this node in VT. If the node already exist in the graph
        it will not fetch information for it. Defaults to True.
      fetch_vt_enterprise (bool, optional): if True, the graph will search any
        available information using VT intelligence for the node if there
        is no normal information for it. Defaults to True.
      label(str, optional): label that appears next to the node. Defaults to "".
      node_attributes(dict, optional): if it is set and fetch_information is
        False, node_attributes will be added to new node with the given node id.
        Defaults to None.
      x (int, optional): X coordinate for Node representation in VT Graph UI.
      y (int, optional): Y coordinate for Node representation in VT Graph UI.

    Returns:
      Node: the node object appended to graph.

    This call consumes API quota if fetch_information=True. It also consumes
    API quota if the given node_id is not standard, such as file with id
    in SHA1 or MD5, URL instead of an VT URL identifier or if the given node_id
    belongs to an unknown identifier.
    """
    if node_type == "file" or node_type == "url":
      node_id = self._get_node_id(node_id, fetch_vt_enterprise)

    # Make this function thread safe.
    with self._nodes_lock:
      node_ids = list(six.iterkeys(self.nodes))

    if node_id not in node_ids:
      new_node = vt_graph_api.node.Node(node_id, node_type, x, y)
      if label:
        new_node.add_label(label)
      if (fetch_information and
          node_type in vt_graph_api.node.Node.SUPPORTED_NODE_TYPES):
        self._fetch_node_information(new_node)
      elif node_attributes:
        new_node.add_attributes(node_attributes)
      with self._nodes_lock:
        self.nodes[node_id] = new_node

    # Make this function thread safe.
    with self._nodes_lock:
      node = self.nodes[node_id]
    return node

  def add_nodes(self, node_list, fetch_information=True,
                fetch_vt_enterprise=True):
    """Adds the node_list to the graph concurrently.

    Args:
      node_list ([dict]): a list of dictionaries with the following keys
        {node_id, node_type, label, attributes, x_position, y_position}.
      fetch_information (bool, optional): whether the script will fetch
        information for the nodes that will be added in VT. Defaults to True.
      fetch_vt_enterprise (bool, optional): if True, the graph will search any
        available information using VT intelligence for the node if there
        is no normal information for it. Defaults to True.

    Returns:
      [Node]: the list with the added nodes.
    """
    futures = []
    added_nodes = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(node_list)) as pool:
      for node_data in node_list:
        futures.append(pool.submit(
            self.add_node, node_data.get("node_id"), node_data.get("node_type"),
            fetch_information, fetch_vt_enterprise, node_data.get("label", ""),
            node_data.get("attributes"), node_data.get("x_position", 0),
            node_data.get("y_position", 0)))
      for future in futures:
        added_nodes.append(future.result())
      return added_nodes

  def has_node(self, node_id):
    """Check if the graph contains the node with the given node_id.

    Args:
        node_id (str): node ID.

    Returns:
        bool: whether the graph contains the node with the given node_id.

    This call consumes API quota if the given node_id is not a standard VT id.
    """
    return self._get_node_id(node_id) in self.nodes

  def delete_node(self, node_id):
    """Deletes the node with the given node_id from the graph.

    Args:
      node_id (str): node ID.

    Raises:
      NodeNotFoundError: if there is no node with the given node_id in
        the graph.

    This call does NOT consume API quota.
    """
    node_id = self._get_node_id(node_id)
    if node_id not in self.nodes:
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes.".format(node_id=node_id))

    self.delete_links(node_id)
    del self.nodes[node_id]

  def add_link(self, source_node, target_node, connection_type=""):
    """Adds a link between source_node and target_node with the given connection_type.

    If there's no connection type supplied, the link will be drawed without
    relationship node in VirusTotal UI.

    Args:
      source_node (str): source node ID.
      target_node (str): target node ID.
      connection_type (str, optional): connection type, for example
        compressed_parent. Defaults to "".

    Raises:
      NodeNotFoundError: if any of the given nodes are not found.
      SameNodeError: if the source_node and the target_node are the same.

    This call does NOT consume API quota.
    """
    if source_node == target_node:
      raise vt_graph_api.errors.SameNodeError(
          "It is no possible to add links between the same node; id: {node_id}."
          .format(node_id=source_node))

    source_node = self._get_node_id(source_node)
    target_node = self._get_node_id(target_node)

    if source_node not in self.nodes:
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes."
          .format(node_id=source_node))
    if target_node not in self.nodes:
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes."
          .format(node_id=target_node))
    if connection_type not in self.nodes[source_node].expansions_available:
      self._log("Expansion `{expansion_type}` is not standard expansion type",
                logging.WARNING)

    connection_type = connection_type.replace(" ", "_")[:self.MAX_CHARACTERS]
    self.links[(source_node, target_node, connection_type)] = True
    self.nodes[source_node].add_child(target_node, connection_type)

  def add_links_if_match(self, source_node, target_node,
                         max_api_quotas=100000, max_depth=3, max_qps=1000,
                         fetch_info_collected_nodes=True):
    """Try to find a relationship between the source_node and the target_node.

    Adds the needed links between the source_node and the target_node if
    the target_node could be reached by source_node.

    Args:
      source_node (str): source node ID.
      target_node (str): target node ID.
      max_api_quotas (int, optional): maximum number of api quotas that could
        be consumed. Defaults to 100000.
      max_depth (int, optional): maximum number of hops between the nodes.
        Defaults to 3.
      max_qps (int, optional): maximum number of requests per second.
        Defaults to 1000.
      fetch_info_collected_nodes (bool, optional): if True, when a new node
        is added to graph to compute the connection, it will be fetched
        on VT for information. It consumes api quotas which are not included
        in max_api_quota. Defaults to True.

    Returns:
      bool: whether relation has been found.

    Raises:
      NodeNotFoundError: if source or target node is not found.
      SameNodeError: if source_node and target_node are the same.

    This call consumes API quota (as much as max_api_quotas value), one for
    each expansion required to find the relation.
    """

    if source_node == target_node:
      raise vt_graph_api.errors.SameNodeError(
          "It is no possible to add links between the same node; id: {node_id}."
          .format(node_id=source_node))

    quotas_before_get_id = self.get_api_calls()
    source_node = self._get_node_id(source_node)
    target_node = self._get_node_id(target_node)
    max_api_quotas -= (self.get_api_calls() - quotas_before_get_id)

    if source_node not in self.nodes:
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes.".format(node_id=source_node))

    if target_node not in self.nodes:
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes.".format(node_id=target_node))

    if (self.nodes[source_node].node_type
        not in vt_graph_api.node.Node.SUPPORTED_NODE_TYPES or
        self.nodes[target_node].node_type
        not in vt_graph_api.node.Node.SUPPORTED_NODE_TYPES):
      raise vt_graph_api.errors.NodeNotSupportedExpansionError(
          "Custom nodes cannot be expanded.")

    return self._resolve_relations(
        self.nodes[source_node], [self.nodes[target_node]], max_api_quotas,
        max_depth, max_qps, fetch_info_collected_nodes)

  def connect_with_graph(self, source_node, max_api_quotas=100000,
                         max_depth=3, max_qps=1000,
                         fetch_info_collected_nodes=True):
    """Try to connect the source_node with the current graph nodes.

    Args:
      source_node (Node): source_node ID.
      max_api_quotas (int, optional): maximum number of api quotas that could
        be consumed. Defaults to 100000.
      max_depth (int, optional): maximum number of hops between the nodes.
        Defaults to 3.
      max_qps (int, optional): maximum number requests per second.
        Defaults to 1000.
      fetch_info_collected_nodes (bool, optional): if True, when a new node
        is added to graph to compute the connection, it will be fetched
        on VT for information. It consumes api quotas which are not included
        in max_api_quota. Defaults to True.

    Raises:
      NodeNotFoundError: if the node source is not found.

    Returns:
      bool: whether at least one relationship has been found.

    This call consumes API quota (as much as max_api_quotas value), one for
    each expansion required to find the relationships.
    """
    quotas_before_get_id = self.get_api_calls()
    source_node = self._get_node_id(source_node)
    max_api_quotas -= (self.get_api_calls() - quotas_before_get_id)

    if source_node not in self.nodes:
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes.".format(node_id=source_node))

    if (self.nodes[source_node].node_type
        not in vt_graph_api.node.Node.SUPPORTED_NODE_TYPES):
      raise vt_graph_api.errors.NodeNotSupportedExpansionError(
          "Custom nodes cannot be expanded.")

    source_node = self.nodes[source_node]
    target_nodes = [
        node for node in six.itervalues(self.nodes)
        if node.node_type in vt_graph_api.node.Node.SUPPORTED_NODE_TYPES]

    target_nodes.remove(source_node)

    return self._resolve_relations(
        source_node, target_nodes, max_api_quotas, max_depth, max_qps,
        fetch_info_collected_nodes)

  def delete_link(self, source_node, target_node, connection_type):
    """Deletes the link between source_node and target_node with the given connection_type.

    Args:
      source_node (str): source node ID.
      target_node (str): target node ID.
      connection_type (str): connection type, for example
        compressed_parent.

    Raises:
      NodeNotFoundError: if any of the given nodes are not found.
      SameNodeError: if the source_node and the target_node are the same.
      LinkNotFoundError: if the given link does not exists in the graph.
    """
    if source_node == target_node:
      raise vt_graph_api.errors.SameNodeError(
          "It is no possible to delete links between the same node; id: " +
          "{node_id}.".format(node_id=source_node))
    source_node = self._get_node_id(source_node)
    target_node = self._get_node_id(target_node)
    if source_node not in self.nodes:
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes."
          .format(node_id=source_node))
    if target_node not in self.nodes:
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes."
          .format(node_id=target_node))

    if (source_node, target_node, connection_type) not in self.links:
      raise vt_graph_api.errors.LinkNotFoundError(
          ("Link between {source} and {target} with {connection_type} does " +
           "not exists.").format(
               source=source_node, target=target_node,
               connection_type=connection_type))
    del self.links[(source_node, target_node, connection_type)]
    self.nodes[source_node].delete_child(target_node, connection_type)

  def delete_links(self, node_id):
    """Deletes all the links which contains the given node_id.

    Args:
      node_id (str): the node which are in the links that will be deleted
        from the graph.

    Raises:
      NodeNotFoundError: if the given node_id is not found.
    """
    node_id = self._get_node_id(node_id)
    if node_id not in self.nodes:
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes."
          .format(node_id=node_id))

    links_to_be_deleted = [
        link for link in six.iterkeys(self.links)
        if link[0] == node_id or link[1] == node_id]
    for source_node, target_node, connection_type in links_to_be_deleted:
      del self.links[(source_node, target_node, connection_type)]
      self.nodes[source_node].delete_child(target_node, connection_type)

  def expand(self, node_id, expansion, max_nodes_per_relationship=40):
    """Expands the given node with the given expansion.

    Args:
      node_id (str): identifier of the node. See the top level documentation
        to understand IDs.
      expansion (str): expansion name. For example: compressed_parents for
        nodes of type file.
      max_nodes_per_relationship (int, optional): max number of nodes that will
        be expanded per relationship. Minimum value will be
        MIN_API_EXPANSION_NUMBER. Defaults to 40.

    Raises:
      NodeNotFoundError: if the node is not found.
      NodeNotSupportedExpansionError: if the node cannot be expanded with the
        given expansion.

    Returns:
      [Node]: a list with the nodes resulted by the expansion of the given node
        with the given relationship.

    This call consumes API quota.
    """
    node_id = self._get_node_id(node_id)
    if node_id not in six.iterkeys(self.nodes):
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes."
          .format(node_id=node_id))
    node = self.nodes[node_id]

    if expansion not in node.expansions_available:
      raise vt_graph_api.errors.NodeNotSupportedExpansionError(
          "Node {node_id} cannot be expanded with {expansion} expansion."
          .format(node_id=node_id, expansion=expansion))

    expansion_nodes, _ = self._get_expansion_nodes(
        node, expansion, max_nodes_per_relationship)
    # Adds data to graph.
    for node in expansion_nodes:
      if node.node_id != node_id:
        self.add_node(
            node.node_id, node.node_type, fetch_information=False,
            node_attributes=node.attributes)
        self.add_link(node_id, node.node_id, expansion)
      else:
        self._log(
            "Ignored expansion result: {node_id} for expansion type:"
            "{expansion}. Source and target are the same node."
              .format(
                node_id=node.node_id, expansion=expansion),
            logging.INFO
        )
    return expansion_nodes

  def expand_one_level(self, node_id, max_nodes_per_relationship=40):
    """Expands all relationship that we know in VirusTotal for the give node.

    Args:
      node_id (str): node ID.
      max_nodes_per_relationship (int, optional): max number of nodes that will
        be expanded per relationship. Defaults to None.

    Raises:
      NodeNotFoundError: if the node is not found.

    It consumes API quota, one for each expansion available for the node.

    Returns:
      [Node]: a list with the nodes resulted by te expansion of the given node
        in all his known relationships.
    """
    node_id = self._get_node_id(node_id)

    if node_id not in six.iterkeys(self.nodes):
      raise vt_graph_api.errors.NodeNotFoundError(
          "Node '{node_id}' not found in nodes.".format(node_id=node_id))

    futures = []
    expansion_nodes = []
    expansions_available = self.nodes[node_id].expansions_available
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(expansions_available)) as pool:
      for expansion in expansions_available:
        futures.append(pool.submit(
            self.expand, node_id, expansion, max_nodes_per_relationship))
      for future in futures:
        expansion_nodes.extend(future.result())

    return expansion_nodes

  def expand_n_level(self, level=1, max_nodes_per_relationship=40,
                     max_nodes=10000):
    """Expands all the nodes in the graph `level` levels.

    For example:
      If your graph has three nodes, and you apply a expand_n_level(1). It will
      expand the three nodes with all the known expansions for those nodes.

      If you select 2 levels of expansions. After the first expansion is applied
      to the three nodes, the new discovered nodes will be expanded as well.

    Args:
      level (int, optional): number of layers down the graph that will be
        expanded. Defaults to 1.
      max_nodes_per_relationship: (int, optional): max number of nodes that will
        be expanded per relationship. Defaults to 40.
      max_nodes (int, optional): max number of nodes that will be added to the
        graph. The expansion will stop as soon as any expansion result adds more
        than this limit to the graph. Defaults to 10000.

    Returns:
      [Node]: a list with the nodes resulted by the expansion of each graph
        node in all his known relationships.

    This call consumes API quota, one for each node expansion.
    """
    pending = {node_id for node_id in six.iterkeys(self.nodes)}
    visited = set()
    expansion_nodes = []
    for _ in range(level):
      for node_id in pending:
        expansion_nodes.extend(self.expand_one_level(
            node_id, max_nodes_per_relationship=max_nodes_per_relationship))
        visited.add(node_id)
        if max_nodes and len(self.nodes) > max_nodes:
          self._log(
              "Hit the maximum limits, " +
              "stopping the calculation. Node len: {len_nodes}"
              .format(len_nodes=len(self.nodes)))
      pending = {node_id for node_id in six.iterkeys(self.nodes)
                 if node_id not in visited}
    return expansion_nodes

  def save_graph(self):
    """Saves the graph into VirusTotal Graph database.

    At this point if the Graph is set to public it will be searchable in
    VirusTotal UI.

    Raises:
      CollaboratorNotFoundError: if any of the collaborators is not found in
        VirusTotal user and group database.
      SaveGraphError: if something went bad when saving the graph.

    This call not consume API quota.
    """
    self._log("Saving the graph")
    self._index = 0
    added = set()
    output = {
        "data": {
            "attributes": {
                "graph_data": {
                    "description": self.name,
                    "version": vt_graph_api.version.__version__,
                },
                "private": self.private,
                "nodes": [],
                "links": [],
            },
            "type": "graph",
        },
    }
    self._compute_common_relationship_ids()
    for (source_id, target_id, expansion) in self.links:
      # Source
      if source_id not in added:
        self._add_node_to_output(output, source_id)
        added.add(source_id)

      # Target
      if target_id not in added:
        self._add_node_to_output(output, target_id)
        added.add(target_id)

      if not expansion or expansion == "manual":
        output["data"]["attributes"]["links"].append({
            "connection_type": expansion,
            "source": source_id,
            "target": target_id,
        })
      else:
        # Relationship node.
        relationship_id = self.nodes[source_id].relationship_ids.get(expansion)
        if relationship_id not in added:
          self._add_node_to_output(output, relationship_id)
          added.add(relationship_id)

        # Links
        output["data"]["attributes"]["links"].append({
            "connection_type": expansion,
            "source": source_id,
            "target": relationship_id,
        })
        output["data"]["attributes"]["links"].append({
            "connection_type": expansion,
            "source": relationship_id,
            "target": target_id,
        })

    new_nodes = (node_id for node_id in self.nodes if node_id not in added)
    for node_id in new_nodes:
      self._add_node_to_output(output, node_id)
      added.add(node_id)

    self._push_graph_to_vt(output)
    self._push_editors()
    self._push_viewers()
    self._index = 0

  def get_api_calls(self):
    """Get api counter in thread safe mode."""
    with self._api_calls_lock:
      api_calls = self._api_calls
    return api_calls

  def get_ui_link(self):
    """Return VirusTotal UI link for the graph.

    Requires that save_graph was called.

    Raises:
      vt_graph_api.errors.SaveGraphError: if `save_graph` was not called.

    Returns:
        str: VirusTotal UI link.
    """
    if not self.graph_id:
      raise vt_graph_api.errors.SaveGraphError(
          "`save_graph` has not been called yet!")
    return "https://www.virustotal.com/graph/{graph_id}".format(
        graph_id=self.graph_id)

  def get_iframe_code(self):
    """Return VirusTotal UI iframe for the graph.

    Requires that save_graph was called.

    Raises:
      vt_graph_api.errors.SaveGraphError: if `save_graph` was not called.

    Returns:
        str: VirusTotal UI iframe.
    """
    if not self.graph_id:
      raise vt_graph_api.errors.SaveGraphError(
          "`save_graph` has not been called yet!")
    return (
        "<iframe src=\"https://www.virustotal.com/graph/embed/" +
        "{graph_id}\" width=\"800\" height=\"600\"></iframe>"
        .format(graph_id=self.graph_id))

  def download_screenshot(self, path = "."):
    """Downloads a screenshot of the graph.

    Args:
      path: Path where screenshot will be saved.

    Raises:
      vt_graph_api.errors.SaveGraphError: if `save_graph` was not called.
      vt_graph_api.errors.DownloadScreenshotError: if screenshot can't be downloaded.

    """
    if not self.graph_id:
      raise vt_graph_api.errors.SaveGraphError(
          "`save_graph` has not been called yet!")

    url = "https://www.virustotal.com/api/v3/graphs/{graph_id}/screenshot".format(
        graph_id=self.graph_id
    )

    r = requests.get(
        url,
        headers=self._get_headers(),
        stream=True)

    if r.status_code == 200:
      r.raw.decode_content = True
      filename = "{graph_id}.jpg".format(graph_id=self.graph_id)
      file_path = os.path.join(path, filename)
      with open(file_path,'wb') as f:
        shutil.copyfileobj(r.raw, f)
    else:
      raise vt_graph_api.errors.DownloadScreenshotError(
          "Couldn't download screenshot for graph {graph_id}".format(
              graph_id=self.graph_id
          )
      )
