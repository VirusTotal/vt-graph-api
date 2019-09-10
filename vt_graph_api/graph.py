"""vt_graph_api.graph.

This modules provides the Python object wrapper for
virustotal graph representation.

Documentation:
  https://developers.virustotal.com/v3.0/docs/api-documentation

Examples:
  https://developers.virustotal.com/v3.0/docs/simple-tutorials
  https://developers.virustotal.com/v3.0/docs/advanced-tutorials
"""


import collections
import functools
import json
import logging
import threading

import concurrent.futures
import requests
import six
from vt_graph_api.errors import CollaboratorNotFoundError
from vt_graph_api.errors import MaximumConnectionRetriesError
from vt_graph_api.errors import NodeNotFoundError
from vt_graph_api.errors import NodeNotSupportedExpansionError
from vt_graph_api.errors import SameNodeError
from vt_graph_api.errors import SaveGraphError
from vt_graph_api.node import Node
from vt_graph_api.version import __version__


class VTGraph(object):
  """Python object wrapper for Virustotal Graph representation.

  Attributes:
    api_key (str): VT API Key.
    graph_id (str): graph identifier for VT.
    name (str): graph title.
    api_calls (int): total api calls consumed by graph.
    private (bool): wether graph is private or not.
    user_editors ([str]): list with users that can edit graph.
    user_viewers ([str]): list with users that can see graph.
    group_editors ([str]): list with groups that can edit graph.
    group_viewers ([str]): list with groups that can see graph.
    verbose (bool): if True log will be displayed.
    nodes (dict): graph nodes.
    links (dict): graph links.
  """

  MAX_API_EXPANSION_LIMIT = 40
  MAX_PARALLEL_REQUESTS = 1000
  X_TOOL = "Graph"
  REQUEST_TIMEOUT = 40

  def __init__(
      self,
      api_key,
      name="",
      private=False,
      user_editors=None,
      user_viewers=None,
      group_editors=None,
      group_viewers=None,
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

    self._api_calls_lock = threading.Lock()
    self._index = 0
    self._logger = logging.getLogger("vt_graph")
    self._logger.addHandler(logging.StreamHandler())
    self._logger.setLevel(logging.INFO)

  def _log(self, msg):
    """Prints if verbose is enabled.

    Args:
      msg (string): message.
    """
    if self.verbose:
      self._logger.info(msg)

  def _get_node_detections(self, node):
    """Get node detections from attributes.

    Args:
      node (Node): node from which detections are getted.

    Returns:
      int: with the number of detections.
    """
    return (
        node.attributes.get("last_analysis_stats", dict()).get("malicious", 0) +
        node.attributes.get("last_analysis_stats", dict()).get("suspicious", 0)
    )

  def _add_node_to_output(self, output, node_id):
    """Add the node with the given node_id to the output.

    Args:
      output (dict): graph structure in json representation to be consumed
        by VT API.
      node_id (str): node ID.
    """

    node = self.nodes.get(node_id)
    node_type = node.node_type if node else "relationship"
    node_data = {
        "type": node_type,
        "entity_id": node_id,
        "index": self._index,
        "x": 0,
        "y": 0,
    }

    if node:

      if node.label:
        node_data["text"] = node.label

      if node.attributes:
        if node.node_type == "file":
          has_detections = self._get_node_detections(node)
          entity_attributes = {
              "has_detections": has_detections,
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
          has_detections = self._get_node_detections(node)
          entity_attributes = {
              "has_detections": has_detections,
          }
          node_data["entity_attributes"] = entity_attributes

    output["data"]["attributes"]["nodes"].append(node_data)
    self._index += 1

  def _add_viewers(self):
    """Adds editors to the graph.

    Raises:
      CollaboratorNotFound: if any of the collaborators don"t exist.
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
        graph_id=self.graph_id
    )
    response = requests.post(
        url,
        headers=self._get_headers(),
        data=json.dumps({"data": data})
    )

    if response.status_code != requests.codes.ok:
      raise CollaboratorNotFoundError()

  def _add_editors(self):
    """Adds editors to the graph.

    Raises:
      CollaboratorNotFound: if any of the collaborators don"t exist.
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
        graph_id=self.graph_id
    )
    response = requests.post(
        url,
        headers=self._get_headers(),
        data=json.dumps({"data": data})
    )

    if response.status_code != requests.codes.ok:
      raise CollaboratorNotFoundError()

  def _fetch_information(self, node):
    """Fetch VT to get the node information.

    Args:
        node (Node): node to be searched in VT.

    It consumes API quota.
    """
    data = {}
    end_point = self._get_api_endpoint(node.node_type)
    url = "https://www.virustotal.com/api/v3/{end_point}/{node_id}".format(
        end_point=end_point,
        node_id=node.node_id
    )
    response = requests.get(url, headers=self._get_headers())
    self._increment_api_counter()
    if response.status_code == 200:
      data = response.json()
    else:
      self._log(
          "Request to '{url}' with '{status_code}' status code"
          .format(
              url=url,
              status_code=response.status_code
          )
      )
    if "data" in data and "attributes" in data.get("data"):
      node.add_attributes(data["data"]["attributes"])

  def _send_graph_to_vt(self, output):
    """Sends the computed graph to VT.

    Args:
      output (dict): graph in VT api readable format.

    Raises:
        SaveGraphError: if something went bad when saving the graph.
    """
    url = "https://www.virustotal.com/api/v3/graphs"
    response = requests.post(
        url,
        headers=self._get_headers(),
        data=json.dumps(output)
    )
    if response.status_code == 200:
      data = response.json()
      if "data" in data:
        self.graph_id = data["data"]["id"]
      else:
        self._log("Saving graph error: {data}".format(data=data))
        raise SaveGraphError(str(data))
    else:
      self._log(
          "Saving graph error: {status_code} status code"
          .format(
              status_code=response.status_code
          )
      )
      raise SaveGraphError(
          "Saving graph error: {status_code} status code"
          .format(
              status_code=response.status_code
          )
      )

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
          if node.node_id not in calculated_nodes
      )
      for node_ in not_visited_node:
        # The interescteion between possible expansion of each node give
        # us the common expansions
        shared_expansions = (
            set(node.expansions_available)
            .intersection(set(node_.expansions_available))
        )
        # Two nodes could be minimized it they have the same children in the
        # same expansion and they have at least one child.
        minimize_expansion = (
            expansion for expansion in shared_expansions
            if node.children[expansion]
        )
        for expansion in minimize_expansion:
          if (
              collections.Counter(node.children[expansion]) ==
              collections.Counter(node_.children[expansion])
          ):
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
              node_id=Node.get_id(node.node_id)
          )
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
          set(node.expansions_available) -
          set(six.iterkeys(node.relationship_ids))
      )
      for expansion in singles_expansion_relationship:
        relationship_id = "relationships_{expansion}_{node_id}".format(
            expansion=expansion,
            node_id=Node.get_id(node.node_id)
        )
        node.relationship_ids[expansion] = relationship_id

  def save_graph(self):
    """Saves the graph into VirusTotal Graph database.

    At this point if the Graph is set to public it will be searchable in
    VirusTotal UI.

    Raises:
      CollaboratorNotFound: if any of the collaborators is not found in
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
                    "version": __version__,
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

    self._send_graph_to_vt(output)
    self._add_editors()
    self._add_viewers()

  def _increment_api_counter(self):
    """Increments api counter in thread safe mode."""
    with self._api_calls_lock:
      self._api_calls += 1
      new_api_calls_value = self._api_calls

    self._log("API counter incremented. Total value: {api_calls}".format(
        api_calls=new_api_calls_value
    ))

  def get_api_calls(self):
    """Get api counter in thread safe mode."""
    with self._api_calls_lock:
      api_calls = self._api_calls
    return api_calls

  def _get_file_sha_256(self, node_id, is_filename=False):
    """Return the sha256 hash for node_id.

    It only retruns sha256 if matches found in VT, else return node_id.

    Args:
      node_id (str): identifier of the node. See the top level documentation
        to understand IDs.
      is_filename (str): wether de given node_id belongs to file without hash.
        If it is True, it will be searched using VT intelligence. Defaults
        to False.

    Returns:
      str: sha256 of the given file node_id.

    It consumes API quota.
    """
    if is_filename:
      url = "https://www.virustotal.com/api/v3/intelligence/search?query={query}".format(
          query=node_id
      )
      response = requests.get(url, headers=self._get_headers())
      if response.status_code == 200:
        data = response.json()
        if (
            data.get("meta", dict()).get("total_hits", 0) == 1 and
            data.get("data", [{"id": node_id}])[0].get("type", "") == "file"
        ):
          node_id = data.get("data", [{"id": node_id}])[0].get("id", node_id)
    else:
      url = "https://www.virustotal.com/api/v3/files/{node_id}".format(
          node_id=node_id
      )
      response = requests.get(url, headers=self._get_headers())
      if response.status_code == 200:
        data = response.json()
        node_id = data.get("data", dict()).get(
            "attributes", dict()).get("sha256", node_id)

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
        url,
        data={"url": node_id},
        headers=self._get_headers()
    )
    if response.status_code == 200:
      data = response.json()
      node_id = data.get("data", dict()).get(
          "id", "u-'{node_id}'-u".format(node_id=node_id)).split("-")
      if len(node_id) > 1:
        node_id = node_id[1]
    self._increment_api_counter()
    return node_id

  def _get_node_id(self, node_id):
    """Return the correct node_id.

    It only change the given node_id in case of file node with no sha256 hash
    or url instead of VT url identifier.

    Args:
      node_id (str): identifier of the node. See the top level documentation
        to understand IDs.

    Returns:
      str: the correct node_id for the given identifier.
    """
    if Node.is_url(node_id):
      node_id = self._get_url_id(node_id)
    elif Node.is_sha1(node_id) or Node.is_md5(node_id):
      node_id = self._get_file_sha_256(node_id)
    # If the node is totally unknow we will search it in intelligence
    elif (
        not Node.is_domain(node_id) and
        not Node.is_ipv4(node_id) and
        not Node.is_sha256(node_id)
    ):
      node_id = self._get_file_sha_256(node_id, True)

    return node_id

  def _get_expansion_nodes(self, node, expansion,
                           max_nodes_per_relationship=1000, cursor=None,
                           max_retries=3, expansion_nodes=None,
                           consumed_quotas=0):
    """Returns the nodes to be attached to given node with the given expansion.

    Args:
      node (Node): node to be expanded
      expansion (str): expansion name. For example: compressed_parents for
        nodes of type file.
      max_nodes_per_relationship (int): max number of nodes that will
        be expanded per relationship. Minimum value will be 10.
        Defaults to 1000.
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
    expansion_nodes = expansion_nodes or []
    parent_node_id = node.node_id
    parent_node_type = node.node_type
    end_point = self._get_api_endpoint(parent_node_type)
    request_try = 0
    has_response = False
    limit = min(max_nodes_per_relationship, self.MAX_API_EXPANSION_LIMIT)

    url = (
        "https://www.virustotal.com/api/v3/" +
        "{end_point}/{node_id}/{expansion}?limit={limit}"
        .format(
            end_point=end_point,
            node_id=node.node_id,
            expansion=expansion,
            limit=limit
        )
    )
    if cursor:
      url = "{url}&cursor={cursor}".format(url=url, cursor=cursor)

    # If the request fails, it will be retried as much as max_retries.
    while request_try < max_retries and not has_response:
      try:
        self._log(
            "Expanding node {node_id} with expansion {expansion}"
            .format(
                node_id=node.node_id,
                expansion=expansion
            )
        )
        response = requests.get(
            url,
            headers=self._get_headers(),
            timeout=self.REQUEST_TIMEOUT
        )
        self._increment_api_counter()
        consumed_quotas += 1
        has_response = True
        if response.status_code == 200:
          data = response.json()
        else:
          data = {}
          self._log(
              "Request to {url} with {status_code} status code"
              .format(
                  url=url, status_code=response.status_code
              )
          )
      except requests.ConnectionError:
        request_try += 1
        if request_try >= max_retries:
          raise MaximumConnectionRetriesError()

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
      new_node = Node(child_node_id, child_node_type)
      if "attributes" in node_data:
        new_node.add_attributes(node_data["attributes"])
      expansion_nodes.append(new_node)

    if has_more:
      cursor = data["meta"]["cursor"]
      next_max = max_nodes_per_relationship - len(data["data"])
      if next_max > 0:
        return self._get_expansion_nodes(
            node,
            expansion, max_nodes_per_relationship=next_max,
            cursor=cursor, expansion_nodes=expansion_nodes,
            consumed_quotas=consumed_quotas
        )

    return expansion_nodes, consumed_quotas

  def _parallel_expansion(self, target_nodes, solution_paths, visited_nodes,
                          max_api_quotas, lock, max_depth, node, params):
    """Parallelize node expansion synchronizing api quotas consumed.

    Args:
      target_nodes ([Node]): target node.
      solution_paths ([paths]): synchronized list of paths. A path
        is a list of tuples (source, target, expansion_type, source_type) where
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
        max_workers=len(expansions)
    ) as pool:

      has_quota = False

      if depth + 1 < max_depth:
        for expansion in expansions:
          # Make this part thread safe.
          with lock:
            quotas_left = max_api_quotas.pop()
            quotas_left -= 1
            if quotas_left > -1:
              has_quota = True
            max_api_quotas.append(quotas_left)

          if has_quota:
            futures.append(
                (
                    pool.submit(
                        self._get_expansion_nodes,
                        node,
                        expansion,
                        40
                    ),
                    expansion
                )
            )
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
                path.append(
                    (
                        node.node_id,
                        not_visited_node.node_id,
                        expansion,
                        not_visited_node.node_type
                    )
                )
                solution_paths.append(path)
                target_nodes.remove(not_visited_node)
              else:
                expansion_nodes[not_visited_node] = (
                    (
                        path + [(node.node_id,
                                 not_visited_node.node_id,
                                 expansion,
                                 not_visited_node.node_type)],
                        depth + 1
                    )
                )
    return expansion_nodes

  def _search_connection(self, node_source, target_nodes,
                         max_api_quotas, max_depth, max_qps):
    """Search connection between node source and all of target_nodes.

                          node_source
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
     |   +-+       +-+                 +-+         +-+ <--- node_target
    +-+
    +-+ <--- node_target

    This algorithm is based on breadth first search.

    Args:
      node_source (Node): start node.
      target_nodes ([Node]): last node.
      max_api_quotas (int, optional): max number of api quotas.
        Defaults to 10000.
      max_depth (int, optional): max hops between nodes. Defaults to 5.
      max_qps (int): max number of queries per second as much as
        MAX_PARALLEL_REQUESTS.
    Returns:
      [[(str, str, str, str))]]: the computed path from node_source to
        each node in target_nodes. The elements of the tuple are:
          - source node id.
          - target node id.
          - expansion name which produces that relation.
          - target node type.

    """

    max_qps = min(max_qps, self.MAX_PARALLEL_REQUESTS)
    queue = {node_source: ([], 0)}
    paths = []
    has_quota = True
    # Shared variables
    max_api_quotas = [max_api_quotas]
    lock = threading.Lock()
    solution_paths = []
    visited_nodes = [node_source]
    target_nodes = list(target_nodes)

    expand_parallel_partial_ = functools.partial(
        self._parallel_expansion,
        target_nodes,
        solution_paths,
        visited_nodes,
        max_api_quotas,
        lock,
        max_depth
    )

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

  def _resolve_relations(self, node_source, target_nodes,
                         max_api_quotas, max_depth, max_qps,
                         fetch_info_collected_nodes):
    """Try to connect node_source with all of the nodes in target_nodes.

    Args:
      node_source (Node): The node that will wanted to be connected.
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
    each expansion required to find the relations.
    """
    quotas_before_get_id = self.get_api_calls()
    quotas_after_get_id = self.get_api_calls()
    max_api_quotas -= (quotas_after_get_id - quotas_before_get_id)

    has_link = False
    for source_, target_, _ in self.links:
      if (source_ == node_source.node_id and
          self.nodes[target_] in target_nodes or
          self.nodes[source_] in target_nodes and
          target_ == node_source.node_id):
        has_link = True
        break  # Exit if found

    if not has_link:
      links = self._search_connection(
          node_source,
          target_nodes,
          max_api_quotas,
          max_depth,
          max_qps
      )

      if links:
        for links_ in links:
          for source_id, target_id, connection_type, target_type in links_:
            self.add_node(target_id, target_type, fetch_info_collected_nodes)
            self.links[(source_id, target_id, connection_type)] = True
            self.nodes[source_id].add_child(target_id, connection_type)
        has_link = True
    return has_link

  def _get_headers(self):
    """Returns the request headers."""
    return {"x-apikey": self.api_key, "x-tool": self.X_TOOL}

  def _get_api_endpoint(self, node_type):
    """Returns the api end point."""
    if node_type == "ip_address":
      return "ip_addresses"
    else:
      return node_type + "s"

  def add_node(self, node_id, node_type, fetch_information=True, label=""):
    """Adds a node with id `node_id` of `node_type` type to the graph.

    Args:
      node_id (string): node ID. Example: https://www.virustotal.com for a url.
      node_type (string): file, url, ip_address or domain.
      fetch_information (bool, optional): whether the script will fetch
        information for this node in VT. If the node already exist in the graph
        it will not fetch information for it. Defaults to True.
      label(str, optional): label that appears next to the node. Defaults to "".

    Returns:
      Node: the node object appended to graph.

    This call consumes API quota if fetch_information=True. It also consumes
    API quota if the given node_id is not standar, for example a file with id
    in SHA1 or MD5 or URL without VT identifier.
    """
    node_id = self._get_node_id(node_id)
    if node_id not in six.iterkeys(self.nodes):
      new_node = Node(node_id, node_type)
      if label:
        new_node.add_label(label)
      if fetch_information:
        self._fetch_information(new_node)
      self.nodes[node_id] = new_node
    return self.nodes[node_id]

  def expand(self, node_id, expansion, max_nodes_per_relationship=40):
    """Expands the given node with the given expansion.

    Args:
      node_id (str): identifier of the node. See the top level documentation
        to understand IDs.
      expansion (str): expansion name. For example: compressed_parents for
        nodes of type file.
      max_nodes_per_relationship (int, optional): max number of nodes that will
        be expanded per relationship. Minimum value will be 10.
        Defaults to 40.

    Raises:
      NodeNotFound: if the node is not found.
      NodeNotSupportedExpansionError: if node cannot be expanded with the given
        expansion.

    This call consumes API quota.
    """
    node_id = self._get_node_id(node_id)
    if node_id not in six.iterkeys(self.nodes):
      raise NodeNotFoundError(
          "node '{node_id}' not found in nodes"
          .format(
              node_id=node_id
          )
      )
    node = self.nodes[node_id]

    if expansion not in node.expansions_available:
      raise NodeNotSupportedExpansionError(
          "node {node_id} cannot be expanded with {expansion} expansion"
          .format(
              node_id=node_id,
              expansion=expansion
          )
      )

    new_nodes, _ = self._get_expansion_nodes(
        node,
        expansion,
        max_nodes_per_relationship
    )
    # Adds data to graph.
    for new_node in new_nodes:
      self.add_node(new_node.node_id, new_node.node_type)
      self.add_link(node_id, new_node.node_id, expansion)

  def expand_one_level(self, node_id, max_nodes_per_relationship=40):
    """Expands all relationship that we know in VirusTotal for the give node.

    Args:
      node_id (str): node ID.
      max_nodes_per_relationship (int, optional): max number of nodes that will
        be expanded per relationship. Defaults to None.

    Returns:
      bool: whether there are more expansions available in this node.

    Raises:
      NodeNotFound: if the node is not found.

    It consumes API quota, one for each expansion available for the node.
    """
    node_id = self._get_node_id(node_id)

    if node_id not in six.iterkeys(self.nodes):
      raise NodeNotFoundError(
          "node '{node_id}' not found in nodes"
          .format(
              node_id=node_id
          )
      )

    expansions_available = self.nodes[node_id].expansions_available
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(expansions_available)
    ) as pool:
      for expansion in expansions_available:
        pool.submit(
            self.expand,
            node_id,
            expansion,
            max_nodes_per_relationship
        )

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

    This call consumes API quota, one for each node expansion.
    """
    pending = {node_id for node_id in six.iterkeys(self.nodes)}
    visited = set()
    for _ in range(level):
      for node_id in pending:
        self.expand_one_level(
            node_id, max_nodes_per_relationship=max_nodes_per_relationship
        )
        visited.add(node_id)
        if max_nodes and len(self.nodes) > max_nodes:
          self._log(
              "Hit the maximum limits, " +
              "stopping the calculation. Node len: {len_nodes}"
              .format(
                  len_nodes=len(self.nodes)
              )
          )
          return
      pending = {node_id
                 for node_id in six.iterkeys(self.nodes)
                 if node_id not in visited}

  def add_link(self, node_source, node_target, connection_type):
    """Adds a link between node_source and node_target with the connection_type.

    If the source or target node don"t exist, an exception will be raised.

    Args:
      node_source (str): source node ID.
      node_target (str): target node ID.
      connection_type (str): connection type, for example
        compressed_parent.

    Raises:
      NodeNotFound: if any node is not found.
      SameNodeError: if node_source and node_target are the same.

    This call does NOT consume API quota.
    """
    if node_source == node_target:
      raise SameNodeError(
          "it is no possible to add links between the same node; id: {node_id}"
          .format(node_id=node_source)
      )

    node_source = self._get_node_id(node_source)
    node_target = self._get_node_id(node_target)
    if node_source not in self.nodes:
      raise NodeNotFoundError(
          "node '{node_id}' not found in nodes"
          .format(
              node_id=node_source
          )
      )
    if node_target not in self.nodes:
      raise NodeNotFoundError(
          "node '{node_id}' not found in nodes"
          .format(
              node_id=node_target
          )
      )
    self.links[(node_source, node_target, connection_type)] = True
    self.nodes[node_source].add_child(node_target, connection_type)

  def add_links_if_match(self, node_source, node_target,
                         max_api_quotas=100000, max_depth=3, max_qps=1000,
                         fetch_info_collected_nodes=True):
    """Try to find relation between the node_source the and node_target.

    Adds the needed links between node_source and node_target if
    node_target could be reached by node_source.

    Args:
      node_source (str): source node ID.
      node_target (str): target node ID.
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
      NodeNotFound: if source or target node is not found.
      SameNodeError: if node_source and node_target are the same.

    This call consumes API quota (as much as max_api_quotas value), one for
    each expansion required to find the relation.
    """

    if node_source == node_target:
      raise SameNodeError(
          "it is no possible to add links between the same node; id: {node_id}"
          .format(node_id=node_source)
      )

    node_source = self._get_node_id(node_source)
    node_target = self._get_node_id(node_target)
    if node_source not in self.nodes:
      raise NodeNotFoundError(
          "node '{node_id}' not found in nodes"
          .format(
              node_id=node_source
          )
      )

    if node_target not in self.nodes:
      raise NodeNotFoundError(
          "node '{node_id}' not found in nodes"
          .format(
              node_id=node_target
          )
      )

    return self._resolve_relations(
        self.nodes[node_source],
        [self.nodes[node_target]],
        max_api_quotas,
        max_depth,
        max_qps,
        fetch_info_collected_nodes
    )

  def connect_with_graph(self, node_source, max_api_quotas=100000,
                         max_depth=3, max_qps=1000,
                         fetch_info_collected_nodes=True):
    """Try to connect node_source with the current graph nodes.

    Args:
      node_source (Node): source_node ID.
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
      NodeNotFound: if node source is not found.

    Returns:
      bool: whether at least one relation has been found.

    This call consumes API quota (as much as max_api_quotas value), one for
    each expansion required to find the relations.
    """
    node_source = self._get_node_id(node_source)
    if node_source not in self.nodes:
      raise NodeNotFoundError(
          "node '{node_id}' not found in nodes"
          .format(
              node_id=node_source
          )
      )

    node_source = self.nodes[node_source]
    target_nodes = list(self.nodes.values())
    target_nodes.remove(node_source)

    return self._resolve_relations(
        node_source,
        target_nodes,
        max_api_quotas,
        max_depth,
        max_qps,
        fetch_info_collected_nodes
    )

  def delete_node(self, node_id):
    """Deletes a node from the graph.

    Args:
      node_id (str): node ID.

    This call does NOT consume API quota.
    """
    node_id = self._get_node_id(node_id)
    if node_id not in self.nodes:
      raise NodeNotFoundError(
          "node '{node_id}' not found in nodes"
          .format(
              node_id=node_id
          )
      )

    to_be_deleted = []
    for link in self.links:
      source, target, _ = link
      if source == node_id or target == node_id:
        to_be_deleted.append(link)
    for node_source, node_target, connection_type in to_be_deleted:
      del self.links[(node_source, node_target, connection_type)]
      self.nodes[node_source].delete_child(node_target, connection_type)
    del self.nodes[node_id]

  def get_ui_link(self):
    """Requires that save_graph was called."""
    return "https://www.virustotal.com/graph/{graph_id}".format(
        graph_id=self.graph_id
    )

  def get_iframe_code(self):
    """Requires that save_graph was called."""
    return (
        "<iframe src=\"https://www.virustotal.com/graph/embed/" +
        "{graph_id}\" width=\"800\" height=\"600\"></iframe>"
        .format(
            graph_id=self.graph_id
        )
    )
