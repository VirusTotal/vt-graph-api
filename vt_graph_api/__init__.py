import json
import requests
from multiprocessing.pool import ThreadPool
from six import iterkeys

name = "vt_graph_api"


class NodeNotFound(Exception):
  pass


class CollaboratorNotFound(Exception):
  pass


class SaveGraphError(Exception):
  pass


SUPPORTED_NODE_TYPES = ('file', 'url', 'domain', 'ip_address')
NODE_EXPANSIONS = {
  'file': [
    'bundled_files',
    'carbonblack_children',
    'carbonblack_parents',
    'compressed_parents',
    'contacted_domains',
    'contacted_ips',
    'contacted_urls',
    'email_parents',
    'embedded_domains',
    'embedded_ips',
    'execution_parents',
    'itw_domains',
    'itw_urls',
    'overlay_parents',
    'pcap_parents',
    'pe_resource_parents',
    'similar_files',
  ],
  'url': [
    'contacted_domains',
    'contacted_ips',
    'downloaded_files',
    'last_serving_ip_address',
    'network_location',
    'redirecting_urls',
  ],
  'domain': [
    'communicating_files',
    'downloaded_files',
    'referrer_files',
    'resolutions',
    'siblings',
    'subdomains',
    'urls',
  ],
  'ip_address': [
    'communicating_files',
    'downloaded_files',
    'referrer_files',
    'resolutions',
    'urls',
  ],
}
VERSION = "api-1.0.0"

pool = ThreadPool(processes=4)


class VTGraph(object):

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

    Params:
      api_key: string, VT API Key.
      name: (optional): string, with the graph title.
      private: (optional) boolean, true for private graphs. You need to have
        Private Graph premium feature enabled in your subscription.
      user_editors: (optional) list of string, with the usernames that can edit
        the graph.
      user_viewers: (optional) list of string, with the usernames that can view
        the graph.
      group_editors: (optional) list of string, with the groups that can edit
        the graph.
      group_viewers: (optional) list of string, with the groups that can view
        the graph.
      verbose: (optional) bool, true for printing log messages.

    This call does NOT consume API quota.
    """
    self.api_key = api_key

    self.graph_id = ""
    self.name = name
    self.api_calls = 0
    self.private = private
    self.user_editors = user_editors or []
    self.user_viewers = user_viewers or []
    self.group_editors = group_editors or []
    self.group_viewers = group_viewers or []
    self.verbose = verbose

    self.nodes = {}
    self.links = {}

    self._index = 0

  def log(self, msg):
    """Prints if verbose is enabled.

    Params:
      msg: string, message.

    This call does NOT consume API quota.
    """
    if self.verbose:
      print(msg)

  def _add_node_to_output(self, output, node_id):
    """
    TODO: DOCUMENT THIS.
    """
    node = self.nodes[node_id]
    node_data = {
      "type": node.node_type,
      "entity_id": node.node_id,
      "index": self._index,
      "x": 0,
      "y": 0,
    }

    if node.label:
      node_data["text"] = node.label

    if node.attributes:
      # File.
      if node.node_type == "file":
        has_detections = (
          node.attributes['last_analysis_stats']['malicious'] +
          node.attributes['last_analysis_stats']['suspicious'])
        entity_attributes = {
          "has_detections": has_detections,
        }

        if 'type_tag' in node.attributes:
          entity_attributes['type_tag'] = node.attributes['type_tag']

        node_data["entity_attributes"] = entity_attributes

      # Ip Address.
      elif (node.node_type == "ip_address" and
            'country' in node.attributes):
        entity_attributes = {
          "country": node.attributes['country'],
        }
        node_data["entity_attributes"] = entity_attributes

      # Urls.
      elif node.node_type == "url":
        has_detections = (
          node.attributes['last_analysis_stats']['malicious'] +
          node.attributes['last_analysis_stats']['suspicious'])
        entity_attributes = {
          "has_detections": has_detections,
        }
        node_data["entity_attributes"] = entity_attributes

    output['data']['attributes']['nodes'].append(node_data)
    self._index += 1

  def _add_viewers(self):
    """Adds editors to the graph.

    Raises:
      CollaboratorNotFound if any of the collaborators don't exist.
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

    url = "https://www.virustotal.com/api/v3/graphs/%s/viewers" % self.graph_id
    headers = {'x-apikey': self.api_key, 'x-tool': VERSION}
    response = requests.post(url, headers=headers, data=json.dumps({"data": data}))

    if response.status_code != requests.codes.ok:
      raise CollaboratorNotFound()

  def _add_editors(self):
    """Adds editors to the graph.

    Raises:
      CollaboratorNotFound if any of the collaborators don't exist.
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

    url = "https://www.virustotal.com/api/v3/graphs/%s/editors" % self.graph_id
    headers = {'x-apikey': self.api_key, 'x-tool': VERSION}
    response = requests.post(url, headers=headers, data=json.dumps({"data": data}))

    if response.status_code != requests.codes.ok:
      raise CollaboratorNotFound()

  def save_graph(self):
    """Saves the graph into VirusTotal Graph database.

    At this point if the Graph is set to public it will be searchable in
    VirusTotal UI.

    Raises:
      CollaboratorNotFound: if any of the collaborators is not found in
      VirusTotal user and group database.
      SaveGraphError: if something went bad when saving the graph.
    """
    self.log("Saving the graph")
    self._index = 0
    added = set()
    output = {
      "data": {
        "attributes": {
          "graph_data": {
            "description": self.name,
            "version": VERSION,
          },
          "private": self.private,
          "nodes": [],
          "links": [],
        },
        "type": "graph",
      },
    }

    for (source_id, target_id, expansion) in self.links:
      # Source
      if source_id not in added:
        self._add_node_to_output(output, source_id)
        added.add(source_id)

      # Relationship node.
      relationship_id = "relationships_%s_%s" % (
          expansion, Node.get_id(source_id))
      if relationship_id not in added:
        output['data']['attributes']['nodes'].append({
          "type": "relationship",
          "entity_id": relationship_id,
          "index": self._index,
          "x": 0,
          "y": 0,
        })
        added.add(relationship_id)
        self._index += 1

      # Target
      if target_id not in added:
        self._add_node_to_output(output, target_id)
        added.add(target_id)

      # Links
      output['data']['attributes']['links'].append({
        "connection_type": expansion,
        "source": source_id,
        "target": relationship_id,
      })
      output['data']['attributes']['links'].append({
        "connection_type": expansion,
        "source": relationship_id,
        "target": target_id,
      })

    for node_id in self.nodes:
      if node_id not in added:
        self._add_node_to_output(output, node_id)
        added.add(node_id)

    self.log("Saving local graph")
    f = open("output.json", 'w')
    f.write(json.dumps(output))
    f.close()

    self.log("Sending Graph to VT")
    url = "https://www.virustotal.com/api/v3/graphs"
    headers = {'x-apikey': self.api_key, 'x-tool': VERSION}
    response = requests.post(url, headers=headers, data=json.dumps(output))
    data = response.json()
    if 'data' in data:
      self.graph_id = data['data']['id']
    else:
      self.log("Saving graph error: %s" % data)
      raise SaveGraphError()

    self._add_editors()
    self._add_viewers()

  def _increment_api_counter(self):
    """Increments api counter."""
    self.api_calls += 1
    self.log("API counter incremented. Total value: %s" % self.api_calls)

  def _get_file_sha_256(self, node_id):
    """
    Return sha256 hash for node_id with file type if matches found in VT, else return None

    Params:
      node_id: str, string, identififer of the node. See the top level documentation
      to understand IDs.

    Returns:
      str.
    """
    headers = self._get_headers()
    url = "https://www.virustotal.com/api/v3/files/%s" % (node_id)
    response = requests.get(url, headers=headers)
    try:
      data = response.json()
      id = data.get('data', dict()).get('attributes', dict()).get('sha256')
    except json.JSONDecodeError:
      id = node_id
    return id

  def _get_node_id(self, node_id):
    """
    Return correct node_id in case of file node with no sha256 hash.

    Params:
      node_id: str, string, identififer of the node. See the top level documentation
      to understand IDs.

    Raises:
      NodeNotFound: if the node is not found.

    Returns:
      str.

    """
    if node_id in iterkeys(self.nodes):
      return node_id 

    sha_256 = self._get_file_sha_256(node_id)
    return sha_256
  
  def _get_headers(self):
    """Returns the request headers."""
    return {'x-apikey': self.api_key, 'x-tool': VERSION}

  def _get_api_endpoint(self, node_type):
    """Returns the api end point."""
    if node_type == "ip_address":
      return "ip_addresses"
    else:
      return node_type + "s"

  def add_node(self, node_id, node_type, fetch_information=True, label=""):
    """Adds a node with id `node_id` of `node_type` type to the graph.

    Args:
      node_id: string, node ID. Example: https://www.virustotal.com for a url.
      node_type: string, file, url, ip_address or domain.
      fetch_information: (optional) boolean, whether the script will fetch
        information for this node in VT. If the node already exist in the graph
        it will not fetch information for it.
      label: (optional) string, label that appears next to the node.

    Returns:
      Node.

    This call consumes API quota if fetch_information=True.
    """
    if node_type == 'file' and len(node_id) != 64:
      node_id = self._get_node_id(node_id)
          
    if node_id not in self.nodes:
      new_node = Node(node_id, node_type)
      if label:
        new_node.add_label(label)
      if fetch_information:
        headers = self._get_headers()
        end_point = self._get_api_endpoint(node_type)
        url = "https://www.virustotal.com/api/v3/%s/%s" % (
            end_point, node_id)
        response = requests.get(url, headers=headers)
        data = response.json()
        if 'attributes' in data.get('data', dict()):
          new_node.add_attributes(data['data']['attributes'])
        self.nodes[node_id] = new_node

    return self.nodes[node_id]

  def expand(self, node_id, expansion, max_nodes_per_relationship=None,
      cursor=None):
    """Expands the given node with the given expansion.

    Args:
      node_id: string, identififer of the node. See the top level documentation
        to understand IDs.
      expansion: string, expansion name. For example: compressed_parents for
        nodes of type file.
      max_nodes_per_relationship: (opt) integer, max number of nodes that will
        be expanded per relationship. Minimum value will be 10.
      cursor: (opt) string, VT relationships cursor.

    This call consumes API quota.
    """
    self.log("Expanding node '%s' with expansion '%s'" % (node_id, expansion))

    node_id = self._get_node_id(node_id)
    node = self.nodes[node_id]
    parent_node_id = node.node_id
    parent_node_type = node.node_type
    end_point = self._get_api_endpoint(parent_node_type)
    max_nodes_per_relationship = max_nodes_per_relationship or 1000000

    url = "https://www.virustotal.com/api/v3/%s/%s/%s" % (
        end_point, node_id, expansion)
    if cursor:
      url = "%s?cursor=%s" % (url, cursor)
    headers = {'x-apikey': self.api_key, 'x-tool': 'graph-api-v1'}
    response = requests.request("GET", url, headers=headers)
    data = response.json()

    # Add cursor data.
    has_more = data.get('meta', {})

    # Some results return just one element back.
    if 'data' not in data:
      new_nodes = []
    elif type(data['data']) == dict:
      new_nodes = [data['data']]
    else:
      new_nodes = data['data']

    for node in new_nodes:
      child_node_id = node['id']
      child_node_type = node['type']

      # Translation for resolutions.
      if child_node_type == "resolution":
        child_node_id = child_node_id.replace(parent_node_id, "")
        if parent_node_type == "domain":
          child_node_type = "ip_address"
        else:
          child_node_type = "domain"

      # Adds data to graph.
      new_node = self.add_node(child_node_id, child_node_type)
      self.add_link(node_id, child_node_id, expansion)
      if 'attributes' in node:
        new_node.add_attributes(node['attributes'])

    self._increment_api_counter()

    if has_more:
      cursor = data['meta']['cursor']
      next_max = max_nodes_per_relationship - len(data['data'])
      if next_max > 0:
        self.expand(
          node_id, expansion, max_nodes_per_relationship=next_max, cursor=cursor)

  def expand_one_level(self, node, max_nodes_per_relationship=None):
    """Expands 20 relations for each relationship that we know in VirusTotal for
    the give node.

    Params:
      node: string, node ID.
      max_nodes_per_relationship: (opt) integer, max number of nodes that will
        be expanded per relationship.

    Returns:
      Boolean, whether there are more expansions available in this node.

    It consumes API quota, one for each expansion available for the node.
    """
    results = []
    node = self._get_node_id(node)
    for expansion in self.nodes[node].expansions_available:
      results.append(
          pool.apply_async(
              self.expand,
              (node, expansion, max_nodes_per_relationship))
          )
      # self.expand(
      #     node, expansion, max_nodes_per_relationship=max_nodes_per_relationship)

    # Wait for results.
    [r.get() for r in results]

  def expand_n_level(self, level=1, max_nodes_per_relationship=None,
      max_nodes=None):
    """Expands all the nodes in the graph `level` levels.

    For example:
      If your graph has three nodes, and you apply a expand_n_level(1). It will
      expand the three nodes with all the known expansions for those nodes.

      If you select 2 levels of expansions. After the first expansion is applied
      to the three nodes, the new discovered nodes will be expanded as well.

    Args:
      level: (opt) integer, number of layers down the graph that will be expanded.
      max_nodes_per_relationship: (opt) integer, max number of nodes that will
        be expanded per relationship.
      max_nodes: (opt) integer, max number of nodes that will be added to the
        graph. The expansion will stop as soon as any expansion result adds more
        than this limit to the graph.
    """
    pending = {node_id for node_id in iterkeys(self.nodes)}
    visited = set()
    for _ in range(level):
      for node_id in pending:
        self.expand_one_level(
          node_id, max_nodes_per_relationship=max_nodes_per_relationship)
        visited.add(node_id)
        if max_nodes and len(self.nodes) > max_nodes:
          self.log(
              "Hit the maximum limits, stopping the calculation. Node len: %s" %
              len(self.nodes))
          return
      pending = {node_id
                 for node_id in iterkeys(self.nodes)
                 if node_id not in visited}

  def add_link(self, node_source, node_target, connection_type):
    """Adds a link between node_source and node_target with the connection_type.

    If the source or target node don't exist, an exception will be raised.

    Params:
      node_source: string, source node ID.
      node_targe: string, target node ID.
      connection_type: string, connection type. For example: compressed_parent.

    Raises:
      NodeNotFound: if the node is not found.

    This call does NOT consume API quota.
    """
    node_source = self._get_node_id(node_source) 
    node_target = self._get_node_id(node_target)
    if node_source not in self.nodes:
      raise NodeNotFound("Source '%s' not found in nodes" % node_source)
    if node_target not in self.nodes:
      raise NodeNotFound("Target '%s' not found in nodes" % node_target)
    self.links[(node_source, node_target, connection_type)] = True

  def delete_node(self, node_id):
    """Deletes a node from the graph.

    Params:
      node_id: string, node ID.

    This call does NOT consume API quota.
    """
    node_id = self._get_node_id(node_id)
    if node_id not in self.nodes:
      raise NodeNotFound("node '%s' not found in nodes" % node_id)

    del self.nodes[node_id]
    to_be_deleted = []
    for link in self.links:
      source, target, _ = link
      if source == node_id or target == node_id:
        to_be_deleted.append(link)
    for link in to_be_deleted:
      del self.links[link]

  def get_ui_link(self):
    """Requires that save_graph was called."""
    return "https://www.virustotal.com/graph/%s" % self.graph_id

  def get_iframe_code(self):
    """Requires that save_graph was called."""
    return """
    <iframe src="https://www.virustotal.com/graph/embed/%s" width="800" height="600"></iframe>
    """ % self.graph_id

class Node(object):

  def __init__(self, node_id, node_type):
    """Creates an instance of a graph object."""
    assert node_type in SUPPORTED_NODE_TYPES
    self.node_id = node_id
    self.node_type = node_type

    self.expansions_available = NODE_EXPANSIONS.get(node_type)
    self.attributes = None
    self.label = ""

  def add_attributes(self, attributes):
    """Adds the attributes if the node doesn't have it yet.

    Args:
      attributes: dict, VirusTotal attribute dict.
    """
    if not self.attributes:
      self.attributes = attributes

  def add_label(self, label):
    """Adds a label to the node.

    Args:
      label: string, value of the label.
    """
    self.label = label

  def __str__(self):
    return "%s: %s" % (self.node_id, self.attributes)

  def __repr__(self):
    return str(self)

  @staticmethod
  def get_id(node_id):
    return node_id.replace(".", "")
