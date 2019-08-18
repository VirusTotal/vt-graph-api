import json
import sys
import requests
from multiprocessing.pool import ThreadPool
from multiprocessing import Value, Manager
from six import iterkeys
from .errors import CollaboratorNotFound, NodeNotFound, SaveGraphError
from .node import Node
from .version import __version__ as VERSION

# added compatibility with python 2.7
if sys.version_info[0] < 3:
  import Queue as queue
else:
  import queue


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
    
    Args:
      api_key (str): VT API Key
      name (str, optional): graph title. Defaults to "".
      private (bool, optional): true for private graphs. You need to have
        Private Graph premium feature enabled in your subscription. Defaults to False.
      user_editors ([str], optional): usernames that can edit the graph. Defaults to None.
      user_viewers ([str], optional): usernames that can view the graph. Defaults to None.
      group_editors ([str], optional): groups that can edit the graph. Defaults to None.
      group_viewers ([str], optional): groups that can view the graph. Defaults to None.
      verbose (bool, optional): true for printing log messages. Defaults to False.
    
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

    Args:
      msg (string): message.

    This call does NOT consume API quota.
    """
    if self.verbose:
      print(msg)

  def _add_node_to_output(self, output, node_id):
    """Add the node with the given node_id to the output in order to send
    information to VT API.
    
    Args:
      output (dict): graph structure in json representation to be consumed
        by VT API.
      node_id (str): node ID.
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
      CollaboratorNotFound: if any of the collaborators don't exist.
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
      CollaboratorNotFound: if any of the collaborators don't exist.
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
    if response.status_code == 200:
      data = response.json()
      if 'data' in data:
        self.graph_id = data['data']['id']
      else:
        self.log("Saving graph error: %s" % data)
        raise SaveGraphError(str(data))
    else:
      self.log("Saving graph error: %s status code" % response.status_code)
      raise SaveGraphError("Saving graph error: %s status code" % response.status_code)

    self._add_editors()
    self._add_viewers()

  def _increment_api_counter(self):
    """Increments api counter."""
    self.api_calls += 1
    self.log("API counter incremented. Total value: %s" % self.api_calls)

  def _get_file_sha_256(self, node_id):
    """Return sha256 hash for node_id with file type if matches found in VT, else return simple node_id.

    Args:
      node_id (str): identifier of the node. See the top level documentation.
        to understand IDs.

    Returns:
      str: sha256 of the given file node_id.
    """
    headers = self._get_headers()
    url = "https://www.virustotal.com/api/v3/files/%s" % node_id
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
      data = response.json()
      node_id = data.get('data', dict()).get('attributes', dict()).get('sha256', node_id)
    return node_id

  def _get_url_id(self, node_id):
    """Return correct identifier in case of url instead of sha256.

    Args:
      node_id (str): identifier of the node. See the top level documentation
        to understand IDs.

    Returns:
      str: url identifier for VT api.
    """
    headers = self._get_headers()
    url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(url, data={'url':node_id}, headers=headers)
    if response.status_code == 200:
      data = response.json()
      node_id = data.get('data', dict()).get('id', "u-'%s'-u" % node_id).split('-')
      if len(node_id) > 1:
        node_id = node_id[1]
    return node_id
    

  def _get_node_id(self, node_id):
    """Return correct node_id in case of file node with no sha256 hash or url instead of sha256.

    Args:
      node_id (str) identifier of the node. See the top level documentation
        to understand IDs.

    Returns:
      str: the correct node_id for the given identifier.
    """

    if node_id in iterkeys(self.nodes):
      return node_id 

    new_id = self._get_url_id(node_id)
    if new_id in iterkeys(self.nodes):
      return new_id

    new_id = self._get_file_sha_256(node_id)
    if new_id in iterkeys(self.nodes):
      return new_id
    
    return ""

  def _get_expansion_nodes(self, node, expansion, max_nodes_per_relationship=1000000, cursor=None):
    """Returns the nodes to be attached to given node with the given expansion.

    Args:
      node (Node): node to be expanded
      expansion (str): expansion name. For example: compressed_parents for
        nodes of type file.
      max_nodes_per_relationship (int, optional): max number of nodes that will
        be expanded per relationship. Minimum value will be 10. Defaults to 1000000.
      cursor (str, optional): VT relationships cursor. Defaults to None.

    Returns:
      (list(Node), int): a list with the nodes produced by the given node expansion in the given expansion type,
        and number with api quotas consumed.
    """
    self.log("Expanding node '%s' with expansion '%s'" % (node.node_id, expansion))
    expansion_nodes = []

    parent_node_id = node.node_id
    parent_node_type = node.node_type
    end_point = self._get_api_endpoint(parent_node_type)
    consumed_quotas = 1

    url = "https://www.virustotal.com/api/v3/%s/%s/%s" % (
        end_point, node.node_id, expansion)
    if cursor:
      url = "%s?cursor=%s" % (url, cursor)
    headers = {'x-apikey': self.api_key, 'x-tool': 'graph-api-v1'}
    response = requests.request("GET", url, headers=headers, timeout=40)
    if response.status_code == 200:
      data = response.json()
    else:
      data = {}
      self.log("Request to '%s' with '%s' status code" % (url, response.status_code))
    # Add cursor data.
    has_more = data.get('meta', {})

    # Some results return just one element back.
    if 'data' not in data:
      new_nodes = []
    elif type(data['data']) == dict:
      new_nodes = [data['data']]
    else:
      new_nodes = data['data']

    for node_data in new_nodes:
      child_node_id = node_data['id']
      child_node_type = node_data['type']

      # Translation for resolutions.
      if child_node_type == "resolution":
        child_node_id = child_node_id.replace(parent_node_id, "")
        if parent_node_type == "domain":
          child_node_type = "ip_address"
        else:
          child_node_type = "domain"
      new_node = Node(child_node_id, child_node_type)
      if 'attributes' in node_data:
        new_node.add_attributes(node_data['attributes'])
      expansion_nodes.append(new_node)
    
    if has_more:
      cursor = data['meta']['cursor']
      next_max = max_nodes_per_relationship - len(data['data'])
      if next_max > 0:
        _expansion_nodes, _consumed_quotas = self._get_expansion_nodes(node, expansion, max_nodes_per_relationship=next_max, 
                                              cursor=cursor)
        expansion_nodes += _expansion_nodes
        consumed_quotas += consumed_quotas

    self._increment_api_counter()
    return expansion_nodes, consumed_quotas

  def _recursive_search_parallel(self, node_source, node_target, max_api_quotas=10000, depth=0, max_depth=5, 
    path=list(), nodes_explored=list(), found=Value('i', 0)):
    """Search connection between node source and node_target.
    
                          node_source                             | depth 0 (first node) 
                             +-+                                  |
                             |-|                                  | 
               +----------+-------+-----------+                   |
               |          |   |   |           |                   |
               |          |   |   |           |                   |
               |          v   v   v           |                   |
    thread 1<-+-+         X   X   X          +-+ ----> thread n   | depth 1 (all nodes produced by expands 
              |-|                            |-|                  |   (node_source in all expansion's types)
          +---------+                   +-----------+             |
          |         X                   X           X             |
     +---+-+       +-+                 +-+         +-+            | depth 2
     |   +-+       +-+                 +-+         +-+            |
    +-+                                                           |
    +-+ <--- node_target                                          | depth 3

    This algorithm is based on depth first search. When target node is achived by source, the synchronized value `found` is
    set to 1 in order to stop the others threads.
    
    Args:
      node_source (Node): start node.
      node_target (Node): last node.
      max_api_quotas (int, optional): max number of api quotas. Defaults to 10000.
      depth (int, optional): actual depth. Defaults to 0.
      max_depth (int, optional): max hops between nodes. Defaults to 5.
      path (list((str, str, str, str)), optional): links from node source to node target. Defaults to list().
      nodes_explored (list(Node), optional): Nodes that have been explored before. Defaults to list().
      found (Value, optional): synchronized value between threads. Defaults to Value('i', 0).
    
    Returns:
      (bool, list((str, str, str, str))): wheter path found and list with the computed path from node_source to 
      node_target
    """
    self.log(("search %s | depth: %s" % (node_source.node_id, depth)))

    quotas_consumed = 0
    success = False

    # if node_source has been explored before, it won't be explored againt
    if node_source not in nodes_explored:
      nodes_explored.append(node_source)
      expansions = Node.NODE_EXPANSIONS.get(node_source.node_type)
      total_nodes_expanded = 0
      threads = []
      pools = []
      expansion_nodes = []
      i = 0

      # node_source will be expanded in all expansion's type if there's api quotas enough
      while quotas_consumed < max_api_quotas and i < len(expansions) and not found.value:
        try:
          __nodes, quotas = self._get_expansion_nodes(node_source, expansions[i], max_nodes_per_relationship=40)
          quotas_consumed += quotas
          total_nodes_expanded += len(__nodes)
          if node_target not in __nodes:
            if len(__nodes) > 0:
                expansion_nodes.append((__nodes, expansions[i]))
          else:
            found.value = 1
            success = True
            path.append((node_source.node_id, node_target.node_id, expansions[i], node_target.node_type))
        except requests.ConnectionError:
          self.log('connection timed out when expandind %s with %s' % (node_source.node_id, expansions[i]))
        i += 1

      # if target node not in the nodes expanded, they will be expanded recursively
      if not success and total_nodes_expanded > 0:
        # once node_source has been explored, the nodes of the next level of the dsf algorithm will have the api quotas left
        # divided by the number of nodes which has been the result of the previous expansions.
        expansion_max_api_quota = int((max_api_quotas - quotas_consumed) / (max(total_nodes_expanded, 1)))
        # thread will be launched for each expansion node in a threadpool
        with ThreadPool(processes=total_nodes_expanded) as pool:
          for __nodes, expansion_type in expansion_nodes:
            for node in __nodes:
              threads.append(pool.apply_async(self._recursive_search_parallel, (node, node_target, expansion_max_api_quota, 
                                              depth + 1, max_depth, 
                                              path + [(node_source.node_id, node.node_id, expansion_type, node.node_type)], 
                                              nodes_explored, found)))
          # wait for the threads in order to get their results
          results = [th.get() for th in threads]
        # once al threads have been finished, let's check the results
        i = 0
        while i < len(results) and not success:
          __success, __path = results[i]
          if __success:
            success = __success 
            path = __path
          i += 1
    # finally return if there's connection and the path
    return success, path
        
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
      node_id (string): node ID. Example: https://www.virustotal.com for a url.
      node_type (string): file, url, ip_address or domain.
      fetch_information (bool, optional): whether the script will fetch
        information for this node in VT. If the node already exist in the graph
        it will not fetch information for it. Defaults to True.
      label(str, optional): label that appears next to the node. Defaults to "".

    Returns:
      Node: the node object appended to graph.

    This call consumes API quota if fetch_information=True.
    """
    if node_type == 'file' and len(node_id) != 64:
      node_id = self._get_file_sha_256(node_id)
    if node_type == 'url':
      node_id = self._get_url_id(node_id)
          
    if node_id not in iterkeys(self.nodes):
      new_node = Node(node_id, node_type)
      if label:
        new_node.add_label(label)
      if fetch_information:
        headers = self._get_headers()
        end_point = self._get_api_endpoint(node_type)
        url = "https://www.virustotal.com/api/v3/%s/%s" % (
            end_point, node_id)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
          data = response.json()
        else:
          data = {}
          self.log("Request to '%s' with '%s' status code" % (url, response.status_code))
        if 'attributes' in data.get('data', dict()):
          new_node.add_attributes(data['data']['attributes'])
      self.nodes[node_id] = new_node
    return self.nodes[node_id]


  def expand(self, node_id, expansion, max_nodes_per_relationship=1000000):
    """Expands the given node with the given expansion.

    Args:
      node_id (str): identifier of the node. See the top level documentation
        to understand IDs.
      expansion (str): expansion name. For example: compressed_parents for
        nodes of type file.
      max_nodes_per_relationship (int, optional): max number of nodes that will
        be expanded per relationship. Minimum value will be 10. Defaults to 1000000.
    
    Raises:
      NodeNotFound: if the node is not found.

    This call consumes API quota.
    """
    node_id = self._get_node_id(node_id)
    if node_id not in iterkeys(self.nodes):
      raise NodeNotFound("node '%s' not found in nodes" % node_id)
    node = self.nodes[node_id]

    new_nodes, _ = self._get_expansion_nodes(node, expansion, max_nodes_per_relationship)
    # Adds data to graph.
    for new_node in new_nodes:
      self.add_node(new_node.node_id, new_node.node_type)
      self.add_link(node_id, new_node.node_id, expansion)
    
  def expand_one_level(self, node, max_nodes_per_relationship=None):
    """Expands 20 relations for each relationship that we know in VirusTotal for
    the give node.

    Args:
      node (str): node ID.
      max_nodes_per_relationship (int, optional): max number of nodes that will
        be expanded per relationship. Defaults to None.

    Returns:
      bool: whether there are more expansions available in this node.

    It consumes API quota, one for each expansion available for the node.
    """
    results = []
    node = self._get_node_id(node)
    with ThreadPool(processes=4) as pool:
      for expansion in self.nodes[node].expansions_available:
        results.append(
            self.pool.apply_async(
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
      level (int, optional): number of layers down the graph that will be expanded.
        Defaults to 1.
      max_nodes_per_relationship: (int, optional): max number of nodes that will
        be expanded per relationship. Defaults to None.
      max_nodes (int, optional): max number of nodes that will be added to the
        graph. The expansion will stop as soon as any expansion result adds more
        than this limit to the graph. Defaults to None.
      
    This call consumes API quota, one for each node expansion.
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

    Args:
      node_source (str): source node ID.
      node_targe (str): target node ID.
      connection_type (str): connection type. For example: compressed_parent.

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

  def add_links_if_match(self, node_source, node_target, max_api_quotas=100000, max_depth=5):
    """Adds the needed links between node_source and node_target if node_target could be achieved by node_source.

    Params:
      node_source (str): source node ID.
      node_targe (str): target node ID.
      max_api_quotas (int, optional) maximum number of api quotas thath could
        be consumed. Defaults to 100000.
      max_depth (int, optional): maximum number of hops between the nodes. 
        Defaults to 5. It must be less than 5.

    Returns:
      bool: whether relation has been found. 

    This call consumes API quota (as much as max_api_quotas value), one for each expansion required to find the 
    relation.
    """
    node_source = self._get_node_id(node_source) 
    node_target = self._get_node_id(node_target)
    if node_source not in self.nodes:
      raise NodeNotFound("Source '%s' not found in nodes" % node_source)
    if node_target not in self.nodes:
      raise NodeNotFound("Target '%s' not found in nodes" % node_target)

    node_source = self.nodes[node_source]
    node_target = self.nodes[node_target]
    max_depth = max_depth if max_depth <= 5 else 5

    with Manager() as manager:
      found, links = self._recursive_search_parallel(node_source, node_target, max_api_quotas=max_api_quotas, max_depth=max_depth, nodes_explored=manager.list())
  
    if found:
      for source_id, target_id, connection_type, target_type in links:
        self.add_node(target_id, target_type)
        self.links[(source_id, target_id, connection_type)] = True
      return True
    else:
      return False

  def delete_node(self, node_id):
    """Deletes a node from the graph.

    Args:
      node_id (str): node ID.

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
