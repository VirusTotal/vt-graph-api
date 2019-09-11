"""vt_graph_api.load.virustotal.graph_id.

This modules provides graph loader method for
retrieve saved graph from virustotal.
"""


import requests
import vt_graph_api.errors
import vt_graph_api.graph
import vt_graph_api.node
import vt_graph_api.version


def from_graph_id(graph_id, api_key, intelligence=False):
  """Load VTGraph using the given virustotal graph_id.

  Args:
    graph_id (str): VT Graph ID.
    api_key (str): VT API key.
    intelligence (bool, optional): if True, the graph will search any
        available information using vt intelligence for the node if there is
        no normal information for it. Defaults to false.

  Raises:
    vt_graph_api.errors.LoaderError: wether the given graph_id cannot be found
      or JSON does not have the correct structure.

  Returns:
    VTGraph: the imported graph.
  """
  graph = None
  headers = {"x-apikey": api_key, "x-tool": vt_graph_api.version.__x_tool__}

  # check if user has editor permissions

  # Get graph data
  graph_data_url = (
      "https://www.virustotal.com/api/v3/graphs/{graph_id}"
      .format(graph_id=graph_id)
  )
  graph_data_response = requests.get(graph_data_url, headers=headers)
  if graph_data_response.status_code != 200:
    raise vt_graph_api.errors.LoaderError(
        "Error to find graph with id: {graph_id}. Response code: {status_code}"
        .format(graph_id=graph_id, status_code=graph_data_response.status_code)
    )

  # Get graph viewers
  has_viewers = True
  viewers_data_url = (
      "https://www.virustotal.com/api/v3/graphs/{graph_id}/relationships/viewers"
      .format(graph_id=graph_id)
  )
  viewers_data_response = requests.get(viewers_data_url, headers=headers)
  if viewers_data_response.status_code != 200:
    has_viewers = False

  # Get graph editors
  has_editors = True
  editors_data_url = (
      "https://www.virustotal.com/api/v3/graphs/{graph_id}/relationships/editors"
      .format(graph_id=graph_id)
  )
  editors_data_response = requests.get(editors_data_url, headers=headers)
  if editors_data_response.status_code != 200:
    has_editors = False

  # Decode data and creates graph
  try:
    user_viewers = []
    group_viewers = []
    user_editors = []
    group_editors = []
    data = graph_data_response.json()
    graph_name = data["data"]["attributes"]["graph_data"]["description"]
    private = data["data"]["attributes"]["private"]
    nodes = data["data"]["attributes"]["nodes"]
    links = data["data"]["attributes"]["links"]
    # Set viewers
    if has_viewers:
      viewers_data = viewers_data_response.json()
      for viewer in viewers_data["data"]:
        if viewer["type"] == "group":
          group_viewers.append(viewer["id"])
        else:
          user_viewers.append(viewer["id"])
    # Set editors
    if has_editors:
      editors_data = editors_data_response.json()
      for editor in editors_data["data"]:
        if editor["type"] == "group":
          group_editors.append(editor["id"])
        else:
          user_editors.append(editor["id"])
    # Create empty graph
    graph = vt_graph_api.graph.VTGraph(
        api_key=api_key,
        name=graph_name,
        private=private,
        intelligence=intelligence,
        user_editors=user_editors,
        user_viewers=user_viewers,
        group_editors=group_editors,
        group_viewers=group_viewers,
    )
    graph.graph_id = graph_id

    # Adds nodes
    suitable_nodes = (
        node for node in nodes if node["type"] != "relationship"
    )
    nodes_to_add = []
    for node_data in suitable_nodes:
      node_type = node_data["type"]
      if node_type not in vt_graph_api.node.Node.SUPPORTED_NODE_TYPES:
        node_type = node_data["entity_attributes"]["custom_type"]
      nodes_to_add.append((
          node_data["entity_id"],
          node_type,
          node_data.get("text", ""),
          node_data.get("entity_attributes"),
          node_data["x"],
          node_data["y"]
      ))
    # Add all nodes concurrently
    graph.add_nodes(nodes_to_add, False)

    # It is necessary to clean the given links because they have relationship
    # nodes
    replace_nodes = {
        link["source"]: link["target"]
        for link in links
        if link["source"].startswith("relationship")
    }
    suitable_links = (
        link
        for link in links
        if not link["source"].startswith("relationship")
    )

    for link_data in suitable_links:
      graph.add_link(
          link_data["source"],
          replace_nodes.get(
              link_data["target"],
              link_data["target"]
          ),
          link_data["connection_type"]
      )

  except KeyError:
    raise vt_graph_api.errors.LoaderError("JSON wrong structure")

  # return the imported graph
  return graph
