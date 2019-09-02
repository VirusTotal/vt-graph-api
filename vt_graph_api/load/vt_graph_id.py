"""vt_graph_api.load.vt_graph_id.

This modules provides graph loader method for
retrieve saved graph from virustotal.
"""


import requests
from vt_graph_api.errors import LoaderError
from vt_graph_api.graph import VTGraph
from vt_graph_api.node import Node
from vt_graph_api.version import __x_tool__


def from_vt_graph_id(api_key, graph_id):
  """Load VTGraph using the given graph_id.

  Args:
    api_key (str): VT API key.
    graph_id (str): VT Graph ID.

  Raises:
    LoaderError: wether the given graph_id cannot be found or JSON
      does not have the correct structure.

  Returns:
    VTGraph: the imported graph.
  """
  imported_graph = None
  headers = {"x-apikey": api_key, "x-tool": __x_tool__}

  # check if user has editor permissions

  # Get graph data
  graph_data_url = (
      "https://www.virustotal.com/api/v3/graphs/{graph_id}"
      .format(graph_id=graph_id)
  )
  graph_data_response = requests.get(graph_data_url, headers=headers)
  if graph_data_response.status_code != 200:
    raise LoaderError(
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
    imported_graph = VTGraph(
        api_key=api_key,
        name=graph_name,
        private=private,
        user_editors=user_editors,
        user_viewers=user_viewers,
        group_editors=group_editors,
        group_viewers=group_viewers,
    )

    imported_graph.graph_id = graph_id

    # Adds nodes
    suitable_nodes = (
        node for node in nodes if node["type"] in Node.SUPPORTED_NODE_TYPES
    )
    for node_data in suitable_nodes:
      imported_graph.add_node(
          node_data["entity_id"], node_data["type"],
          False, node_data.get("text", ""),
          node_data["entity_attributes"],
          node_data["x"], node_data["y"]
      )

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
      imported_graph.add_link(
          link_data["source"],
          replace_nodes.get(
              link_data["target"],
              link_data["target"]
          ),
          link_data["connection_type"]
      )

  except KeyError:
    raise LoaderError("JSON wrong structure")

  return imported_graph
