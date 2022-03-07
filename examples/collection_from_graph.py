"""Create a VT Collection from VT Graph."""

from vt_graph_api import VTGraph

API_KEY = "" # Insert your VT API here.

# Creates the graph.
graph = VTGraph(API_KEY, verbose=True, private=True, name="First Graph")

# Adds the node.
graph.add_node(
    "malpedia_win_emotet",
    "collection", label="Emotet Collection")

# Expands the graph 1 level.
graph.expand_n_level(level=1, max_nodes_per_relationship=5, max_nodes=100)

collection_ui_link = graph.create_collection("New Emotet collection")

# Visualizing Collection link
print(collection_ui_link)
