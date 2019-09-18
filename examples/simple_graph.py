"""Simple VTGraph usage example."""


from vt_graph_api import VTGraph


API_KEY = ""  # Insert your VT API here.


# Creates the graph.
graph = VTGraph(API_KEY, verbose=True, private=True, name="First Graph")

# Adds the node.
graph.add_node(
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "file", label="Investigation node")

# Expands the graph 1 level.
graph.expand_n_level(level=1, max_nodes_per_relationship=5, max_nodes=100)

# Saves the graph
graph.save_graph()

# Get the graph id
print("Graph Id: %s" % graph.graph_id)

# Visualizing the Graph
print(graph.get_ui_link())  # Open the url in the browser
