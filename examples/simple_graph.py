"""Simple VTGraph usage example."""


from vt_graph_api import VTGraph


API_KEY = ""  # Insert your VT API here.


# Creates the graph.
g = VTGraph(
    API_KEY,
    verbose=False,
    private=False,
    name="First Graph API test"
)

# Adds the node.
g.add_node(
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "file",
    label="Investigation node"
)

# Expands the graph 1 level.
g.expand_n_level(
    level=1,
    max_nodes_per_relationship=5,
    max_nodes=100
)

# Saves the graph
g.save_graph()

# Get the graph id
print("Graph Id: %s" % g.graph_id)

# Visualizing the Graph
print(g.get_ui_link())  # Open the url in the browser
