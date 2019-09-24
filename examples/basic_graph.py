"""Basic VTGraph usage example."""


from vt_graph_api import VTGraph


API_KEY = "c2ad34b007d8182a06753507ecfa0dbc550b1679d9bb6a7f53cbe6c13452f74d"  # Insert your VT API here.


# Creates the graph.
graph = VTGraph(API_KEY, verbose=True, private=True, name="First Graph")

# Adds the node.
n = graph.add_node(
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "file", label="Investigation node")

nn = graph.add_node(
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41ca",
    "file", label="Investigation node")

nnn = graph.add_node(
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5gabe8e080e41ca",
    "file", label="Investigation node")

graph.add_link(n.node_id, nn.node_id, "myownrelation")
graph.add_link(n.node_id, nnn.node_id)


# Saves the graph
graph.save_graph()

# Get the graph id
print("Graph Id: %s" % graph.graph_id)

# Visualizing the Graph
print(graph.get_ui_link())  # Open the url in the browser
