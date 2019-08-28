# pylint: disable=superfluous-parens
"""VTGraph advanced search usage example."""

from vt_graph_api import VTGraph


API_KEY = ""  # Insert your VT API here.


# Creates the graph.
graph = VTGraph(
    API_KEY,
    verbose=True,
    private=True,
    name="First Graph API test"
)

# Add some nodes to graph.
graph.add_node("b3b7d8a4daee86280c7e54b0ff3283afe3579480", "file", True)
graph.add_node("nsis.sf.net", "domain", True)
graph.add_node(
    "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
    "file"
)
graph.add_node("www.openssl.org", "domain", True)

# Try to connect node with graph.
graph.connect_with_graph(
    "b3b7d8a4daee86280c7e54b0ff3283afe3579480",
    max_api_quotas=1000,
    max_depth=10
)

graph.save_graph()

# Get the graph id
print("Graph Id: %s" % graph.graph_id)

# Visualizing the Graph
print(graph.get_ui_link())  # Open the url in the browser
