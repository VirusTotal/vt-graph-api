# pylint: disable=superfluous-parens
"""VTGraph basic search usage example."""

import time
from vt_graph_api import VTGraph


API_KEY = ""  # Insert your VT API here.


# Creates the graph.
graph = VTGraph(
    API_KEY,
    verbose=True,
    private=True,
    name="First Graph API test"
)

graph.add_node("b3b7d8a4daee86280c7e54b0ff3283afe3579480", "file", True)
graph.add_node("nsis.sf.net", "domain", True)
start_time = time.time()

graph.add_links_if_match(
    "b3b7d8a4daee86280c7e54b0ff3283afe3579480",
    "nsis.sf.net",
    max_api_quotas=1000,
    max_depth=10
)

print("--- %s seconds ---" % (time.time() - start_time))
graph.save_graph()

# Get the graph id
print("Graph Id: %s" % graph.graph_id)

# Visualizing the Graph
print(graph.get_ui_link())  # Open the url in the browser
