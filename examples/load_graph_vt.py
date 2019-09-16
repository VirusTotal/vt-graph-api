"""VirusTotal Graph id load example."""


import vt_graph_api


API_KEY = ""  # Insert your VT API here.
GRAPH_ID = ""  # Insert yout graph id here.


# Retrieve the graph.
graph = vt_graph_api.VTGraph.from_graph_id(GRAPH_ID, API_KEY)

# modify your graph here

# save it in VirusTotal.
graph.save_graph()

# Get the graph id
print("Graph Id: %s" % graph.graph_id)

# Visualizing the Graph
print(graph.get_ui_link())  # Open the url in the browser
