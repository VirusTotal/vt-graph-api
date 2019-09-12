"""Maltego graphml load example."""


import vt_graph_api.load.maltego


API_KEY = ""  # Insert your VT API here.
FILENAME = "" # Insert yout graphml filename here.

graph = vt_graph_api.load.maltego.from_graphml(FILENAME, API_KEY)

# modify your graph here

# save it in VirusTotal.
graph.save_graph()

# Get the graph id
print("Graph Id: %s" % graph.graph_id)

# Visualizing the Graph
print(graph.get_ui_link())  # Open the url in the browser