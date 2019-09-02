"""VTGraph load usage example."""


import vt_graph_api.load


API_KEY = ""  # Insert your VT API here.
GRAPH_ID = ""  # Insert yout graph id here.


# Retrieve the graph.
graph = vt_graph_api.load.from_vt_graph_id(API_KEY, GRAPH_ID)

# modify your graph here

# save it in VirusTotal.
graph.save_graph()

# Get the graph id
print("Graph Id: %s" % graph.graph_id)

# Visualizing the Graph
print(graph.get_ui_link())  # Open the url in the browser
