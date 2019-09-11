"""vt_graph_api.load.maltego.

This modules provides virustotal graph loaders for maltego graph files.
"""

from vt_graph_api.load.maltego.csv import from_csv
from vt_graph_api.load.maltego.graphml import from_graphml


__all__ = ["from_csv", "from_graphml"]
