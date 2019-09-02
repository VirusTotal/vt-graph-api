"""vt_graph_api.load.

This modules provides virustotal graph loaders through with,
the user could load VTGraph in different ways.
"""


from vt_graph_api.load.maltego_csv import from_maltego_csv
from vt_graph_api.load.maltego_xml import from_maltego_xml
from vt_graph_api.load.vt_graph_id import from_vt_graph_id


__all__ = ["from_vt_graph_id", "from_maltego_csv", "from_maltego_xml"]
