"""vt_graph_api.load.maltego_csv.

This modules provides graph loader method for
maltego graph in xml format.
"""


import xml.etree.ElementTree as ET


XML_NAMESPACE = "{http://graphml.graphdrawing.org/xmlns}"
XML_MTGX = "{http://maltego.paterva.com/xml/mtgx}"


def from_maltego_graphml(filename):
  """Load VTGraph from the given file in maltego graphml format.

  Args:
      filename (str): the path to the graphml file.
  """
  xml_graph = ET.parse(filename).getroot().get(XML_NAMESPACE + "graph")
  nodes = (node for node in xml_graph.findall("node"))
  links = (link for link in xml_graph.findall("edge"))

  for node in nodes:
    node_data = (
        node
        .find(XML_NAMESPACE + "data")
        .find(XML_MTGX + "MaltegoEntity")
    )
    maltego_id = node.get("id")
    node_type = node_data.get("type")
