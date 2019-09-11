"""vt_graph_api.load.maltego.graphml.

This modules provides graph loader method for
maltego graph in graphml (XML) format.
"""


import defusedxml.ElementTree as ET
import vt_graph_api.graph
import vt_graph_api.load.helpers
import vt_graph_api.load.maltego.legend


XML_NAMESPACE = "{http://graphml.graphdrawing.org/xmlns}"
XML_MTGX = "{http://maltego.paterva.com/xml/mtgx}"
XML_MALTEGO_TYPES_VALUES = {
    "maltego.DNSName": "fqdn",
    "maltego.Domain": "fqdn",
    "maltego.IPv4Address": "ipv4-address",
    "maltego.MXRecord": "fqdn",
    "maltego.NSRecord": "fqdn",
    "maltego.Netblock": "ipv4-range",
    "maltego.Website": "fqdn",
    "maltego.URL": "url",
    "maltego.Hash": "properties.hash",
    "maltego.Document": "title",
    "maltego.EmailAddress": "email",
    "maltego.Person": "person.fullname",
    "maltego.Organization": "title",
    "maltego.Company": "title",
    "maltego.Service": "properties.service",
    "maltego.Port": "properties.port",
    "maltego.Phrase": "text"
}


def from_graphml(
    filename,
    api_key,
    name="",
    private=False,
    intelligence=False,
    user_editors=None,
    user_viewers=None,
    group_editors=None,
    group_viewers=None):
  """Load VTGraph from the given file in maltego graphml format.

  Args:
      filename (str): the path to the graphml file.
      api_key (str): VT API Key
      name (str, optional): graph title. Defaults to "".
      private (bool, optional): true for private graphs. You need to have
        Private Graph premium feature enabled in your subscription. Defaults
        to False.
      intelligence (bool, optional): if True, the graph will search any
        available information using vt intelligence for the node if there is
        no normal information for it. Defaults to false.
      user_editors ([str], optional): usernames that can edit the graph.
        Defaults to None.
      user_viewers ([str], optional): usernames that can view the graph.
        Defaults to None.
      group_editors ([str], optional): groups that can edit the graph.
        Defaults to None.
      group_viewers ([str], optional): groups that can view the graph.
        Defaults to None.

  Raises:
    LoaderError: if XML does not have the correct structure.

  Returns:
    VTGraph: the imported graph.
  """
  xml_graph = ET.parse(filename).getroot().find(XML_NAMESPACE + "graph")
  node_reference = {}
  graph = vt_graph_api.graph.VTGraph(
      api_key=api_key,
      name=name or filename,
      private=private,
      intelligence=intelligence,
      user_editors=user_editors,
      user_viewers=user_viewers,
      group_editors=group_editors,
      group_viewers=group_viewers,
  )

  # First add nodes to graph.
  nodes = (node for node in xml_graph.findall(XML_NAMESPACE + "node"))
  nodes_to_add = []
  for node in nodes:
    node_data = (
        node
        .find(XML_NAMESPACE + "data")
        .find(XML_MTGX + "MaltegoEntity")
    )
    maltego_id = node.get("id")
    maltego_properties = node_data.find(XML_MTGX + "Properties")
    node_type = node_data.get("type")
    if node_type in vt_graph_api.load.maltego.legend.MALTEGO_TYPES_REFERENCE:
      node_ids = []
      suitable_values = (
          attr for attr in maltego_properties
          if attr.get("name") == XML_MALTEGO_TYPES_VALUES.get(node_type)
      )
      # Maybe there is more than one suitable property.
      for attr in suitable_values:
        value = attr.find(XML_MTGX + "Value").text
        # The maltego.Netblock type get IP range, for this reason it will be
        # needed to process each one ip in the given range
        if node_type == "maltego.Netblock":
          ips = value.split("-")
          start = ips[0]
          for ip in ips[1:]:
            node_ids += vt_graph_api.load.helpers.range_ips(start, ip)
            start = ip
        else:
          node_ids.append(value)
      for node_id in node_ids:
        nodes_to_add.append((
            node_id,
            vt_graph_api.load.maltego.legend.MALTEGO_TYPES_REFERENCE[node_type],
            "",
            None,
            0,
            0
        ))
      node_reference[maltego_id] = node_ids, node_type
  # Add all nodes concurrently
  graph.add_nodes(nodes_to_add)

  # Second add links to graph.
  links = (
      link for link in xml_graph.findall(XML_NAMESPACE + "edge")
      if link.get("source") in node_reference and
      link.get("target") in node_reference
  )
  for link in links:
    source_ids, source_type = node_reference[link.get("source")]
    target_ids, _ = node_reference[link.get("target")]
    connection_type_properties = (
        link
        .find(XML_NAMESPACE + "data")
        .find(XML_MTGX + "MaltegoLink")
        .find(XML_MTGX + "Properties")
    )
    connection_type = ""
    for attr in connection_type_properties:
      if attr.get("name") == "maltego.link.transform.display-name":
        connection_type = attr.find(XML_MTGX + "Value").text
    for source_id in source_ids:
      for target_id in target_ids:
        if source_id != target_id:
          # Add link between source and target with te correct connection_type
          # to graph.
          graph.add_link(
              source_id, target_id,
              (
                  vt_graph_api.load.maltego.legend
                  .MALTEGO_EDGE_REFERENCE.get(source_type, {})
                  .get(connection_type, "manual")
              )
          )

  # return the imported graph
  return graph
