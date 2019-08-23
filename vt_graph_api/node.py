
"""Class Node."""


from vt_graph_api.errors import NodeNotSupportedTypeError


class Node(object):
  """Python object wrapper por Node representation.

  Attributes:
    node_id (str): node identifier.
    node_type (str): node type, must be one of the SUPPORTED_NODE_TYPES.
    expansions_available ([str]): available expansions for the node.
    attributes (dict): VirusTotal attribute dict.
    label (str): node name.
  """

  SUPPORTED_NODE_TYPES = ("file", "url", "domain", "ip_address")
  NODE_EXPANSIONS = {
      "file": [
          "bundled_files",
          "carbonblack_children",
          "carbonblack_parents",
          "compressed_parents",
          "contacted_domains",
          "contacted_ips",
          "contacted_urls",
          "email_parents",
          "embedded_domains",
          "embedded_ips",
          "execution_parents",
          "itw_domains",
          "itw_urls",
          "overlay_parents",
          "pcap_parents",
          "pe_resource_parents",
          "similar_files",
      ],
      "url": [
          "contacted_domains",
          "contacted_ips",
          "downloaded_files",
          "last_serving_ip_address",
          "network_location",
          "redirecting_urls",
      ],
      "domain": [
          "communicating_files",
          "downloaded_files",
          "referrer_files",
          "resolutions",
          "siblings",
          "subdomains",
          "urls",
      ],
      "ip_address": [
          "communicating_files",
          "downloaded_files",
          "referrer_files",
          "resolutions",
          "urls",
      ],
  }

  def __init__(self, node_id, node_type):
    """Creates an instance of a graph object.

    Args:
      node_id (str): node identifier.
      node_type (str): node type, must be one of the SUPPORTED_NODE_TYPES

    Raises:
      NodeNotSupportedTypeError: if node_type not in SUPPORTED_NODE_TYPES
    """
    if node_type not in self.SUPPORTED_NODE_TYPES:
      raise NodeNotSupportedTypeError("Node type: %s not supported" % node_type)
    self.node_id = node_id
    self.node_type = node_type

    self.expansions_available = self.NODE_EXPANSIONS.get(node_type)
    self.attributes = None
    self.label = ""

  def add_attributes(self, attributes):
    """Adds the attributes if the node doesn't have it yet.

    Args:
      attributes (dict): VirusTotal attribute dict.
    """
    if not self.attributes:
      self.attributes = attributes

  def add_label(self, label):
    """Adds a label to the node.

    Args:
      label (str): value of the label.
    """
    self.label = label

  def __str__(self):
    return "%s: %s" % (self.node_id, self.attributes)

  def __repr__(self):
    return str(self)

  def __eq__(self, other):
    return isinstance(other, Node) and self.node_id == other.node_id

  @staticmethod
  def get_id(node_id):
    return node_id.replace(".", "")
