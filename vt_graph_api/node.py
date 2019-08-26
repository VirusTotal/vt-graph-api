
"""vt_graph_api.node.

this module provides the Python object wrapper for
VTGraph node representation.
"""


import re
from vt_graph_api.errors import NodeNotSupportedTypeError


URL_RE = re.compile(r"https?://", re.IGNORECASE)
SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")


class Node(object):
  """Python object wraper for a the VT Graph Node representation.

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

  @staticmethod
  def is_url(node_id):
    """Check if node_id belongs to url.

    Args:
        node_id (str): node ID.

    Returns:
        bool: wether node_id belongs to url
    """
    return URL_RE.match(node_id)

  @staticmethod
  def is_md5(node_id):
    """Check if node_id belongs to md5 hash.

    Args:
        node_id (str): node ID.

    Returns:
        bool: wether node_id belongs to md5 hash.
    """
    return MD5_RE.match(node_id)

  @staticmethod
  def is_sha1(node_id):
    """Check if node_id belongs to sha1 hash.

    Args:
        node_id (str): node ID.

    Returns:
        bool: wether node_id belongs to sha1 hash.
    """
    return SHA1_RE.match(node_id)

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
