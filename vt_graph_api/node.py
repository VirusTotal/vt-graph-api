"""vt_graph_api.node.

This module provides the Python object wrapper for
VTGraph node representation.
"""


import re


URL_RE = re.compile(r"https?://", re.IGNORECASE)
SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
IPV4_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
DOMAIN_RE = re.compile(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$")


class Node(object):
  """Python object wraper for the VT Graph Node representation.

  Attributes:
    node_id (str): node identifier.
    node_type (str): node type, must be one of the SUPPORTED_NODE_TYPES.
    pretty_id (str): node identifier without dots.
    x (int, optional): X coordinate for Node representation in VT Graph GUI.
    y (int, optional): Y coordinate for Node representation in VT Graph GUI.
    expansions_available ([str]): available expansions for the node.
    attributes (dict): VirusTotal attribute dict.
    label (str): node name.
    children (dict): dict with the children for each expansion type.
    relationship_ids (dict): dict with the relationship id for each
      expansion type.
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
          "embedded_urls",
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
          "downloaded_files",
          "last_serving_ip_address",
          "network_location",
          "redirecting_urls",
      ],
      "domain": [
          "inmediate_parent",
          "parent",
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
      ]
  }

  def __init__(self, node_id, node_type, x=0, y=0):
    """Creates an instance of a node object.

    Args:
      node_id (str): node identifier.
      node_type (str): node type, must be one of the SUPPORTED_NODE_TYPES
      x (int, optional): X coordinate for Node representation in VT Graph GUI.
      y (int, optional): Y coordinate for Node representation in VT Graph GUI.
    """
    self.pretty_id = node_id.replace(".", "")
    self.node_id = node_id
    self.node_type = node_type
    self.x = x
    self.y = y
    self.expansions_available = self.NODE_EXPANSIONS.get(node_type, [])
    self.attributes = None
    self.label = ""
    self.children = {
        expansion_type: [] for expansion_type in self.expansions_available
    }
    self.relationship_ids = {}

  def get_detections(self):
    """Get the node detections from attributes.

    Returns:
      int: the number of detections.
    """
    if "has_detections" in self.attributes:
      return self.attributes["has_detections"]
    else:
      stats = self.attributes.get("last_analysis_stats", {})
      return stats.get("malicious", 0) + stats.get("suspicious", 0)

  @staticmethod
  def is_url(node_id):
    """Check if node_id belongs to url.

    Args:
        node_id (str): node ID.

    Returns:
        bool: whether node_id belongs to a url
    """
    return URL_RE.match(node_id)

  @staticmethod
  def is_md5(node_id):
    """Check if node_id belongs to md5 hash.

    Args:
        node_id (str): node ID.

    Returns:
        bool: wether node_id belongs to a md5 hash.
    """
    return MD5_RE.match(node_id)

  @staticmethod
  def is_sha1(node_id):
    """Check if node_id belongs to sha1 hash.

    Args:
        node_id (str): node ID.

    Returns:
        bool: wether node_id belongs to a sha1 hash.
    """
    return SHA1_RE.match(node_id)

  @staticmethod
  def is_sha256(node_id):
    """Check if node_id belongs to a sha256 hash.

    Args:
        node_id (str): node ID.

    Returns:
        bool: wether node_id belongs to a sha256 hash.
    """
    return SHA256_RE.match(node_id)

  @staticmethod
  def is_ipv4(node_id):
    """Check if node_id belongs to ipv4.

    Args:
        node_id (str): node ID.

    Returns:
        bool: wether node_id belongs to a ipv4.
    """
    return IPV4_RE.match(node_id)

  @staticmethod
  def is_domain(node_id):
    """Check if node_id belongs to domain name.

    Args:
        node_id (str): node ID.

    Returns:
        bool: wether node_id belongs to a domain name.
    """
    return DOMAIN_RE.match(node_id)

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

  def add_child(self, node_id, expansion):
    """Add child to Node in the given expansion.

    Args:
      node_id (str): child node id.
      expansion (str): expansion for the given node_id.
    """
    if expansion not in self.children:
      self.children[expansion] = []

    self.children[expansion].append(node_id)

  def delete_child(self, node_id, expansion):
    """Delete child from Node in the given expansion.

    Args:
      node_id (str): child node id.
      expansion (str): expansion for the given node_id.
    """
    if expansion in self.children:
      self.children[expansion].remove(node_id)

  def reset_relationship_ids(self):
    """Reset relationship_ids."""
    self.relationship_ids.clear()

  def __str__(self):
    return "%s" % (self.node_id)

  def __repr__(self):
    return str(self)

  def __eq__(self, other):
    return isinstance(other, Node) and self.node_id == other.node_id

  def __hash__(self):
    return hash(self.node_id)
