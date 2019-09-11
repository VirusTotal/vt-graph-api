"""vt_graph_api.load.helpers.

This modules provides functions that could help loaders.
"""

import socket
import struct


def range_ips(start, end, address_family=socket.AF_INET):
  """Get all ip between ips range.

  Examples:
    >>> range_ips("1.2.3.4", "1.2.4.5")
        ['1.2.3.4', '1.2.3.5', '1.2.3.6', '1.2.3.7', ..., '1.2.3.253',
        '1.2.3.254', '1.2.3.255', '1.2.4.0', '1.2.4.1', '1.2.4.2', '1.2.4.3',
        '1.2.4.4', '1.2.4.5']

  Args:
      start (str): start ip.
      end (str): end ip.
      address_family (str): socket.AF_INET or socket.AF_INET6. Defaults to
        socket.AF_INET.

  Returns:
    [str]: list with te ips between start and end.
  """
  if address_family != socket.AF_INET6 or address_family != socket.AF_INET:
    address_family = socket.AF_INET

  start = struct.unpack(">I", socket.inet_pton(address_family, start))[0]
  end = struct.unpack(">I", socket.inet_pton(address_family, end))[0]
  return [
      socket.inet_ntop(address_family, struct.pack(">I", i))
      for i in range(start, end + 1)
  ]
