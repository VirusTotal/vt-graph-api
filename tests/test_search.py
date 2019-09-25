"""Test search VTGraph methods."""


import pytest
import six
import vt_graph_api

try:
  from unittest.mock import call
  from unittest.mock import Mock
  import urllib.parse as urlparse
except ImportError:
  from mock import call
  from mock import Mock
  import urlparse


test_graph = vt_graph_api.VTGraph(
    "Dummy api key", verbose=False, private=False, name="Graph test",
    user_editors=["agfernandez"], group_viewers=["virustotal"])


def test_search_connection_first_level(mocker):
  """Test search connection and found it in the first level."""
  rq_id = "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16"
  request_data = {
      "data": [
          {
              "attributes": {},
              "id": rq_id,
              "type": "file"
          }
      ]
  }
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file")
  node_b = vt_graph_api.Node(
      "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16",
      "file")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  assert test_graph._search_connection(node_a, [node_b], 1000, 5, 100)
  assert test_graph._get_expansion_nodes.call_count == len(
      node_a.expansions_available)
  assert test_graph._parallel_expansion.call_count == 1
  mocker.resetall()


def test_search_connection_second_level(mocker):
  """Test search connection and found it in the second level."""
  rq_id = "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16"
  request_response_first_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": rq_id,
                  "type": "file"
              }
          ]
      }
  ]
  request_response_second_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": "nsis.sf.net",
                  "type": "domain"
              }
          ]
      },
  ]
  side_effects = list(
      request_response_first_level *
      len(vt_graph_api.Node.NODE_EXPANSIONS["file"]))
  side_effects += (
      request_response_second_level *
      len(vt_graph_api.Node.NODE_EXPANSIONS["file"]))
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file")
  node_b = vt_graph_api.Node("nsis.sf.net", "domain")
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  assert test_graph._search_connection(node_a, [node_b], 1000, 5, 100)
  assert test_graph._get_expansion_nodes.call_count == len(side_effects)
  # 2 is the number of distinct nodes that the algorithm will explore
  assert test_graph._parallel_expansion.call_count == 2
  mocker.resetall()


def test_search_connection_third_level(mocker):
  """Test search connection and found it in the third level."""
  rq_id = "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16"
  rq_id_2 = "660903b139d5c7ec80af124e93320c18895de32135450d4acd14096e6c0dd2ef"
  request_response_first_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": rq_id,
                  "type": "file"
              }
          ]
      }
  ]
  request_response_second_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": "nsis.sf.net",
                  "type": "domain"
              }
          ]
      },
  ]
  request_response_third_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": rq_id_2,
                  "type": "file"
              }
          ]
      },
  ]
  side_effects = list(
      request_response_first_level *
      len(vt_graph_api.Node.NODE_EXPANSIONS["file"])
  )
  side_effects += (
      request_response_second_level *
      len(vt_graph_api.Node.NODE_EXPANSIONS["file"])
  )
  side_effects += (
      request_response_third_level *
      len(vt_graph_api.Node.NODE_EXPANSIONS["domain"])
  )
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file")
  node_b = vt_graph_api.Node(
      "660903b139d5c7ec80af124e93320c18895de32135450d4acd14096e6c0dd2ef",
      "file")
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  assert test_graph._search_connection(node_a, [node_b], 3000, 5, 1000)
  assert test_graph._get_expansion_nodes.call_count == len(side_effects)
  # 3 is the number of distinct nodes that the algorithm will explore
  assert test_graph._parallel_expansion.call_count == 3
  mocker.resetall()


def test_search_connection_not_found_and_consumes_max_api_quotas(mocker):
  """Test search connection and found it in the third level."""
  rq_id = "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16"
  rq_id_2 = "660903b139d5c7ec80af124e93320c18895de32135450d4acd14096e6c0dd2ef"
  request_response_first_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": rq_id,
                  "type": "file"
              }
          ]
      }
  ]
  request_response_second_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": "nsis.sf.net",
                  "type": "domain"
              }
          ]
      },
  ]
  request_response_third_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": rq_id_2,
                  "type": "file"
              }
          ]
      },
  ]
  side_effects = list(request_response_first_level * 17)
  side_effects += request_response_second_level * 289
  side_effects += request_response_third_level*2023
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file" )
  node_b = vt_graph_api.Node(
      "660903b139d5c7ec80af124e93320c18895de32135450d4acd14096e6c0dd2ef",
      "file")
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  assert not test_graph._search_connection(node_a, [node_b], 100, 5, 1000)
  assert test_graph._get_expansion_nodes.call_count <= 100
  mocker.resetall()

###############################################################################
#                              END TO END TEST                                #
###############################################################################
SOURCE_NODE_ID = (
    "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906")
INTERMEDIATE_NODE_ID = (
    "bde526ed27ce0630401ad24794014b68e32de413de6bc7f37319e4cc4afa283d")
TARGET_NODE_ID = "nsis.sf.net"

EXPANSION_NODES = {
    SOURCE_NODE_ID: "file",
    INTERMEDIATE_NODE_ID: "file",
    "bde526ed27ce0630401ad24794014b68e32de413de6bc7f37319e4cc4afa283d": "file",
    "070f603e0443b1fae57425210fb3b27c2f77d8983cfefefb0ee185de572df33d": "file",
    "e575a260b7f9efe98a3674eb7347d01d447cebce0e6ef2b9b2444bdd0a98b0a2": "file",
    "d44cc91c43f7099a2c7b5cc4c56e4db903532e96f0b9c7c0a7f1b16117679b1e": "file",
    "e3ecdaf963efcfe5cf20559b4d68dd624ebb83f08d6be15d252a8baf0125eeb2": "file",
    "fb0b6044347e972e21b6c376e37e1115dab494a2c6b9fb28b92b1e45b45d0ebc": "file",
    "download.eu-west-3.fromsmash.co": "domain",
    "76.68.25.125": "ip_address",
    "99.52.126.32": "ip_address",
    "ohd.vault.cf": "domain",
    "http://junior.catsecurity.net/~tmdahr1245/wannacry.exe": "url",
    "428f22a9afd2797ede7c0583d34a052c32693cbb55f567a60298587b6e675c6f": "file",
    "junior.catsecurity.net": "domain",
    "http://cdn.discordapp.com/attachments/564096601342083104/5931234022" +
    "15325722/hungarianproject.exe": "url",
    "https://cdn.discordapp.com/attachments/564096601342083104/593123402" +
    "215325722/hungarianproject.exe": "url",
    "blackhatmail.com": "domain",
    "cdn-20.anonfile.com": "domain",
    "85ce324b8f78021ecfc9b811c748f19b82e61bb093ff64f2eab457f9ef19b186": "file",
    "5c1f4f69c45cff9725d9969f9ffcf79d07bd0f624e06cfa5bcbacd2211046ed6": "file",
    "a93ee7ea13238bd038bcbec635f39619db566145498fe6e0ea60e6e76d614bd3": "file",
}

EXPANSION_SIDE_EFFECTS = {
    SOURCE_NODE_ID: {
        "bundled_files": {
            "data": [
                {
                    "attributes": {},
                    "id": INTERMEDIATE_NODE_ID,
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "070f603e0443b1fae57425210fb3b27c2f77d8983" +
                          "cfefefb0ee185de572df33d",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "e575a260b7f9efe98a3674eb7347d01d447cebce0" +
                          "e6ef2b9b2444bdd0a98b0a2",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "d44cc91c43f7099a2c7b5cc4c56e4db903532e96f" +
                          "0b9c7c0a7f1b16117679b1e",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "e3ecdaf963efcfe5cf20559b4d68dd624ebb83f08" +
                          "d6be15d252a8baf0125eeb2",
                    "type": "file"
                }
            ]
        },
        "carbonblack_children": {
            "data": []
        },
        "carbonblack_parents": {
            "data": [
                {
                    "attributes": {},
                    "id": "fb0b6044347e972e21b6c376e37e1115dab494a2c" +
                          "6b9fb28b92b1e45b45d0ebc",
                    "type": "file"
                }
            ]
        },
        "compressed_parents": {
            "data": [
                {
                    "attributes": {},
                    "id": "fb0b6044347e972e21b6c376e37e1115dab494a2c" +
                          "6b9fb28b92b1e45b45d0ebc",
                    "type": "file"
                }
            ]
        },
        "contacted_domains": {
            "data": [
                {
                    "attributes": {},
                    "id": "download.eu-west-3.fromsmash.co",
                    "type": "domain"
                },
                {
                    "attributes": {},
                    "id": "ohd.vault.cf",
                    "type": "domain"
                }
            ]
        },
        "contacted_ips": {
            "data": [
                {
                    "attributes": {},
                    "id": "76.68.25.125",
                    "type": "ip_address"
                },
                {
                    "attributes": {},
                    "id": "99.52.126.32",
                    "type": "ip_address"
                }
            ]
        },
        "contacted_urls": {
            "data": []
        },
        "email_parents": {
            "data": []
        },
        "embedded_domains": {
            "data": [
                {
                    "attributes": {},
                    "id": "ohd.vault.cf",
                    "type": "domain"
                }
            ]
        },
        "embedded_urls": {
            "data": [
                {
                    "attributes": {},
                    "id": "http://junior.catsecurity.net/~tmdahr1245" +
                          "/wannacry.exe",
                    "type": "url"
                }
            ]
        },
        "embedded_ips": {
            "data": []
        },
        "execution_parents": {
            "data": [
                {
                    "attributes": {},
                    "id": "fb0b6044347e972e21b6c376e37e1115dab494a2c" +
                          "6b9fb28b92b1e45b45d0ebc",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "428f22a9afd2797ede7c0583d34a052c32693cbb5" +
                          "5f567a60298587b6e675c6f",
                    "type": "file"
                }
            ]
        },
        "itw_domains": {
            "data": [
                {
                    "attributes": {},
                    "id": "junior.catsecurity.net",
                    "type": "domain"
                },
                {
                    "attributes": {},
                    "id": "download.eu-west-3.fromsmash.co",
                    "type": "domain"
                },
                {
                    "attributes": {},
                    "id": "ohd.vault.cf",
                    "type": "domain"
                }
            ]
        },
        "itw_urls": {
            "data": [
                {
                    "attributes": {},
                    "id": "http://junior.catsecurity.net/~tmdahr1245" +
                          "/wannacry.exe",
                    "type": "url"
                },
                {
                    "attributes": {},
                    "id": "http://cdn.discordapp.com/attachments/564" +
                          "096601342083104/593123402215325722/hungar" +
                          "ianproject.exe",
                    "type": "url"
                },
                {
                    "attributes": {},
                    "id": "https://cdn.discordapp.com/attachments/564" +
                          "096601342083104/593123402215325722/hungari" +
                          "anproject.exe",
                    "type": "url"
                }
            ]
        },
        "overlay_parents": {
            "data": []
        },
        "pcap_parents": {
            "data": [
                {
                    "attributes": {},
                    "id": "blackhatmail.com",
                    "type": "domain"
                },
                {
                    "attributes": {},
                    "id": "cdn-20.anonfile.com",
                    "type": "domain"
                }
            ]
        },
        "pe_resource_parents": {
            "data": [
                {
                    "attributes": {},
                    "id": "fb0b6044347e972e21b6c376e37e1115dab494a2c6b9" +
                          "fb28b92b1e45b45d0ebc",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "428f22a9afd2797ede7c0583d34a052c32693cbb55f5" +
                          "67a60298587b6e675c6f",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "85ce324b8f78021ecfc9b811c748f19b82e61bb093ff6" +
                          "4f2eab457f9ef19b186",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "5c1f4f69c45cff9725d9969f9ffcf79d07bd0f624e06c" +
                          "fa5bcbacd2211046ed6",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "a93ee7ea13238bd038bcbec635f39619db566145498fe" +
                          "6e0ea60e6e76d614bd3",
                    "type": "file"
                }
            ]
        },
        "similar_files": {
            "data": []
        },
    },
    # Intermediate node will achieve target node in his fifth expansion.
    INTERMEDIATE_NODE_ID: {
        "bundled_files": {
            "data": [
                {
                    "attributes": {},
                    "id": "fb0b6044347e972e21b6c376e37e1115dab494a2" +
                          "c6b9fb28b92b1e45b45d0ebc",
                    "type": "file"
                }
            ]
        },
        "carbonblack_children": {
            "data": []
        },
        "carbonblack_parents": {
            "data": []
        },
        "compressed_parents": {
            "data": []
        },
        "contacted_domains": {
            "data": []
        },
        "contacted_ips": {
            "data": []
        },
        "contacted_urls": {
            "data": []
        },
        "email_parents": {
            "data": []
        },
        "embedded_domains": {
            "data": [
                {
                    "attributes": {},
                    "id": TARGET_NODE_ID,
                    "type": "domain"
                }
            ]
        },

        "embedded_urls": {
            "data": [
                {
                    "attributes": {},
                    "id": "http://junior.catsecurity.net/~tmdahr1245" +
                          "/wannacry.exe",
                    "type": "url"
                }
            ]
        },
        "embedded_ips": {
            "data": []
        },
        "execution_parents": {
            "data": [
                {
                    "attributes": {},
                    "id": "fb0b6044347e972e21b6c376e37e1115dab494a2c" +
                          "6b9fb28b92b1e45b45d0ebc",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "428f22a9afd2797ede7c0583d34a052c32693cbb5" +
                          "5f567a60298587b6e675c6f",
                    "type": "file"
                }
            ]
        },
        "itw_domains": {
            "data": [
                {
                    "attributes": {},
                    "id": "junior.catsecurity.net",
                    "type": "domain"
                },
                {
                    "attributes": {},
                    "id": "download.eu-west-3.fromsmash.co",
                    "type": "domain"
                },
                {
                    "attributes": {},
                    "id": "ohd.vault.cf",
                    "type": "domain"
                }
            ]
        },
        "itw_urls": {
            "data": [
                {
                    "attributes": {},
                    "id": "http://junior.catsecurity.net/~tmdahr1245" +
                          "/wannacry.exe",
                    "type": "url"
                },
                {
                    "attributes": {},
                    "id": "http://cdn.discordapp.com/attachments/564" +
                          "096601342083104/593123402215325722/hungar" +
                          "ianproject.exe",
                    "type": "url"
                },
                {
                    "attributes": {},
                    "id": "https://cdn.discordapp.com/attachments/564" +
                          "096601342083104/593123402215325722/hungari" +
                          "anproject.exe",
                    "type": "url"
                }
            ]
        },
        "overlay_parents": {
            "data": []
        },
        "pcap_parents": {
            "data": [
                {
                    "attributes": {},
                    "id": "blackhatmail.com",
                    "type": "domain"
                },
                {
                    "attributes": {},
                    "id": "cdn-20.anonfile.com",
                    "type": "domain"
                }
            ]
        },
        "pe_resource_parents": {
            "data": [
                {
                    "attributes": {},
                    "id": "fb0b6044347e972e21b6c376e37e1115dab494a2c6b9" +
                          "fb28b92b1e45b45d0ebc",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "428f22a9afd2797ede7c0583d34a052c32693cbb55f5" +
                          "67a60298587b6e675c6f",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "85ce324b8f78021ecfc9b811c748f19b82e61bb093ff6" +
                          "4f2eab457f9ef19b186",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "5c1f4f69c45cff9725d9969f9ffcf79d07bd0f624e06c" +
                          "fa5bcbacd2211046ed6",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "a93ee7ea13238bd038bcbec635f39619db566145498fe" +
                          "6e0ea60e6e76d614bd3",
                    "type": "file"
                }
            ]
        },
        "similar_files": {
            "data": []
        },
    }
}


def mock_request(url, headers, timeout):
  """Mock for method request.get()."""
  assert "x-apikey" in headers
  assert timeout == vt_graph_api.VTGraph.REQUEST_TIMEOUT
  # url path format "/api/v3/<type>/<id>/<expansion>"
  # if id is url it will require extra parse.
  url = urlparse.urlparse(url)
  path = url.path.split("/api/v3/")[1].split("/")
  expansion = path[-1]
  # if url join path again
  node_id = "/".join(path[1:-1])
  if node_id not in EXPANSION_NODES:
    pytest.xfail("This call have never been invoked")

  if node_id not in EXPANSION_SIDE_EFFECTS:
    mock = Mock(status_code=200, json=Mock(return_value={"data": []}))
  else:
    mock = Mock(
        status_code=200,
        json=Mock(return_value=EXPANSION_SIDE_EFFECTS[node_id][expansion]))
  return mock


def test_search_connection_second_level_real_data(mocker):
  """Test search connection end to end.

                     +-----------------+SOURCE_NODE+-----------------+
                     |                       +                       |
                     |                 +-----+---------+             |
                     v                 v               v             v
              bundled_files   carbonblack_children    ...      similar_files
                     +                 +               +             +
         +-----------+----+      +-----+-----+         |      +-------------+
         |           |    |      |           |         |      |      |      |
         v           v    v      v           v         v      v      v      v
  INTERMEDIATE_NODE ...  ...    ...         ...       ...    ...    ...    ...
         +
   +-----+---------------------+
   |             |             |
   v             v             v
  ...    contacted_domains    ...
                 +
                 |
                 v
            TARGET_NODE
  """
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file"
  )
  intermediate_node = vt_graph_api.Node(
      INTERMEDIATE_NODE_ID,
      "file"
  )
  node_b = vt_graph_api.Node(
      "nsis.sf.net",
      "domain"
  )
  mocker.patch("requests.get", mock_request)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  total_nodes_first_level = len(
      node_a.expansions_available)
  assert test_graph._search_connection(node_a, [node_b], 1000, 5, 100)
  # Check that _get_expansion_nodes was called with the correct arguments.
  calls = [
      call(node_a, "bundled_files", 40),
      call(node_a, "carbonblack_children", 40),
      call(node_a, "carbonblack_parents", 40),
      call(node_a, "compressed_parents", 40),
      call(node_a, "contacted_domains", 40),
      call(node_a, "contacted_ips", 40),
      call(node_a, "contacted_urls", 40),
      call(node_a, "email_parents", 40),
      call(node_a, "embedded_domains", 40),
      call(node_a, "embedded_urls", 40),
      call(node_a, "embedded_ips", 40),
      call(node_a, "execution_parents", 40),
      call(node_a, "itw_domains", 40),
      call(node_a, "itw_urls", 40),
      call(node_a, "overlay_parents", 40),
      call(node_a, "pcap_parents", 40),
      call(node_a, "pe_resource_parents", 40),
      call(node_a, "similar_files", 40),
      call(intermediate_node, "bundled_files", 40),
      call(intermediate_node, "carbonblack_children", 40),
      call(intermediate_node, "carbonblack_parents", 40),
      call(intermediate_node, "compressed_parents", 40),
      call(intermediate_node, "contacted_domains", 40),
      call(intermediate_node, "contacted_ips", 40),
      call(intermediate_node, "contacted_urls", 40),
      call(intermediate_node, "email_parents", 40),
      call(intermediate_node, "embedded_domains", 40),
      call(intermediate_node, "embedded_urls", 40),
      call(intermediate_node, "embedded_ips", 40),
      call(intermediate_node, "execution_parents", 40),
      call(intermediate_node, "itw_domains", 40),
      call(intermediate_node, "itw_urls", 40),
      call(intermediate_node, "overlay_parents", 40),
      call(intermediate_node, "pcap_parents", 40),
      call(intermediate_node, "pe_resource_parents", 40),
      call(intermediate_node, "similar_files", 40),
  ]
  test_graph._get_expansion_nodes.assert_has_calls(calls, any_order=True)
  total_expansion_calls = 0
  for node_type in six.itervalues(EXPANSION_NODES):
    total_expansion_calls += len(vt_graph_api.Node.NODE_EXPANSIONS[node_type])
  # all assertions are less than instead of equal because of the difficult of
  # stopping threads when solution is found.
  assert test_graph._get_expansion_nodes.call_count <= total_expansion_calls
  assert test_graph._parallel_expansion.call_count <= (
      1 +
      total_nodes_first_level +
      289  # max expansions in second level
  )
  mocker.resetall()
