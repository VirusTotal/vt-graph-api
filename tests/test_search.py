"""Test search VTGraph methods."""


import pytest
try:
  from unittest.mock import call
  from unittest.mock import Mock
  from urllib.parse import urlparse
except ImportError:
  from mock import call
  from mock import Mock
  from urlparse import urlparse
import vt_graph_api


test_graph = vt_graph_api.VTGraph(
    "Dummy api key",
    verbose=False,
    private=False,
    name="Graph test",
    user_editors=["jinfantes"],
    group_viewers=["virustotal"]
)


def test_search_connection_first_level(mocker):
  """Test search connection and found it in the first level."""
  request_data = {
      "data": [
          {
              "attributes": {},
              "id":
                  "7c11c7ccd384fd9f377da499fc0" +
                  "59fa08fdc33a1bb870b5bc3812d24dd421a16",
              "type": "file"
          }
      ]
  }
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file"
  )
  node_b = vt_graph_api.Node(
      "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16",
      "file"
  )
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  assert test_graph._search_connection(node_a, [node_b], 1000, 5, 100)
  assert test_graph._get_expansion_nodes.call_count == len(
      node_a.expansions_available
  )
  assert test_graph._parallel_expansion.call_count == 1
  mocker.resetall()


def test_search_connection_second_level(mocker):
  """Test search connection and found it in the second level."""
  request_response_first_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id":
                      "7c11c7ccd384fd9f377da499fc059fa" +
                      "08fdc33a1bb870b5bc3812d24dd421a16",
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
  side_effects = list(request_response_first_level * 17)
  side_effects += request_response_second_level*289
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file"
  )
  node_b = vt_graph_api.Node(
      "nsis.sf.net",
      "domain"
  )
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  total_file_expansions = len(
      node_a.expansions_available
  )
  total_nodes_first_level = total_file_expansions
  assert test_graph._search_connection(node_a, [node_b], 1000, 5, 100)
  assert test_graph._get_expansion_nodes.call_count <= (
      total_file_expansions +
      total_file_expansions * total_nodes_first_level
  )
  assert test_graph._parallel_expansion.call_count <= (
      1 +
      total_nodes_first_level
  )
  mocker.resetall()


def test_search_connection_third_level(mocker):
  """Test search connection and found it in the third level."""
  request_response_first_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id":
                      "7c11c7ccd384fd9f377da499fc059fa" +
                      "08fdc33a1bb870b5bc3812d24dd421a16",
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
                  "id":
                      "660903b139d5c7ec80af124e93320" +
                      "c18895de32135450d4acd14096e6c0dd2ef",
                  "type": "file"
              }
          ]
      },
  ]
  side_effects = list(request_response_first_level * 17)
  side_effects += request_response_second_level * 289
  side_effects += request_response_third_level * 2023
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file"
  )
  node_b = vt_graph_api.Node(
      "660903b139d5c7ec80af124e93320c18895de32135450d4acd14096e6c0dd2ef",
      "file"
  )
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  total_file_expansions = len(
      node_a.expansions_available
  )
  total_nodes_first_level = total_file_expansions
  total_domain_expansions = len(
      vt_graph_api.Node.NODE_EXPANSIONS.get("domain")
  )
  total_nodes_second_level = total_nodes_first_level * total_file_expansions
  assert test_graph._search_connection(node_a, [node_b], 3000, 5, 1000)
  assert test_graph._get_expansion_nodes.call_count <= (
      total_file_expansions +
      total_file_expansions * total_nodes_first_level +
      total_domain_expansions * total_nodes_second_level
  )
  assert test_graph._parallel_expansion.call_count <= (
      1 +
      total_nodes_first_level +
      total_nodes_second_level
  )
  mocker.resetall()


def test_search_connection_not_found_and_consumes_max_api_quotas(mocker):
  """Test search connection and found it in the third level."""
  request_response_first_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id":
                      "7c11c7ccd384fd9f377da499fc059fa" +
                      "08fdc33a1bb870b5bc3812d24dd421a16",
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
                  "id":
                      "660903b139d5c7ec80af124e93320" +
                      "c18895de32135450d4acd14096e6c0dd2ef",
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
      "file"
  )
  node_b = vt_graph_api.Node(
      "660903b139d5c7ec80af124e93320c18895de32135450d4acd14096e6c0dd2ef",
      "file"
  )
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
EXPANSION_NODES = {
    "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906": [],
    "bde526ed27ce0630401ad24794014b68e32de413de6bc7f37319e4cc4afa283d": []
}

EXPANSION_SIDE_EFFECTS = {
    "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906": {
        "bundled_files": {
            "data": [
                {
                    "attributes": {},
                    "id": "bde526ed27ce0630401ad24794014b68e32de413d" +
                          "e6bc7f37319e4cc4afa283d",
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
                    "id": "74.125.124.113",
                    "type": "ip_address"
                },
                {
                    "attributes": {},
                    "id": "82.223.21.74",
                    "type": "ip_address"
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
                    "id": "https://cdn.discordapp.com/attachments/56" +
                          "4096601342083104/593123402215325722/hunga" +
                          "rianproject.exe",
                    "type": "url"
                }
            ]
        },
        "contacted_ips": {
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
                    "id": "fb0b6044347e972e21b6c376e37e1115dab494a2c" +
                          "6b9fb28b92b1e45b45d0ebc",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "428f22a9afd2797ede7c0583d34a052c32693cbb5" +
                          "5f567a60298587b6e675c6f",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "85ce324b8f78021ecfc9b811c748f19b82e61bb09" +
                          "3ff64f2eab457f9ef19b186",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "5c1f4f69c45cff9725d9969f9ffcf79d07bd0f624" +
                          "e06cfa5bcbacd2211046ed6",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "a93ee7ea13238bd038bcbec635f39619db56614549" +
                          "8fe6e0ea60e6e76d614bd3",
                    "type": "file"
                }
            ]
        },
        "embedded_urls": {
            "data": [
                {
                    "attributes": {},
                    "id": "junior.catsecurity.net",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "download.eu-west-3.fromsmash.co",
                    "type": "file"
                },
                {
                    "attributes": {},
                    "id": "ohd.vault.cf",
                    "type": "file"
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
                    "id": "fb0b6044347e972e21b6c376e37e1115dab494a2" +
                          "c6b9fb28b92b1e45b45d0ebc",
                    "type": "file"
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
    "bde526ed27ce0630401ad24794014b68e32de413de6bc7f37319e4cc4afa283d": {
        "bundled_files": {
            "data": [
                {
                    "attributes": {},
                    "id": "nsis.sf.net",
                    "type": "domain"
                }
            ]
        }
    }
}

def mock_request(url, *args, **kwargs):
  """Mock for method request.get()."""
  url = urlparse(url)
  node_id, expansion = url.path.split("/")[-2:]
  if not node_id in EXPANSION_NODES or expansion in EXPANSION_NODES[node_id]:
    pytest.xfail("This call have never been invoked")
  EXPANSION_NODES[node_id].append(expansion)
  return Mock(
      status_code=200, 
      json=Mock(
          return_value=EXPANSION_SIDE_EFFECTS[node_id][expansion]
      )
  )
    

def test_search_connection_second_level_real_data(mocker):
  """Test search connection end to end."""
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file"
  )
  node_b = vt_graph_api.Node(
      "nsis.sf.net",
      "domain"
  )
  mocker.patch("requests.get", mock_request)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  total_file_expansions = len(
      node_a.expansions_available
  )
  total_nodes_first_level = total_file_expansions
  assert test_graph._search_connection(node_a, [node_b], 19, 5, 100)
  # check that _get_expansion_nodes was called with correct arguments.
  # The first node is espanded 17 times.
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
      call(vt_graph_api.Node(
          "bde526ed27ce0630401ad24794014b68e32de413d" +
          "e6bc7f37319e4cc4afa283d", "file"),
          "bundled_files", 40)
  ]
  test_graph._get_expansion_nodes.assert_has_calls(calls)
  # The target node is reached during the
  # bde526ed27ce0630401ad24794014b68e32de413de6bc7f37319e4cc4afa283d expansion
  assert test_graph._get_expansion_nodes.call_count == (
      len(node_a.expansions_available) + 1
  )
  assert test_graph._parallel_expansion.call_count <= (
      1 +
      total_nodes_first_level +
      289  # max expansions in second level
  )
  mocker.resetall()
