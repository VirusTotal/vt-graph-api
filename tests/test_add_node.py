"""Test add node to graph."""


import requests
import vt_graph_api
import vt_graph_api.errors


test_graph = vt_graph_api.VTGraph(
    "Dummy api key", verbose=False, private=False, name="Graph test",
    user_editors=["agfernandez"], group_viewers=["virustotal"])


def test_add_node_file_sha256(mocker):
  """Test add node file sha256."""
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  node_id = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  added_node = test_graph.add_node(node_id, "file", label="Investigation node")
  assert test_graph.nodes[node_id] == added_node
  assert len(test_graph.nodes) == 1
  # add the same node again to check that graph's nodes not increases
  test_graph.add_node(node_id, "file", label="Investigation node")
  assert len(test_graph.nodes) == 1
  mocker.resetall()


def test_add_node_file_sha1(mocker):
  """Test add node file sha1."""
  rq_id = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  request_data = {
      "data": {
          "attributes": {
              "sha256": rq_id
          }
      }
  }
  mocker.patch.object(test_graph, "_fetch_node_information")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  node_id = "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467"
  added_node = test_graph.add_node(node_id, "file", label="Investigation node")
  assert not test_graph.nodes.get(node_id)
  assert test_graph.nodes[added_node.node_id] == added_node
  mocker.resetall()


def test_add_node_file_md5(mocker):
  """Test add node file md5."""
  rq_id = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  request_data = {
      "data": {
          "attributes": {
              "sha256": rq_id
          }
      }
  }
  mocker.patch.object(test_graph, "_fetch_node_information")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "84c82835a5d21bbcf75a61706d8ab549"
  added_node = test_graph.add_node(
      added_node_id, "file", label="Investigation node")
  assert test_graph.nodes.get(added_node_id) is None
  assert test_graph.nodes[added_node.node_id] == added_node
  mocker.resetall()


def test_add_node_url(mocker):
  """Test add node URL."""
  rq_id = "u-afb80d6e2f84fbe2248ad78-1566543875"
  request_data = {
      "data": {
          "id": rq_id,
          "type": "analysis"
      }
  }
  mocker.patch.object(test_graph, "_fetch_node_information")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.post", return_value=m)
  added_node_id = "http://cwwnhwhlz52maqm7.onion/"
  added_node = test_graph.add_node(
      added_node_id, "url", label="Investigation node")
  assert not test_graph.nodes.get(added_node_id)
  assert test_graph.nodes[added_node.node_id] == added_node
  mocker.resetall()


def test_add_node_domain(mocker):
  """Test add node domain."""
  m = mocker.Mock(status_code=400, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "google.com"
  added_node = test_graph.add_node(
      added_node_id, "domain", label="Investigation node")
  assert test_graph.nodes[added_node_id] == added_node
  mocker.resetall()


def test_add_node_ip(mocker):
  """Test add node IP."""
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "104.17.38.137"
  added_node = test_graph.add_node(
      added_node_id, "ip_address", label="Investigation node")
  assert test_graph.nodes[added_node_id] == added_node
  mocker.resetall()


def test_add_node_with_fetch_vt_enterprise_search_and_found(mocker):
  """Test add node calling fetch_vt_enterprise to search for the node id."""
  rq_id = "5504e04083d6146a67cb0d671d8ad5885315062c9ee08a62e40e264c2d5eab91"
  request_data = {
      "data": [
          {
              "id": rq_id,
              "type": "file"
          }
      ],
      "meta": {
          "total_hits": 1
      }
  }
  mocker.patch.object(test_graph, "_fetch_node_information")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "dummy file.bak"
  added_node = test_graph.add_node(
      added_node_id, "file", label="Investigation node")
  assert not test_graph.nodes.get(added_node_id)
  assert test_graph.nodes[added_node.node_id] == added_node
  url = "https://www.virustotal.com/api/v3/intelligence/search?query={query}".format(
      query=added_node_id)
  requests.get.assert_called_with(url, headers=test_graph._get_headers())
  mocker.resetall()


def test_add_node_with_fetch_vt_enterprise_search_and_not_found(mocker):
  """Test add node with calling fetch_vt_enterprise without exact result."""
  rq_id_1 = "efa0b414a831cbf724d1c67808b7483dec22a981ae670947793d114048f880571"
  rq_id_2 = "5504e04083d6146a67cb0d671d8ad5885315062c9ee08a62e40e264c2d5eab912"
  request_data = {
      "data": [
          {
              "id": rq_id_1,
              "type": "file"
          },
          {
              "id": rq_id_2,
              "type": "file"
          }
      ],
      "meta": {
          "total_hits": 2
      }
  }
  mocker.patch.object(test_graph, "_fetch_node_information")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "dummy file 2.bak"
  added_node = test_graph.add_node(
      added_node_id, "file", label="Investigation node")
  assert test_graph.nodes[added_node_id] == added_node
  url = "https://www.virustotal.com/api/v3/intelligence/search?query={query}".format(
      query=added_node_id)
  requests.get.assert_called_with(url, headers=test_graph._get_headers())
  mocker.resetall()


def test_add_nodes(mocker):
  """Test add nodes."""
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id_1 = (
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
  added_node_type_1 = "file"
  added_node_id_2 = "dummy.com"
  added_node_type_2 = "domain"
  nodes_to_add = [
      {
          "node_id": added_node_id_1,
          "node_type": added_node_type_1,
      },
      {
          "node_id": added_node_id_2,
          "node_type": added_node_type_2,
      }
  ]

  added_nodes = test_graph.add_nodes(nodes_to_add)
  assert test_graph.nodes[added_node_id_1] in added_nodes
  assert test_graph.nodes[added_node_id_2] in added_nodes
  mocker.resetall()
