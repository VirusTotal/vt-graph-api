"""Test add node to graph."""


import pytest
import vt_graph_api
import vt_graph_api.errors


test_graph = vt_graph_api.VTGraph(
    "Dummy api key",
    verbose=False,
    private=False,
    name="Graph test",
    user_editors=["jinfantes"],
    group_viewers=["virustotal"]
)


def test_add_node_file_sha256(mocker):
  """Test add node file sha256."""
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  added_node = test_graph.add_node(
      added_node_id, "file",
      label="Investigation node"
  )
  assert test_graph.nodes[added_node_id] == added_node
  assert len(test_graph.nodes) == 1
  # add the same node again to check that graph's nodes not increases
  test_graph.add_node(added_node_id, "file", label="Investigation node")
  assert len(test_graph.nodes) == 1
  mocker.resetall()


def test_add_node_file_sha1(mocker):
  """Test add node file sha1."""
  request_data = {
      "data": {
          "attributes": {
              "sha256":
                  "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
          }
      }
  }
  mocker.patch.object(test_graph, "_fetch_information")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467"
  added_node = test_graph.add_node(
      added_node_id, "file",
      label="Investigation node"
  )
  assert not test_graph.nodes.get(added_node_id)
  assert test_graph.nodes[added_node.node_id] == added_node
  mocker.resetall()


def test_add_node_file_md5(mocker):
  """Test add node file md5."""
  request_data = {
      "data": {
          "attributes": {
              "sha256":
                  "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
          }
      }
  }
  mocker.patch.object(test_graph, "_fetch_information")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "84c82835a5d21bbcf75a61706d8ab549"
  added_node = test_graph.add_node(
      added_node_id, "file",
      label="Investigation node"
  )
  assert test_graph.nodes.get(added_node_id) is None
  assert test_graph.nodes[added_node.node_id] == added_node
  mocker.resetall()


def test_add_node_url(mocker):
  """Test add node URL."""
  request_data = {
      "data": {
          "id":
              "u-afb80d6e2f84fbe2248ad781ade97a8a0479ee691d523142d44f102b2c9753c1-1566543875",
          "type": "analysis"
      }
  }
  mocker.patch.object(test_graph, "_fetch_information")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.post", return_value=m)
  added_node_id = "http://cwwnhwhlz52maqm7.onion/"
  added_node = test_graph.add_node(
      added_node_id, "url",
      label="Investigation node"
  )
  assert test_graph.nodes.get(added_node_id) is None
  assert test_graph.nodes[added_node.node_id] == added_node
  mocker.resetall()


def test_add_node_domain(mocker):
  """Test add node domain."""
  m = mocker.Mock(status_code=400, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "google.com"
  added_node = test_graph.add_node(
      added_node_id, "domain",
      label="Investigation node"
  )
  assert test_graph.nodes[added_node_id] == added_node
  mocker.resetall()


def test_add_node_ip(mocker):
  """Test add node IP."""
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "104.17.38.137"
  added_node = test_graph.add_node(
      added_node_id, "ip_address",
      label="Investigation node"
  )
  assert test_graph.nodes[added_node_id] == added_node
  mocker.resetall()


def test_add_node_not_supported(mocker):
  """Test add node with not supported type."""
  with pytest.raises(vt_graph_api.errors.NodeNotSupportedTypeError,
                     match=r"Node type: dummy not supported"):
    mocker.patch.object(test_graph, "_fetch_information")
    added_node_id = "invented"
    test_graph.add_node(
        added_node_id, "dummy",
        label="Investigation node"
    )
  mocker.resetall()
