"""Test expansion nodes from graph."""


import pytest
import vt_graph_api
import vt_graph_api.errors


test_graph = vt_graph_api.VTGraph(
    "Dummy api key", verbose=False, private=False, name="Graph test",
    user_editors=["agfernandez"], group_viewers=["virustotal"])


def test_get_expansion_nodes_one_level(mocker):
  """Test get expansion nodes at once level."""
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
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file")
  node_b = vt_graph_api.Node(
      "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16",
      "file")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  expansion_nodes, _ = test_graph._get_expansion_nodes(
      node_a, "similar_files", 20)
  assert test_graph._get_expansion_nodes.call_count == 1
  assert node_b in expansion_nodes
  mocker.resetall()


def test_get_expansion_nodes_n_level_with_cursor(mocker):
  """Test get expansion nodes at n level without cursor."""
  rq_id = "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16"
  request_data = {
      "data": [
          {
              "attributes": {},
              "id": rq_id,
              "type": "file"
          }
      ],
      "meta": {
          "cursor": "dummy cursor"
      }
  }
  mocker.spy(test_graph, "_get_expansion_nodes")
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file")
  node_b = vt_graph_api.Node(
      "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16",
      "file")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  expansion_nodes, _ = test_graph._get_expansion_nodes(
      node_a, "similar_files", 40)
  assert test_graph._get_expansion_nodes.call_count == 40
  assert node_b in expansion_nodes
  mocker.resetall()


def test_get_expansion_nodes_n_level_without_cursor(mocker):
  """Test get expansion nodes at n level without cursor."""
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
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file")
  node_b = vt_graph_api.Node(
      "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16",
      "file")
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  expansion_nodes, _ = test_graph._get_expansion_nodes(
      node_a, "similar_files", 1000)
  assert test_graph._get_expansion_nodes.call_count == 1
  assert node_b in expansion_nodes
  mocker.resetall()


def test_expansion_existing_node(mocker):
  """Test expansion existing node in graph."""
  mocker.patch.object(test_graph, "_fetch_node_information")
  rq_id = "fb0b6044347e972e21b6c376e37e1115dab494a2c6b9fb28b92b1e45b45d0ebc"
  first_level = {
      "data": [
          {
              "attributes": {},
              "id": rq_id,
              "type": "file"
          }
      ]
  }
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=first_level))
  mocker.patch("requests.get", return_value=m)
  added_node_id = (
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
  added_node = test_graph.add_node(added_node_id, "file",
                                   label="Investigation node")
  expansion_node = vt_graph_api.Node(
      "fb0b6044347e972e21b6c376e37e1115dab494a2c6b9fb28b92b1e45b45d0ebc",
      "file")
  assert (
      [expansion_node] ==
      test_graph.expand(added_node_id, "compressed_parents", 40))
  assert len(test_graph.nodes) == 2
  assert test_graph.nodes[expansion_node.node_id] == expansion_node
  assert test_graph.links[
      (added_node.node_id, expansion_node.node_id, "compressed_parents")]
  mocker.resetall()


def test_expand_not_existing_node():
  """Test expansion not existing node."""
  with pytest.raises(vt_graph_api.errors.NodeNotFoundError,
                     match=r"Node 'dummy id' not found in nodes."):
    test_graph.expand("dummy id", "compressed_parents", 40)


def test_not_supported_expansion(mocker):
  """Test not suported expansion type."""
  mocker.patch.object(test_graph, "_fetch_node_information")
  added_node_id = (
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
  test_graph.add_node(added_node_id, "file",
                      label="Investigation node")
  expansion = "dummy expansion"
  with pytest.raises(vt_graph_api.errors.NodeNotSupportedExpansionError,
                     match=r"Node %s cannot be expanded with %s expansion." %
                     (added_node_id, expansion)):
    test_graph.expand(added_node_id, expansion, 40)
  mocker.resetall()


def test_expand_one_level_existing_node(mocker):
  """Test expand one level for existing node."""
  mocker.patch.object(test_graph, "_fetch_node_information")
  added_node_id = (
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
  added_node = test_graph.add_node(added_node_id, "file",
                                   label="Investigation node")
  mocker.spy(test_graph, "expand")
  assert not test_graph.expand_one_level(added_node_id, 40)
  assert test_graph.expand.call_count == len(added_node.expansions_available)
  mocker.resetall()


def test_expand_one_level_not_existing_node():
  """Test expand one level for not existing node."""
  with pytest.raises(vt_graph_api.errors.NodeNotFoundError,
                     match=r"Node 'dummy id' not found in nodes."):
    test_graph.expand_one_level("dummy id", 40)


def test_expand_n_level(mocker):
  """Test expand graph n levels."""
  mocker.patch.object(test_graph, "_fetch_node_information")
  test_graph.add_node(
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
      "file", label="Investigation node")
  test_graph.add_node(
      "fb0b6044347e972e21b6c376e37e1115dab494a2c6b9fb28b92b1e45b45d0ebc",
      "file", label="Investigation node 2")
  test_graph.add_node("www.google.es", "domain", label="Investigation node 3")
  mocker.patch.object(test_graph, "expand_one_level")
  mocker.spy(test_graph, "expand_one_level")
  assert not test_graph.expand_n_level(1)
  assert test_graph.expand_one_level.call_count == len(test_graph.nodes)
  mocker.resetall()

def test_expand_node_that_returns_itself_in_the_expansion(mocker):
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
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  test_graph.add_node(rq_id, "file", label="Investigation Node File")
  test_graph.expand(rq_id, "similar_files")
  assert not (rq_id, rq_id, "similar_files") in test_graph.links
  mocker.resetall()
