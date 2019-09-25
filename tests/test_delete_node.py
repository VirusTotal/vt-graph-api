"""Test delete node from graph."""


import pytest
import vt_graph_api
import vt_graph_api.errors


test_graph = vt_graph_api.VTGraph(
    "Dummy api key", verbose=False, private=False, name="Graph test",
    user_editors=["agfernandez"], group_viewers=["virustotal"])


def test_delete_existing_node(mocker):
  """Test delete existing node."""
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id = (
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
  test_graph.add_node(added_node_id, "file", label="Investigation node")
  test_graph.delete_node(added_node_id)
  assert not test_graph.nodes
  mocker.resetall()


def test_delete_node_with_links(mocker):
  """Test delete existing node with links."""
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id_a = (
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
  added_node_id_b = (
      "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16")
  test_graph.add_node(added_node_id_a, "file", label="Investigation node")
  test_graph.add_node(added_node_id_b, "file", label="Investigation node 2")
  test_graph.add_link(added_node_id_a, added_node_id_b, "similar_files")
  assert test_graph.links[(added_node_id_a, added_node_id_b, "similar_files")]
  test_graph.delete_node(added_node_id_a)
  assert added_node_id_a not in test_graph.nodes
  assert not test_graph.links.get(
      (added_node_id_a, added_node_id_b, "similar_files"))
  mocker.resetall()


def test_delete_not_existing_node():
  """Test delete not existing node."""
  with pytest.raises(vt_graph_api.errors.NodeNotFoundError,
                     match=r"Node 'dummy id' not found in nodes."):
    test_graph.delete_node("dummy id")
