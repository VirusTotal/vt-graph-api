"""Test graph has node."""


import vt_graph_api
import vt_graph_api.errors


test_graph = vt_graph_api.VTGraph(
    "Dummy api key", verbose=False, private=False, name="Graph test",
    user_editors=["agfernandez"], group_viewers=["virustotal"])


def test_graph_has_node(mocker):
  """Test add node file sha256."""
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id = (
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
  test_graph.add_node(added_node_id, "file", label="Investigation node")
  assert test_graph.has_node(added_node_id)
  mocker.resetall()


def test_graph_not_has_node():
  """Test add node file sha256."""
  added_node_id = ("Dummy_id")
  assert not test_graph.has_node(added_node_id)
