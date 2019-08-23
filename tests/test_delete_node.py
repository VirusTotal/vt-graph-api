"""Test delete node from graph."""


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


def test_delete_existing_node(mocker):
  """Test delete existing node."""
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={}))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  test_graph.add_node(added_node_id, "file", label="Investigation node")
  test_graph.delete_node(added_node_id)
  assert not test_graph.nodes
  mocker.resetall()


def test_delete_not_existing_node():
  """Test delete not existing node."""
  with pytest.raises(vt_graph_api.errors.NodeNotFoundError,
                     match=r"node 'dummy id' not found in nodes"):
    test_graph.delete_node("dummy id")
