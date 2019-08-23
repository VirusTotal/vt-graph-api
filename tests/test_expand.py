"""Test expansion nodes from graph."""


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


def test_expansion_existing_node(mocker):
  """Test expansion existing node in graph."""
  mocker.patch.object(test_graph, "_fetch_information")
  first_level = {
      "data": [
          {
              "attributes": {},
              "id":
                  "fb0b6044347e972e21b6c376e37e1115" +
                  "dab494a2c6b9fb28b92b1e45b45d0ebc",
              "type": "file"
          }
      ]
  }
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=first_level))
  mocker.patch("requests.get", return_value=m)
  added_node_id = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  added_node = test_graph.add_node(added_node_id, "file",
                                   label="Investigation node")
  expansion_node = vt_graph_api.Node(
      "fb0b6044347e972e21b6c376e37e1115dab494a2c6b9fb28b92b1e45b45d0ebc",
      "file"
  )
  test_graph.expand(added_node_id, "compressed_parents", 40)
  assert len(test_graph.nodes) == 2
  assert test_graph.nodes[expansion_node.node_id] == expansion_node
  assert test_graph.links[
      (added_node.node_id, expansion_node.node_id, "compressed_parents")
  ]
  mocker.resetall()


def test_expand_not_existing_node():
  """Test expansion not existing node."""
  with pytest.raises(vt_graph_api.errors.NodeNotFoundError,
                     match=r"node 'dummy id' not found in nodes"):
    test_graph.expand("dummy id", "compressed_parents", 40)


def test_not_supported_expansion(mocker):
  """Test not suported expansion type."""
  mocker.patch.object(test_graph, "_fetch_information")
  added_node_id = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  test_graph.add_node(added_node_id, "file",
                      label="Investigation node")
  expansion = "dummy expansion"
  with pytest.raises(vt_graph_api.errors.NodeNotSupportedExpansionError,
                     match=r"node %s cannot be expanded with %s expansion" %
                     (added_node_id, expansion)):
    test_graph.expand(added_node_id, expansion, 40)
  mocker.resetall()


def test_expand_one_level_existing_node(mocker):
  """Test expand one level for existing node."""
  mocker.patch.object(test_graph, "_fetch_information")
  added_node_id = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
  added_node = test_graph.add_node(added_node_id, "file",
                                   label="Investigation node")
  mocker.patch.object(test_graph, "expand")
  mocker.spy(test_graph, "expand")
  test_graph.expand_one_level(added_node_id, 40)
  assert test_graph.expand.call_count == len(added_node.expansions_available)
  mocker.resetall()


def test_expand_one_level_not_existing_node():
  """Test expand one level for not existing node."""
  with pytest.raises(vt_graph_api.errors.NodeNotFoundError,
                     match=r"node 'dummy id' not found in nodes"):
    test_graph.expand_one_level("dummy id", 40)


def test_expand_n_level(mocker):
  """Test expand graph n levels."""
  mocker.patch.object(test_graph, "_fetch_information")
  test_graph.add_node(
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
      "file",
      label="Investigation node"
  )
  test_graph.add_node(
      "fb0b6044347e972e21b6c376e37e1115dab494a2c6b9fb28b92b1e45b45d0ebc",
      "file",
      label="Investigation node 2"
  )
  test_graph.add_node(
      "www.google.es",
      "domain",
      label="Investigation node 3"
  )
  mocker.patch.object(test_graph, "expand_one_level")
  mocker.spy(test_graph, "expand_one_level")
  test_graph.expand_n_level(1)
  assert test_graph.expand_one_level.call_count == len(test_graph.nodes)
  mocker.resetall()
