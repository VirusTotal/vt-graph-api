"""Test create a Group of nodes."""

import pytest
import vt_graph_api
import vt_graph_api.errors


def create_dummy_graph():
  return vt_graph_api.VTGraph(
      "Dummy api key", verbose=False, private=False, name="Graph test",
      user_editors=["dummy_user"], group_viewers=["virustotal"])


def test_create_empty_group():
  """Test create a group without nodes."""
  test_graph = create_dummy_graph()
  test_graph.add_node("virustotal.com", "domain")
  test_graph.add_node("google.com", "domain")

  with pytest.raises(vt_graph_api.errors.CreateGroupError,
                     match=r"A group must contain at least one node."):
    test_graph.create_group([], "Group 1")


def test_create_group_with_nodes_already_grouped():
  """Test create a group with nodes already grouped."""
  test_graph = create_dummy_graph()
  test_graph.add_node("virustotal.com", "domain")
  test_graph.add_node("google.com", "domain")
  test_graph.create_group(['virustotal.com', 'google.com'], 'Group 1')

  with pytest.raises(vt_graph_api.errors.CreateGroupError,
                     match=r"Nodes .+ are already in groups."):
    test_graph.create_group(['virustotal.com', 'google.com'], "Group 1")


def test_create_group_with_node_that_does_not_exist():
  """Test create a group with nodes that are not in the graph."""
  test_graph = create_dummy_graph()
  test_graph.add_node("virustotal.com", "domain")
  test_graph.add_node("google.com", "domain")
  test_graph.create_group(['virustotal.com', 'google.com'], 'Group 1')

  with pytest.raises(vt_graph_api.errors.CreateGroupError,
                     match=r"Node hola.es is not in the Graph."):
    test_graph.create_group(['virustotal.com', 'hola.es'], "Group 1")


def test_create_group(mocker):
  """Test create a group."""
  test_graph = create_dummy_graph()

  test_graph.add_node("virustotal.com", "domain")
  test_graph.add_node("google.com", "domain")
  test_graph.create_group(['virustotal.com', 'google.com'], 'Group 1')

  mocker.patch.object(test_graph, "_push_editors")
  mocker.patch.object(test_graph, "_push_viewers")
  event_mocked = mocker.patch.object(test_graph, "_push_graph_to_vt")

  test_graph.save_graph()

  # Assert group relationship node is generated
  group_node = event_mocked.call_args[0][0]['data']['attributes']['nodes'][-1]
  assert set(group_node['entity_attributes']['grouped_node_ids']) == {'virustotal.com', 'google.com'}
  assert len(group_node['entity_attributes']['grouped_node_ids']) == 2

  # Assert group relationship links are generated
  links = event_mocked.call_args[0][0]['data']['attributes']['links']
  group_links = [link for link in links if link['connection_type'] == 'group']
  assert len(group_links) == 2
  mocker.resetall()
