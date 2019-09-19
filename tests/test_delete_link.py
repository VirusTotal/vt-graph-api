"""Test delete node from graph."""


import pytest
import vt_graph_api
import vt_graph_api.errors


test_graph = vt_graph_api.VTGraph(
    "Dummy api key", verbose=False, private=False, name="Graph test",
    user_editors=["agfernandez"], group_viewers=["virustotal"])

node_a = test_graph.add_node("dummy_hash_1", "file")
node_b = test_graph.add_node("dummy_hash_2", "file")
node_not_found_id = "dummy_hash_3"


def test_delete_link():
  test_graph.add_link(node_a.node_id, node_b.node_id, "bundled_files")
  assert test_graph.links[((node_a.node_id, node_b.node_id, "bundled_files"))]
  test_graph.delete_link(node_a.node_id, node_b.node_id, "bundled_files")
  assert not test_graph.links.get(
      (node_a.node_id, node_b.node_id, "bundled_files"))


def test_delete_link_node_not_found_error():
  with pytest.raises(
      vt_graph_api.errors.NodeNotFoundError,
      match=(r"Node '{node_id}' not found in nodes.".
             format(node_id=node_not_found_id))):
    test_graph.delete_link(node_not_found_id, node_b.node_id, "bundled_files")

  with pytest.raises(
      vt_graph_api.errors.NodeNotFoundError,
      match=(r"Node '{node_id}' not found in nodes.".
             format(node_id=node_not_found_id))):
    test_graph.delete_link(node_a.node_id, node_not_found_id, "bundled_files")


def test_delete_link_same_node_error():
  with pytest.raises(
      vt_graph_api.errors.SameNodeError,
      match=(r"It is no possible to delete links between the same node; id: " +
             "{node_id}.".format(node_id=node_a.node_id))):
    test_graph.delete_link(node_a.node_id, node_a.node_id, "bundled_files")


def test_delete_link_link_not_found_error():
  connection_type = "dummy connection"
  with pytest.raises(
      vt_graph_api.errors.LinkNotFoundError,
      match=(r"Link between {source} and {target} with {connection_type} does" +
             " not exists.").format(
                 source=node_a.node_id, target=node_b.node_id,
                 connection_type=connection_type)):
    test_graph.delete_link(node_a.node_id, node_b.node_id, connection_type)


def test_delete_links():
  test_graph.add_link(node_a.node_id, node_b.node_id, "bundled_files")
  test_graph.add_link(node_a.node_id, node_b.node_id, "carbonblack_children")
  test_graph.add_link(node_a.node_id, node_b.node_id, "carbonblack_parents")
  assert test_graph.links[((node_a.node_id, node_b.node_id, "bundled_files"))]
  assert test_graph.links[
      ((node_a.node_id, node_b.node_id, "carbonblack_children"))]
  assert test_graph.links[
      ((node_a.node_id, node_b.node_id, "carbonblack_parents"))]
  test_graph.delete_links(node_a.node_id)
  assert not test_graph.links.get(
      (node_a.node_id, node_b.node_id, "bundled_files"))
  assert not test_graph.links.get(
      (node_a.node_id, node_b.node_id, "carbonblack_children"))
  assert not test_graph.links.get(
      (node_a.node_id, node_b.node_id, "carbonblack_parents"))


def test_delete_links_node_not_found_error():
  with pytest.raises(
      vt_graph_api.errors.NodeNotFoundError,
      match=(r"Node '{node_id}' not found in nodes.".
             format(node_id=node_not_found_id))):
    test_graph.delete_links(node_not_found_id)
