"""Test add node to graph."""


import pytest
import vt_graph_api
import vt_graph_api.errors


test_graph = vt_graph_api.VTGraph(
    "Dummy api key", verbose=False, private=False, name="Graph test",
    user_editors=["agfernandez"], group_viewers=["virustotal"])


def test_add_link(mocker):
  """Test add link."""
  mocker.patch.object(test_graph, "_fetch_node_information")
  node_1 = test_graph.add_node(
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
      "file", label="Investigation node")
  node_2 = test_graph.add_node(
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41bb",
      "file", label="Investigation node")
  test_graph.add_link(node_1.node_id, node_2.node_id, "compressed_parents")
  assert test_graph.links[
      (node_1.node_id, node_2.node_id, "compressed_parents")]
  mocker.resetall()


def test_add_link_not_existing_node():
  """Test link between not existing nodes."""
  with pytest.raises(vt_graph_api.errors.NodeNotFoundError,
                     match=r"Node 'dummy id 1' not found in nodes."):
    test_graph.add_link("dummy id 1", "dummy id 2", "compressed_parents")


def test_add_link_between_the_same_node():
  """Test add link between the same node."""
  dummy_id = "dummy id"
  with pytest.raises(
      vt_graph_api.errors.SameNodeError,
      match=r"It is no possible to add links between the same node; id: {gid}."
      .format(gid=dummy_id)
  ):
    test_graph.add_link(dummy_id, dummy_id, "compressed_parents")


def test_add_links_if_match(mocker):
  """Test add links if match."""
  mocker.patch.object(test_graph, "_fetch_node_information")
  search_connection_response = [[(
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41cc",
      "similar_files",
      "file"
  )]]
  mocker.patch("vt_graph_api.VTGraph._search_connection",
               return_value=search_connection_response)
  node_1 = test_graph.add_node(
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
      "file", label="Investigation node")
  node_2 = test_graph.add_node(
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41cc",
      "file", label="Investigation node")
  assert test_graph.add_links_if_match(node_1.node_id, node_2.node_id)
  assert test_graph.links[
      (node_1.node_id, node_2.node_id, "similar_files")]
  mocker.resetall()


def test_add_links_if_match_link_already_exists(mocker):
  """Test add links if match if link already exists."""
  mocker.patch.object(test_graph, "_fetch_node_information")
  node_1 = test_graph.add_node(
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
      "file", label="Investigation node")
  node_2 = test_graph.add_node(
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41bb",
      "file", label="Investigation node")
  test_graph.add_link(node_1.node_id, node_2.node_id, "compressed_parents")
  assert test_graph.add_links_if_match(node_1.node_id, node_2.node_id)
  assert test_graph.links[
      (node_1.node_id, node_2.node_id, "compressed_parents")]
  assert not test_graph.links.get(
      (node_1.node_id, node_2.node_id, "similar_files"))
  mocker.resetall()


def test_add_links_if_match_not_existing_node():
  """Test add links if match between not existing nodes."""
  with pytest.raises(vt_graph_api.errors.NodeNotFoundError,
                     match=r"Node 'dummy id 1' not found in nodes."):
    test_graph.add_links_if_match("dummy id 1", "dummy id 2")


def test_add_links_if_match_between_the_same_node():
  """Test add links if match between the same node."""
  dummy_id = "dummy id"
  with pytest.raises(
      vt_graph_api.errors.SameNodeError,
      match=r"It is no possible to add links between the same node; id: {gid}."
      .format(gid=dummy_id)
  ):
    test_graph.add_links_if_match(dummy_id, dummy_id, "compressed_parents")


def test_connect_with_graph_and_found(mocker):
  """Test connect node with graph resolving connections."""
  search_connection_response = [
      [
          (
              "b3b7d8a4daee86280c7e54b0ff3283afe3579480",
              "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
              "execution_parents",
              "file"
          ),
          (
              "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
              "nsis.sf.net",
              "embedded_domains",
              "domain"
          )
      ],
      [
          (
              "b3b7d8a4daee86280c7e54b0ff3283afe3579480",
              "www.openssl.org",
              "embedded_domains",
              "domain"
          )
      ]
  ]
  mocker.patch("vt_graph_api.VTGraph._search_connection",
               return_value=search_connection_response)
  mocker.spy(test_graph, "_search_connection")
  test_graph.add_node("b3b7d8a4daee86280c7e54b0ff3283afe3579480", "file", False)
  test_graph.add_node("nsis.sf.net", "domain", False)
  test_graph.add_node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file", False)
  test_graph.add_node("www.openssl.org", "domain", False)
  assert test_graph.connect_with_graph(
      "b3b7d8a4daee86280c7e54b0ff3283afe3579480",
      max_api_quotas=1000, max_depth=10)
  assert test_graph._search_connection.call_count == 1
  assert test_graph.links[
      (
          "b3b7d8a4daee86280c7e54b0ff3283afe3579480",
          "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
          "execution_parents"
      )
  ]
  assert test_graph.links[
      (
          "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
          "nsis.sf.net",
          "embedded_domains"
      )
  ]
  assert test_graph.links[
      (
          "b3b7d8a4daee86280c7e54b0ff3283afe3579480",
          "www.openssl.org",
          "embedded_domains"
      )
  ]
  mocker.resetall()


def test_connect_with_graph_and_not_found(mocker):
  """Test connect node with graph resolving connections."""
  search_connection_response = []
  mocker.patch("vt_graph_api.VTGraph._search_connection",
               return_value=search_connection_response)
  mocker.spy(test_graph, "_search_connection")
  test_graph.add_node("98374253453454352345fdgdsfg3grgh", "file", False)
  assert not test_graph.connect_with_graph(
      "98374253453454352345fdgdsfg3grgh",
      max_api_quotas=1000, max_depth=10)
  assert test_graph._search_connection.call_count == 1
  mocker.resetall()
