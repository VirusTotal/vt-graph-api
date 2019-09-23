"""Test save graph on VT and get links."""


import pytest
import vt_graph_api
import vt_graph_api.errors


test_graph = vt_graph_api.VTGraph(
    "Dummy api key", verbose=False, private=False, name="Graph test",
    user_editors=["agfernandez"], group_viewers=["virustotal"])


def test_save_graph(mocker):
  """Test save graph without errors."""
  request_data = {
      "data": {
          "id": "437502384758sdafasdfadsfas9873452938cgf"
      }
  }
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.post", return_value=m)
  mocker.patch.object(test_graph, "_fetch_node_information")
  added_node_id_a = (
      "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
  added_node_id_b = (
      "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16")
  test_graph.add_node(added_node_id_a, "file", label="Investigation node")
  test_graph.add_node(added_node_id_b, "file", label="Investigation node 2")
  test_graph.add_link(added_node_id_a, added_node_id_b, "similar_files")
  mocker.patch.object(test_graph, "_push_editors")
  mocker.patch.object(test_graph, "_push_viewers")
  test_graph.save_graph()
  mocker.resetall()


def test_save_graph_collaborator_not_found(mocker):
  """Test save graph on VT with collaborators not found in VT."""
  with pytest.raises(vt_graph_api.errors.CollaboratorNotFoundError):
    mocker.patch.object(test_graph, "_push_graph_to_vt")
    test_graph.save_graph()
    mocker.resetall()


def test_save_graph_error(mocker):
  """Test save graph on VT with error."""
  with pytest.raises(vt_graph_api.errors.SaveGraphError):
    m = mocker.Mock(status_code=400, json=mocker.Mock(return_value={}))
    mocker.patch("requests.post", return_value=m)
    mocker.patch.object(test_graph, "_push_editors")
    mocker.patch.object(test_graph, "_push_viewers")
    test_graph.save_graph()
    mocker.resetall()


def test_get_link():
  """Test get VT graph link."""
  graph_id = "dfadsfasd7fa9ds8f7asd9f87dsfasd6f6s8d76fa6sd87f6adsfsdfasd687"
  test_graph.graph_id = graph_id
  assert (test_graph.get_ui_link() ==
          "https://www.virustotal.com/graph/%s" % graph_id)


def test_get_link_error():
  test_graph.graph_id = ""
  with pytest.raises(vt_graph_api.errors.SaveGraphError):
    test_graph.get_ui_link()


def test_get_iframe():
  """Test get VT graph iframe."""
  graph_id = "dfadsfasd7fa9ds8f7asd9f87dsfasd6f6s8d76fa6sd87f6adsfsdfasd687"
  test_graph.graph_id = graph_id
  assert test_graph.get_iframe_code() == (
      "<iframe src=\"https://www.virustotal.com/graph/embed/" +
      "{graph_id}\" width=\"800\" height=\"600\"></iframe>"
      .format(graph_id=graph_id))


def test_get_iframe_error():
  test_graph.graph_id = ""
  with pytest.raises(vt_graph_api.errors.SaveGraphError):
    test_graph.get_iframe_code()
