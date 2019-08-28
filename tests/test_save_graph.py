"""Test save graph on VT and get links."""


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


def test_save_graph(mocker):
  """Test save graph without errors."""
  request_data = {
      "data": {
          "id": "437502384758sdafasdfadsfas9873452938cgf"
      }
  }
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.post", return_value=m)
  mocker.patch.object(test_graph, "_add_editors")
  mocker.patch.object(test_graph, "_add_viewers")
  test_graph.save_graph()
  mocker.resetall()


def test_save_graph_collaborator_not_found(mocker):
  """Test save graph on VT with collaborators not found in VT."""
  with pytest.raises(vt_graph_api.errors.CollaboratorNotFoundError):
    mocker.patch.object(test_graph, "_send_graph_to_vt")
    test_graph.save_graph()
    mocker.resetall()


def test_save_graph_error(mocker):
  """Test save graph on VT with error."""
  with pytest.raises(vt_graph_api.errors.SaveGraphError):
    m = mocker.Mock(status_code=400, json=mocker.Mock(return_value={}))
    mocker.patch("requests.post", return_value=m)
    mocker.patch.object(test_graph, "_add_editors")
    mocker.patch.object(test_graph, "_add_viewers")
    test_graph.save_graph()
    mocker.resetall()


def test_get_link():
  """Test get VT graph link."""
  id_ = "dfadsfasd7fa9ds8f7asd9f87dsfasd6f6s8d76fa6sd87f6adsfsdfasd687"
  test_graph.graph_id = id_
  assert test_graph.get_ui_link() == "https://www.virustotal.com/graph/%s" % id_


def test_get_iframe():
  """Test get VT graph iframe."""
  id_ = "dfadsfasd7fa9ds8f7asd9f87dsfasd6f6s8d76fa6sd87f6adsfsdfasd687"
  test_graph.graph_id = id_
  assert test_graph.get_iframe_code() == (
      "<iframe src=\"https://www.virustotal.com/graph/embed/" +
      "{graph_id}\" width=\"800\" height=\"600\"></iframe>"
      .format(
          graph_id=id_
      )
  )
