"""Test VTGraph is_viewer and is_editor."""


import pytest
import vt_graph_api
import vt_graph_api.errors


VT_USER = "alvarogf"
GRAPH_ID = "Dummy Graph ID"
API_KEY = "Dummy Api Key"
API_RESPONSE = {
    "data": [
        {
            "id": "alvarogf",
            "type": "user"
        }
    ]
}


def test_is_viewer(mocker):
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=API_RESPONSE))
  mocker.patch("requests.get", return_value=m)
  assert vt_graph_api.VTGraph.is_viewer(VT_USER, GRAPH_ID, API_KEY)
  mocker.resetall()


def test_is_not_viewer(mocker):
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={"data": []}))
  mocker.patch("requests.get", return_value=m)
  assert not vt_graph_api.VTGraph.is_viewer(VT_USER, GRAPH_ID, API_KEY)
  mocker.resetall()


def test_viewer_load_error(mocker):
  mocker.patch("requests.get", return_value=mocker.Mock(status_code=401))
  with pytest.raises(vt_graph_api.errors.LoadError):
    vt_graph_api.VTGraph.is_viewer(VT_USER, GRAPH_ID, API_KEY)
  mocker.resetall()


def test_is_editor(mocker):
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=API_RESPONSE))
  mocker.patch("requests.get", return_value=m)
  assert vt_graph_api.VTGraph.is_editor(VT_USER, GRAPH_ID, API_KEY)
  mocker.resetall()


def test_is_not_editor(mocker):
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={"data": []}))
  mocker.patch("requests.get", return_value=m)
  assert not vt_graph_api.VTGraph.is_editor(VT_USER, GRAPH_ID, API_KEY)
  mocker.resetall()


def test_editor_load_error(mocker):
  mocker.patch("requests.get", return_value=mocker.Mock(status_code=401))
  with pytest.raises(vt_graph_api.errors.LoadError):
    vt_graph_api.VTGraph.is_editor(VT_USER, GRAPH_ID, API_KEY)
  mocker.resetall()
