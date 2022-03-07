"""Test create collection from graph."""

import pytest
import vt_graph_api
import vt_graph_api.errors

test_graph = vt_graph_api.VTGraph(
    "Dummy api key", verbose=False, private=False, name="Graph test",
    user_editors=["agfernandez"], group_viewers=["virustotal"])


def test_create_collection(mocker):
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value={
      'data': {'id': 'new_collection'}
  }))
  mocker.patch("requests.post", return_value=m)
  test_graph.add_node("virustotal.com", "domain")
  collection_url = test_graph.create_collection()
  assert collection_url == "https://www.virustotal.com/gui/collection/new_collection"


def test_create_collection_fails(mocker):
  m = mocker.Mock(status_code=400, json=mocker.Mock({}))
  mocker.patch("requests.post", return_value=m)
  test_graph.add_node("virustotal.com", "domain")

  with pytest.raises(vt_graph_api.errors.CreateCollectionError):
    test_graph.create_collection()
