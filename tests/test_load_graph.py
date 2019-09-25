"""Test load graph from VT."""


import json
import os
import pytest
import vt_graph_api.errors
import vt_graph_api.graph


with (
    open(os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "resources/virustotal_graph_id.json"))) as fp:
  GRAPH_RESPONSE_DATA = json.load(fp)

VIEWERS_RESPONSE_DATA = {
    "data": [
        {
            "id": "alvarogf",
            "type": "user"
        }
    ]
}

EDITORS_RESPONSE_DATA = {
    "data": [
        {
            "id": "virustotal",
            "type": "group"
        }
    ]
}

GRAPH_WRONG_RESPONSE_DATA = {
    "dummy": "dummy_value"
}


API_KEY = "DUMMY_API_KEY"
GRAPH_ID = "DUMMY_ID"


def test_load_graph_with_match(mocker):
  """Test load from graph id without errors."""
  side_effects = [
      GRAPH_RESPONSE_DATA,
      VIEWERS_RESPONSE_DATA,
      EDITORS_RESPONSE_DATA
  ]
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  test_graph = vt_graph_api.graph.VTGraph.load_graph(GRAPH_ID, API_KEY)
  nodes = [
      "5504e04083d6146a67cb0d671d8ad5885315062c9ee08a62e40e264c2d5eab91",
      "178.62.125.244",
      "efa0b414a831cbf724d1c67808b7483dec22a981ae670947793d114048f88057",
      "720d6a4288fa43357151bdeb8dc9cdb7c27fd7db1b5f76345f5ff094d48ae5a0",
      "b20ce00a6864225f05de6407fac80ddb83cd0aec00ada438c1e354cdd0d7d5df",
      "5961861d2b9f50d05055814e6bfd1c6291b30719f8a4d02d4cf80c2e87753fa1",
      "e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e",
      "e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f885"
  ]
  links = [
      (
          "5504e04083d6146a67cb0d671d8ad5885315062c9ee08a62e40e264c2d5eab91",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "efa0b414a831cbf724d1c67808b7483dec22a981ae670947793d114048f88057",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "720d6a4288fa43357151bdeb8dc9cdb7c27fd7db1b5f76345f5ff094d48ae5a0",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "b20ce00a6864225f05de6407fac80ddb83cd0aec00ada438c1e354cdd0d7d5df",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "5961861d2b9f50d05055814e6bfd1c6291b30719f8a4d02d4cf80c2e87753fa1",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "178.62.125.244",
          "e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e",
          "communicating_files",
      ),
      (
          "178.62.125.244",
          "e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f885",
          "communicating_files",
      )
  ]
  for node in nodes:
    assert test_graph.nodes[node]
  for source, target, connection_type in links:
    assert test_graph.links[(source, target, connection_type)]
  assert "virustotal" in test_graph.group_editors
  assert "alvarogf" in test_graph.user_viewers
  mocker.resetall()


def test_load_graph_without_editors_and_viewers(mocker):
  """Test load from id without editors and viewers."""
  side_effects = [
      mocker.Mock(status_code=200,
                  json=mocker.Mock(return_value=GRAPH_RESPONSE_DATA)),
      mocker.Mock(status_code=200, json=mocker.Mock(return_value={"data": []})),
      mocker.Mock(status_code=200, json=mocker.Mock(return_value={"data": []}))
  ]
  mocker.patch("requests.get", side_effect=side_effects)
  test_graph = vt_graph_api.graph.VTGraph.load_graph(GRAPH_ID, API_KEY)
  nodes = [
      "5504e04083d6146a67cb0d671d8ad5885315062c9ee08a62e40e264c2d5eab91",
      "178.62.125.244",
      "efa0b414a831cbf724d1c67808b7483dec22a981ae670947793d114048f88057",
      "720d6a4288fa43357151bdeb8dc9cdb7c27fd7db1b5f76345f5ff094d48ae5a0",
      "b20ce00a6864225f05de6407fac80ddb83cd0aec00ada438c1e354cdd0d7d5df",
      "5961861d2b9f50d05055814e6bfd1c6291b30719f8a4d02d4cf80c2e87753fa1",
      "e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e"
  ]
  links = [
      (
          "5504e04083d6146a67cb0d671d8ad5885315062c9ee08a62e40e264c2d5eab91",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "efa0b414a831cbf724d1c67808b7483dec22a981ae670947793d114048f88057",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "720d6a4288fa43357151bdeb8dc9cdb7c27fd7db1b5f76345f5ff094d48ae5a0",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "b20ce00a6864225f05de6407fac80ddb83cd0aec00ada438c1e354cdd0d7d5df",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "5961861d2b9f50d05055814e6bfd1c6291b30719f8a4d02d4cf80c2e87753fa1",
          "178.62.125.244",
          "contacted_ips",
      ),
      (
          "178.62.125.244",
          "e6ecb146f469d243945ad8a5451ba1129c5b190f7d50c64580dbad4b8246f88e",
          "communicating_files",
      )
  ]
  for node in nodes:
    assert test_graph.nodes[node]
  for source, target, connection_type in links:
    assert test_graph.links[(source, target, connection_type)]
  assert "virustotal" not in test_graph.group_editors
  assert "alvarogf" not in test_graph.user_viewers
  mocker.resetall()


def test_load_graph_with_fail_request(mocker):
  """Test load from id with errors."""
  with pytest.raises(
      vt_graph_api.errors.LoadError,
      match=r"Error to find graph with id: DUMMY_ID. Response code: 400."):
    mocker.patch("requests.get", return_value=mocker.Mock(status_code=400))
    vt_graph_api.graph.VTGraph.load_graph(GRAPH_ID, API_KEY)
  mocker.resetall()


def test_load_graph_wrong_json(mocker):
  """Test load from id with error in JSON structure."""
  with pytest.raises(
      vt_graph_api.errors.InvalidJSONError):
    side_effects = [
        GRAPH_WRONG_RESPONSE_DATA,
        VIEWERS_RESPONSE_DATA,
        EDITORS_RESPONSE_DATA
    ]
    m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
    mocker.patch("requests.get", return_value=m)
    vt_graph_api.graph.VTGraph.load_graph(GRAPH_ID, API_KEY)
  mocker.resetall()
