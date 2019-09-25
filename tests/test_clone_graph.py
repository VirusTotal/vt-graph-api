"""Test clone graph from VT."""


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


API_KEY = "DUMMY_API_KEY"
GRAPH_ID = "DUMMY_ID"


def test_clone_graph(mocker):
  """Test clone graph without errors."""
  side_effects = [
      GRAPH_RESPONSE_DATA,
      VIEWERS_RESPONSE_DATA,
      EDITORS_RESPONSE_DATA
  ]
  new_user_viewers = ["jinfantes"]
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  test_graph = vt_graph_api.graph.VTGraph.clone_graph(
      GRAPH_ID, API_KEY, user_viewers=new_user_viewers)
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
  assert not test_graph.group_editors
  assert not test_graph.user_editors
  assert not test_graph.group_viewers
  assert "alvarogf" not in test_graph.user_viewers
  assert "jinfantes" in test_graph.user_viewers
  mocker.resetall()
