"""Test load graph from VT."""


import pytest
import vt_graph_api.errors
import vt_graph_api.load


GRAPH_RESPONSE_DATA = {
    "data": {
        "attributes": {
            "comments_count": 0,
            "creation_date": 1567094335,
            "graph_data": {
                "description": "First Graph API test",
                "version": "api-1.0.0"
            },
            "last_modified_date": 1567094335,
            "links": [
                {
                    "connection_type": "contacted_ips",
                    "source":
                        "5504e04083d6146a67cb0d671d8ad5885315062c9ee" +
                        "08a62e40e264c2d5eab91",
                    "target":
                        "relationships_contacted_ips_5504e04083d6146" +
                        "a67cb0d671d8ad5885315062c9ee08a62e40e264c2d" +
                        "5eab91"
                },
                {
                    "connection_type": "contacted_ips",
                    "source":
                        "efa0b414a831cbf724d1c67808b7483dec22a981ae6" +
                        "70947793d114048f88057",
                    "target":
                        "relationships_contacted_ips_5504e04083d6146" +
                        "a67cb0d671d8ad5885315062c9ee08a62e40e264c2d" +
                        "5eab91"
                },
                {
                    "connection_type": "contacted_ips",
                    "source":
                        "720d6a4288fa43357151bdeb8dc9cdb7c27fd7db1b5" +
                        "f76345f5ff094d48ae5a0",
                    "target":
                        "relationships_contacted_ips_5504e04083d6146" +
                        "a67cb0d671d8ad5885315062c9ee08a62e40e264c2d" +
                        "5eab91"
                },
                {
                    "connection_type": "contacted_ips",
                    "source":
                        "b20ce00a6864225f05de6407fac80ddb83cd0aec00a" +
                        "da438c1e354cdd0d7d5df",
                    "target":
                        "relationships_contacted_ips_5504e04083d6146" +
                        "a67cb0d671d8ad5885315062c9ee08a62e40e264c2d" +
                        "5eab91"
                },
                {
                    "connection_type": "contacted_ips",
                    "source":
                        "5961861d2b9f50d05055814e6bfd1c6291b30719f8a" +
                        "4d02d4cf80c2e87753fa1",
                    "target":
                        "relationships_contacted_ips_5504e04083d6146" +
                        "a67cb0d671d8ad5885315062c9ee08a62e40e264c2d" +
                        "5eab91"
                },
                {
                    "connection_type": "contacted_ips",
                    "source":
                        "relationships_contacted_ips_5504e04083d6146" +
                        "a67cb0d671d8ad5885315062c9ee08a62e40e264c2d" +
                        "5eab91",
                    "target": "178.62.125.244"
                },
                {
                    "connection_type": "communicating_files",
                    "source": "178.62.125.244",
                    "target":
                        "relationships_communicating_files_178" +
                        "62125244"
                },
                {
                    "connection_type": "communicating_files",
                    "source":
                        "relationships_communicating_files_178" +
                        "62125244",
                    "target":
                        "e6ecb146f469d243945ad8a5451ba1129c5b190f7d5" +
                        "0c64580dbad4b8246f88e"
                }
            ],
            "nodes": [
                {
                    "entity_attributes": {
                        "has_detections": 45,
                        "type_tag": "docx"
                    },
                    "entity_id":
                        "5504e04083d6146a67cb0d671d8ad5885315062c9ee" +
                        "08a62e40e264c2d5eab91",
                    "index": 0,
                    "type": "file",
                    "x": 0,
                    "y": 0
                },
                {
                    "entity_attributes": {
                        "country": "GB"
                    },
                    "entity_id": "178.62.125.244",
                    "index": 1,
                    "type": "ip_address",
                    "x": 0,
                    "y": 0
                },
                {
                    "entity_id":
                        "relationships_contacted_ips_5504e04083d6146" +
                        "a67cb0d671d8ad5885315062c9ee08a62e40e264c2d" +
                        "5eab91",
                    "index": 2,
                    "type": "relationship",
                    "x": 0,
                    "y": 0
                },
                {
                    "entity_attributes": {
                        "has_detections": 51,
                        "type_tag": "peexe"
                    },
                    "entity_id":
                        "efa0b414a831cbf724d1c67808b7483dec22a981ae6" +
                        "70947793d114048f88057",
                    "index": 3,
                    "type": "file",
                    "x": 0,
                    "y": 0
                },
                {
                    "entity_attributes": {
                        "has_detections": 55,
                        "type_tag": "peexe"
                    },
                    "entity_id":
                        "720d6a4288fa43357151bdeb8dc9cdb7c27fd7db1b5" +
                        "f76345f5ff094d48ae5a0",
                    "index": 4,
                    "type": "file",
                    "x": 0,
                    "y": 0
                },
                {
                    "entity_attributes": {
                        "has_detections": 52,
                        "type_tag": "peexe"
                    },
                    "entity_id":
                        "b20ce00a6864225f05de6407fac80ddb83cd0aec00a" +
                        "da438c1e354cdd0d7d5df",
                    "index": 5,
                    "type": "file",
                    "x": 0,
                    "y": 0
                },
                {
                    "entity_attributes": {
                        "has_detections": 59,
                        "type_tag": "peexe"
                    },
                    "entity_id":
                        "5961861d2b9f50d05055814e6bfd1c6291b30719f8a" +
                        "4d02d4cf80c2e87753fa1",
                    "index": 6,
                    "type": "file",
                    "x": 0,
                    "y": 0
                },
                {
                    "entity_attributes": {
                        "has_detections": 57,
                        "type_tag": "peexe"
                    },
                    "entity_id":
                        "e6ecb146f469d243945ad8a5451ba1129c5b190f7d5" +
                        "0c64580dbad4b8246f88e",
                    "index": 7,
                    "type": "file",
                    "x": 0,
                    "y": 0
                },
                {
                    "entity_id":
                        "relationships_communicating_files_178621252" +
                        "44",
                    "index": 8,
                    "type": "relationship",
                    "x": 0,
                    "y": 0
                }
            ],
            "private": True,
            "views_count": 6
        }
    }
}

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


def test_load_from_id_with_match(mocker):
  """Test load from graph id without errors."""
  side_effects = [
      GRAPH_RESPONSE_DATA,
      VIEWERS_RESPONSE_DATA,
      EDITORS_RESPONSE_DATA
  ]
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  test_graph = vt_graph_api.load.from_vt_graph_id(API_KEY, GRAPH_ID)
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
  assert "virustotal" in test_graph.group_editors
  assert "alvarogf" in test_graph.user_viewers


def test_load_from_id_without_editors_and_viewers(mocker):
  """Test load from id without editors and viewers."""
  side_effects = [
      mocker.Mock(status_code=200,
                  json=mocker.Mock(return_value=GRAPH_RESPONSE_DATA)),
      mocker.Mock(status_code=404),
      mocker.Mock(status_code=404)
  ]
  mocker.patch("requests.get", side_effect=side_effects)
  test_graph = vt_graph_api.load.from_vt_graph_id(API_KEY, GRAPH_ID)
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


def test_load_from_id_with_fail_request(mocker):
  """Test load from id with errors."""
  with pytest.raises(
      vt_graph_api.errors.LoaderError,
      match=r"Error to find graph with id: DUMMY_ID. Response code: 400"
  ):
    mocker.patch("requests.get", return_value=mocker.Mock(status_code=400))
    vt_graph_api.load.from_vt_graph_id(API_KEY, GRAPH_ID)


def test_load_from_id_with_wrong_json(mocker):
  """Test load from id with error in JSON structure."""
  with pytest.raises(
      vt_graph_api.errors.LoaderError,
      match=r"JSON wrong structure"
  ):
    side_effects = [
        GRAPH_WRONG_RESPONSE_DATA,
        VIEWERS_RESPONSE_DATA,
        EDITORS_RESPONSE_DATA
    ]
    m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
    mocker.patch("requests.get", return_value=m)
    vt_graph_api.load.from_vt_graph_id(API_KEY, GRAPH_ID)
