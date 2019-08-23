# pylint: disable=protected-access
"""Test private VTGraph methods."""


import vt_graph_api


test_graph = vt_graph_api.VTGraph(
    "Dummy api key",
    verbose=False,
    private=False,
    name="Graph test",
    user_editors=["jinfantes"],
    group_viewers=["virustotal"]
)


def test_search_connection_first_level(mocker):
  """Test search connection and found it in the first level."""
  request_data = {
      "data": [
          {
              "attributes": {},
              "id":
                  "7c11c7ccd384fd9f377da499fc0" +
                  "59fa08fdc33a1bb870b5bc3812d24dd421a16",
              "type": "file"
          }
      ]
  }
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file"
  )
  node_b = vt_graph_api.Node(
      "7c11c7ccd384fd9f377da499fc059fa08fdc33a1bb870b5bc3812d24dd421a16",
      "file"
  )
  m = mocker.Mock(status_code=200, json=mocker.Mock(return_value=request_data))
  mocker.patch("requests.get", return_value=m)
  assert test_graph._search_connection(node_a, node_b, 1000, 5, 100)
  assert test_graph._get_expansion_nodes.call_count == len(
      node_a.expansions_available
  )
  assert test_graph._parallel_expansion.call_count == 1
  mocker.resetall()


def test_search_connection_second_level(mocker):
  """Test search connection and found it in the second level."""
  request_response_first_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id":
                      "7c11c7ccd384fd9f377da499fc059fa" +
                      "08fdc33a1bb870b5bc3812d24dd421a16",
                  "type": "file"
              }
          ]
      }
  ]
  request_response_second_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": "nsis.sf.net",
                  "type": "domain"
              }
          ]
      },
  ]
  side_effects = list(request_response_first_level * 17)
  side_effects += request_response_second_level*289
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file"
  )
  node_b = vt_graph_api.Node(
      "nsis.sf.net",
      "domain"
  )
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  total_file_expansions = len(
      node_a.expansions_available
  )
  total_nodes_first_level = total_file_expansions
  assert test_graph._search_connection(node_a, node_b, 1000, 5, 100)
  assert test_graph._get_expansion_nodes.call_count <= (
      total_file_expansions +
      total_file_expansions * total_nodes_first_level
  )
  assert test_graph._parallel_expansion.call_count <= (
      1 +
      total_nodes_first_level
  )
  mocker.resetall()


def test_search_connection_third_level(mocker):
  """Test search connection and found it in the third level."""
  request_response_first_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id":
                      "7c11c7ccd384fd9f377da499fc059fa" +
                      "08fdc33a1bb870b5bc3812d24dd421a16",
                  "type": "file"
              }
          ]
      }
  ]
  request_response_second_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": "nsis.sf.net",
                  "type": "domain"
              }
          ]
      },
  ]
  request_response_third_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id":
                      "660903b139d5c7ec80af124e93320" +
                      "c18895de32135450d4acd14096e6c0dd2ef",
                  "type": "file"
              }
          ]
      },
  ]
  side_effects = list(request_response_first_level * 17)
  side_effects += request_response_second_level * 289
  side_effects += request_response_third_level*2023
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file"
  )
  node_b = vt_graph_api.Node(
      "660903b139d5c7ec80af124e93320c18895de32135450d4acd14096e6c0dd2ef",
      "file"
  )
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  total_file_expansions = len(
      node_a.expansions_available
  )
  total_nodes_first_level = total_file_expansions
  total_domain_expansions = len(
      vt_graph_api.Node.NODE_EXPANSIONS.get("domain")
  )
  total_nodes_second_level = total_nodes_first_level * total_file_expansions
  assert test_graph._search_connection(node_a, node_b, 3000, 5, 1000)
  assert test_graph._get_expansion_nodes.call_count <= (
      total_file_expansions +
      total_file_expansions * total_nodes_first_level +
      total_domain_expansions * total_nodes_second_level
  )
  assert test_graph._parallel_expansion.call_count <= (
      1 +
      total_nodes_first_level +
      total_nodes_second_level
  )
  mocker.resetall()


def test_search_connection_not_found_and_consumes_max_api_quotas(mocker):
  """Test search connection and found it in the third level."""
  request_response_first_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id":
                      "7c11c7ccd384fd9f377da499fc059fa" +
                      "08fdc33a1bb870b5bc3812d24dd421a16",
                  "type": "file"
              }
          ]
      }
  ]
  request_response_second_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id": "nsis.sf.net",
                  "type": "domain"
              }
          ]
      },
  ]
  request_response_third_level = [
      {
          "data": [
              {
                  "attributes": {},
                  "id":
                      "660903b139d5c7ec80af124e93320" +
                      "c18895de32135450d4acd14096e6c0dd2ef",
                  "type": "file"
              }
          ]
      },
  ]
  side_effects = list(request_response_first_level * 17)
  side_effects += request_response_second_level * 289
  side_effects += request_response_third_level*2023
  node_a = vt_graph_api.Node(
      "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906",
      "file"
  )
  node_b = vt_graph_api.Node(
      "660903b139d5c7ec80af124e93320c18895de32135450d4acd14096e6c0dd2ef",
      "file"
  )
  m = mocker.Mock(status_code=200, json=mocker.Mock(side_effect=side_effects))
  mocker.patch("requests.get", return_value=m)
  mocker.spy(test_graph, "_get_expansion_nodes")
  mocker.spy(test_graph, "_parallel_expansion")
  assert not test_graph._search_connection(node_a, node_b, 100, 5, 1000)
  assert test_graph._get_expansion_nodes.call_count <= 100
  mocker.resetall()
