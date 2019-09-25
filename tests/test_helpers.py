"""Test vt_graph_api.helpers module."""


import vt_graph_api.helpers as helpers


def test_safe_get():
  """Test safe_get."""
  my_dict = {"a": {"b": {"c": "my_value"}}}
  assert helpers.safe_get(my_dict, "a", "b", "c") == "my_value"
  assert not helpers.safe_get(my_dict, "a", "z")
  assert (
      helpers.safe_get(my_dict, "a", "z", default="my_other_value") ==
      "my_other_value")

  my_other_dict = {"a": ["first"]}
  assert helpers.safe_get(my_other_dict, "a", 0) == "first"
  assert not helpers.safe_get(my_other_dict, "a", 1)
  assert helpers.safe_get(my_other_dict, "a", 1, default="second") == "second"
