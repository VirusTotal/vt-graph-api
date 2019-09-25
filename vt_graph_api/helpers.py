"""vt_graph_api.helpers.

This module provides some helper methods.
"""


def safe_get(dct, *keys, **kwargs):
  """Return the dict value for the given ordered keys.

  Args:
    dct (dict): the dictionary that will be consulted.
    *keys: positional arguments which contains the key path to the
      wanted value.
    **kwargs:
      default -> If any key is missing, default will be returned.

  Examples:
    >>> my_dict = {"a": {"b": {"c": "my_value"}}}
    >>> safe_get(my_dict, "a", "b", "c")
    'my_value'
    >>> safe_get(my_dict, "a", "z")
    >>> safe_get(my_dict, "a", "z", default="my_other_value")
    'my_other_value'
    >>> my_other_dict = {"a": ["first"]}
    >>> safe_get(my_other_dict, "a", 0)
    'first'
    >>> safe_get(my_other_dict, "a", 1)
    >>> safe_get(my_other_dict, "a", 1, default="second")
    'second'

  Returns:
    Any: the dictionary value for the given ordered keys.
  """
  default_value = kwargs.get("default")
  for key in keys:
    try:
      dct = dct[key]
    except (KeyError, IndexError):
      return default_value
  return dct
