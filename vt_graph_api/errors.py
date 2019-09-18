"""vt_graph_api.errors.

This modules provides all errors that could be thrown by
the methods in vt_graph_api package.
"""


class NodeNotFoundError(Exception):
  pass


class NodeNotSupportedTypeError(Exception):
  pass


class NodeNotSupportedExpansionError(Exception):
  pass


class CollaboratorNotFoundError(Exception):
  pass


class SaveGraphError(Exception):
  pass


class SameNodeError(Exception):
  pass


class MaximumConnectionRetriesError(Exception):
  pass


class WrongJSONError(Exception):
  pass


class LoadError(Exception):
  pass
