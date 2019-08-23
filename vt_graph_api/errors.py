"""This module contains all custom exceptions that could be thrown by the methods in this package."""


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
