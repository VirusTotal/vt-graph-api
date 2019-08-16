"""This module contains all custom exceptions that could be thrown by the methods
in this package.
"""


class NodeNotFound(Exception):
  
  def __init__(self, msg):
    """Constructor for NodeNotFound
    
    Args:
        msg (str): Human readable string describing the exception.
    """
    super(NodeNotFound, self).__init__(msg)


class CollaboratorNotFound(Exception):

  def __init__(self, msg):
    """Constructor for CollaboratorNotFound
    
    Args:
        msg (str): Human readable string describing the exception.
    """
    super(CollaboratorNotFound, self).__init__(msg)


class SaveGraphError(Exception):

  def __init__(self, msg):
    """Constructor for SaveGraphError
    
    Args:
        msg (str): Human readable string describing the exception.
    """
    super(SaveGraphError, self).__init__(msg)
