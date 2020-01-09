**************
Quickstart
**************

.. note::

  Please check `VirusTotal Graph overview <https://www.virustotal.com/gui/graph-overview>`_ before start.

Basic usage
==========================

Start by importing the **vt_graph_api** module:

.. code-block:: python

  >>> import vt_graph_api

Creates a new graph (replace **<apikey>** with your actual VirusTotal API key):

.. code-block:: python

  >>> graph = vt_graph_api.VTGraph("<apikey>", name="My Graph", private=False)

.. warning::

  **Private graphs** are only allowed for `premium users <https://www.virustotal.com/gui/graph-overview>`_.

Nodes
==========================

Nodes are the minimum unit of graph representation. There's some basic node types, and we have also the opportunity to represent our own custom node types, so we can specify any type such as "actor" or "email". The basic node types are the following:

  + file
  + domain
  + ip_address
  + url

The difference between basic nodes and custom nodes is that the first ones could be expanded using VirusTotal API.

Adding Node
-------------------

.. warning::

  Adding a file node with no sha256 hash, url node with raw URL instead of an VirusTotal URL identifier or unknown
  ID with **fetch_vt_enterprise** option, consumes API quota.

We can either add a basic node:

.. code-block:: python

  >>> graph.add_node("www.virustotal.com", "domain", label="mynode")

Or our own custom type:

.. code-block:: python

  >>> graph.add_node("badguy", "victim")")

We can also specify that we want to fetch information on VirusTotal, about the node we are adding by setting **fetch_information** to True:

.. code-block:: python

  >>> graph.add_node("www.virustotal.com", "domain", fetch_information=True)

You can improve the search using `VirusTotal Intelligence <https://www.virustotal.com/gui/intelligence-overview>`_ 
by setting **fetch_vt_enterprise** to True.

.. warning::

  **fetch_vt_enterprise** flag is only available for `premium users <https://www.virustotal.com/gui/intelligence-overview>`_.

If we want to add some nodes at the same time we can use **add_nodes**, this method
receive a node list which is a list of dictionaries with the following structure:

.. code-block:: python

  node_list = [
      ...
      {
        "node_id" = "www.virustotal.com",
        "node_type" = "domain",
        "label" = "mynode",   # This attribute is optional.
        "attributes" = "",  # This attribute is optional.
        "x_position" = "", # This attribute is optional.
        "y_position" = ""  # This attribute is optional.
      },
      ...
  ]

  >>> graph.add_nodes(node_list, fetch_information=True)

.. seealso::

  For advanced usage, please check :ref:`APIReference overview`.

.. warning::

  Setting **fetch_information** to True consumes API quota.

Deleting Node
-------------------

.. code-block:: python

  graph.delete_node("www.virustotal.com")

This method will raise **NodeNotFoundError** if the given node id does not belong to the graph.

.. note::

  This method also deletes every link which have relation with the deleted node.

Checking if node id belongs to graph
--------------------------------------

It is possible to check if graph has a node id using:

.. code-block:: python

  >>> graph.has_node("www.virustotal.com")
  False


Links
==========================

Link is a connection between two nodes which represents how and why they are connected:

.. note::

  If **connection_type** is supplied, a relationship node will be created in VirusTotal Graph UI. Althought there are many
  relationship types, we have also the opportunity to represent our own custom relationship. It is possible to create a 
  link without **connection_type** too.

.. seealso::

  Please see VirusTotal documentation in order to check all VirusTotal relationship types:

  + `File <https://developers.virustotal.com/v3/reference/#files-relationships>`_.
  + `URL <https://developers.virustotal.com/v3/reference/#urls-relationships>`_.
  + `Domain <https://developers.virustotal.com/v3/reference/#domains-relationships>`_.
  + `IP <https://developers.virustotal.com/v3/reference/#ip-relationships>`_.


Adding link
-------------------

We can add link between two nodes.

.. code-block:: python

  >>> graph.add_link("85ce324b8f78021ecfc9b811c748f19b82e61bb093ff64f2eab457f9ef19b186",
  >>>                "3f3a9dde96ec4107f67b0559b4e95f5f1bca1ec6cb204bfe5fea0230845e8301",
  >>>                connection_type="bundled_files")

.. note::

  This call may raise **NodeNotFoundError** if any of the given node ids not found in
  graph. It is also possible to raise **SameNodeError** if source and target nodes
  are the same.


.. _add_links_if_match:

Adding link using autoexploring
------------------------------------

It is possible to infer the path that connects two nodes by expanding the given source node.
A link will be created if a connection between them is found.

For example we want to link the node "my_hash_1" with the node "my_hash_2", but we have no
idea how they are connected/related. The algorithm will expand "my_hash_1" using all the
available relationships by querying the VirusTotal API. If the algorithm finds the path that
connects "my_hash_1" with "my_hash_2", a link will be created using the relationship type
that relates them.

.. code-block:: python

  >>> graph.add_links_if_match("source_id", "target_id")
  True

This method uses VirusTotal API to expand nodes in order to find the relationship. If the 
relationship has been found, then return True, otherwise False.

.. warning::

  This call may consumes a lot of API quota. If it is necessary set **max_api_quotas** and
  **max_depth** to ensure that this method does not consumes more quotas than we want.

Connecting node with whole graph
-----------------------------------

We can connect a node with our graph by using the same algorithm that :ref:`add links if match <add_links_if_match>` uses, with the difference that this time we will use all graph's nodes instead of just one. 

.. code-block:: python

  >>> graph.connect_with_graph("my node")
  True

.. warning::

  This call will call multiple times to the API. If it is necessary set **max_api_quotas** and
  **max_depth** to ensure that this method does not consumes more quotas than your limits.

Deleting link
-------------------

Yoy can either delete a single link:

.. code-block::

  >>> graph.delete_link("source_id", "target_id", "connection_type")

or delete all the links in which node is involved:

.. code-block::

  >>> graph.delete_links("source_id")

.. seealso::

  Please check the :ref:`APIReference overview` to take more information about the errors that could be
  raised by this methods.

Expansions
==========================

An expansion is the action to get related nodes to a node.

.. seealso::

  Please see VirusTotal documentation in order to check relationship types:

  + `File <https://developers.virustotal.com/v3/reference/#files-relationships>`_.
  + `URL <https://developers.virustotal.com/v3/reference/#urls-relationships>`_.
  + `Domain <https://developers.virustotal.com/v3/reference/#domains-relationships>`_.
  + `IP <https://developers.virustotal.com/v3/reference/#ip-relationships>`_.


Expanding node by a given expansion
----------------------------------------

There is file node with the hash **7ed0707be56fe3a7f5f2eb1747fdb929bbb9879e6c22b6825da67be5e93b6bd2** and we want to know the domains that the file has contacted with, so we can use VirusTotal API to get the connected domains by expanding the file node using **contacted_domains** as expansion type.

.. code-block:: python

  >>> graph.expand("7ed0707be56fe3a7f5f2eb1747fdb929bbb9879e6c22b6825da67be5e93b6bd2", "contacted_domains")

This method adds to the graph the contacted domains returned by VirusTotal API.

.. note::

  It is possible to specify the maximum number of nodes returned by the expansion, setting
  **max_nodes_per_relationship** parameter.

.. warning::

  This call consumes API quota as much as **max_nodes_per_relationship/max_nodes_per_query**.

.. note::

  max_nodes_per_query = 40, this is the maximum number of nodes that we can request to VirusTotal API per query.

.. seealso::
  
  Please check :ref:`APIReference overview` for more information.

Expanding node one level
-----------------------------

We can expand a node in all of his available expansions:

.. code-block:: python

  >>> graph.expand_one_level("7ed0707be56fe3a7f5f2eb1747fdb929bbb9879e6c22b6825da67be5e93b6bd2", max_nodes_per_relationship=10)

.. warning::

  This call consumes API quota as much as **the number of node's expansions * max_nodes_per_relationship/max_nodes_per_query**.

Expanding the whole graph
-----------------------------

Alternatively we can expand the whole graph all the levels that we want:

.. code-block:: python

  >>> graph.expand_n_level(level=2)


.. note::

  As the methods before, we can specify **max_nodes_per_relationship** and **max_nodes** to ensure that we will not take
  more nodes than necessary.

.. warning::

  This call consumes API quota as much as **the number of total expansion of each graph node * max_nodes_per_relationship/max_nodes_per_query**.

.. seealso::

  Please see :ref:`APIReference overview` for more information.

Save
=============

Once our graph is finished we can save it in VirusTotal:

.. code-block:: python

  >>> graph.save_graph()

.. note::

  At this point if the Graph is set public it will be searchable in VirusTotal UI.

Load
=============

We can recover a VirusTotal Graph if we have his **ID**:

.. code-block:: python

  >>> vt_graph_api.VTGraph.load_graph("<graphid>", "<apikey>")

We can retrieve graphs that we are viewer, editor or owner.

.. warning::

  We cannot modify and save the loaded graph if we have no editor permissions.

.. seealso:: Please see also **clone_graph** method.


Clone
=============

.. code-block:: python

  >>> vt_graph_api.VTGraph.clone_graph("<graphid>", "<apikey>")

.. warning::

  This method does not clone the original user/group viewers/editors. It is necessary to call **save_graph()** in order
  to save the cloned graph in VirusTotal.


.. seealso::

  Please check :ref:`APIReference overview` for advanced usage.

Utilities
=============

Check if someone is viewer
---------------------------

.. code-block:: python

  >>> vt_graph_api.is_viewer("<username>", "<graphid>", "<apikey>")
  False


Check if someone is editor
----------------------------

.. code-block:: python

  >>> vt_graph_api.is_viewer("<username>", "<graphid>", "<apikey>")
  False

Getting link
-----------------------

.. code-block:: python

  >>> vt_graph_api.get_ui_link()
  'https://www.virustotal.com/graph/{graph_id}'


Getting iframe
-----------------------

We can also get an **iframe link** in order to embed the graph in our website.

.. code-block:: python

  >>> vt_graph_api.get_iframe_code()
  '<iframe src="https://www.virustotal.com/graph/embed/<<graph_id>>" width="800" height="600"></iframe>'


Getting API quota consumed
------------------------------

We can get how many API quota we have consumed since the script started

.. code-block::

  >>> graph.get_api_calls()
  1257
