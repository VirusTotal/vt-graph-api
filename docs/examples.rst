**************
Examples
**************

Basic Graph
==========================

.. code-block:: python

    """Basic VTGraph usage example."""


    from vt_graph_api import VTGraph


    API_KEY = ""  # Insert your VT API here.


    # Creates the graph.
    graph = VTGraph(API_KEY, verbose=True, private=True, name="First Graph")

    # Adds the node.
    graph.add_node(
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "file", label="Investigation node")

    # Expands the graph 1 level.
    graph.expand_n_level(level=1, max_nodes_per_relationship=5, max_nodes=100)

    # Saves the graph
    graph.save_graph()

    # Get the graph id
    print("Graph Id: %s" % graph.graph_id)

    # Visualizing the Graph
    print(graph.get_ui_link())  # Open the url in the browser


Advanced Graph
==========================

.. code-block:: python

    """Advanced VTGraph usage example."""


    from vt_graph_api import VTGraph
    from vt_graph_api.errors import NodeNotFoundError


    API_KEY = ""  # Add your VT API Key here.


    graph = VTGraph(
        API_KEY, verbose=False, private=True, name="First Graph",
        user_editors=["jinfantes"], group_viewers=["virustotal"])

    # Adding first node. WannyCry hash
    graph.add_node(
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "file", label="Investigation node")

    print("Expanding... this might take a few seconds.")
    graph.expand_n_level(level=1, max_nodes_per_relationship=10, max_nodes=200)

    # Adding second node, Kill Switch domain
    graph.add_node(
        "www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "domain",
        label="Kill Switch", fetch_information=True
    )

    # Expanding the communicating files of the kill switch domain.
    graph.expand(
        "www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com", "communicating_files",
        max_nodes_per_relationship=20
    )

    # Deleting nodes
    nodes_to_delete = [
        "52.57.88.48",
        "54.153.0.145",
        "52.170.89.193",
        "184.168.221.43",
        "144.217.254.91",
        "144.217.254.3",
        "98.143.148.47",
        "104.41.151.54",
        "144.217.74.156",
        "fb0b6044347e972e21b6c376e37e1115dab494a2c6b9fb28b92b1e45b45d0ebc",
        "428f22a9afd2797ede7c0583d34a052c32693cbb55f567a60298587b6e675c6f",
        "b43b234012b8233b3df6adb7c0a3b2b13cc2354dd6de27e092873bf58af2693c",
        "85ce324b8f78021ecfc9b811c748f19b82e61bb093ff64f2eab457f9ef19b186",
        "3f3a9dde96ec4107f67b0559b4e95f5f1bca1ec6cb204bfe5fea0230845e8301",
        "2c2d8bc91564050cf073745f1b117f4ffdd6470e87166abdfcd10ecdff040a2e",
        "a93ee7ea13238bd038bcbec635f39619db566145498fe6e0ea60e6e76d614bd3",
        "7a828afd2abf153d840938090d498072b7e507c7021e4cdd8c6baf727cafc545",
        "a897345b68191fd36f8cefb52e6a77acb2367432abb648b9ae0a9d708406de5b",
        "5c1f4f69c45cff9725d9969f9ffcf79d07bd0f624e06cfa5bcbacd2211046ed6"
    ]

    for node in nodes_to_delete:
      try:
        graph.delete_node(node)
      except NodeNotFoundError:
        pass  # Ignoring if the node does not exist in the graph.

    graph.save_graph()

    print("Graph ID: %s" % graph.graph_id)


Basic Graph Search
==========================

.. code-block:: python


    """VTGraph basic search usage example."""

    from vt_graph_api import VTGraph


    API_KEY = ""  # Insert your VT API here.


    # Creates the graph.
    graph = VTGraph(API_KEY, verbose=True, private=True, name="First Graph")

    # Add some nodes to graph.
    graph.add_node("b3b7d8a4daee86280c7e54b0ff3283afe3579480", "file", True)
    graph.add_node("nsis.sf.net", "domain", True)

    graph.add_links_if_match(
        "b3b7d8a4daee86280c7e54b0ff3283afe3579480", "nsis.sf.net",
        max_api_quotas=1000, max_depth=10)

    # Try to connect node with graph.
    graph.save_graph()

    # Get the graph id
    print("Graph Id: %s" % graph.graph_id)

    # Visualizing the Graph
    print(graph.get_ui_link())  # Open the url in the browser


Advanced Graph Search
==========================

.. code-block:: python

    """VTGraph advanced search usage example."""

    from vt_graph_api import VTGraph


    API_KEY = ""  # Insert your VT API here.


    # Creates the graph.
    graph = VTGraph(API_KEY, verbose=True, private=True, name="First Graph")

    # Add some nodes to graph.
    graph.add_node("b3b7d8a4daee86280c7e54b0ff3283afe3579480", "file", True)
    graph.add_node("nsis.sf.net", "domain", True)
    graph.add_node(
        "26c808a1eb3eaa7bb29ec2ab834559f06f2636b87d5f542223426d6f238ff906", "file")

    graph.add_node("www.openssl.org", "domain", True)

    # Try to connect node with graph.
    graph.connect_with_graph(
        "b3b7d8a4daee86280c7e54b0ff3283afe3579480", max_api_quotas=1000,
        max_depth=10)

    graph.save_graph()

    # Get the graph id
    print("Graph Id: %s" % graph.graph_id)

    # Visualizing the Graph
    print(graph.get_ui_link())  # Open the url in the browser

Load Graph
==========================

.. code-block:: python

    """VirusTotal Graph id load example."""


    import vt_graph_api


    API_KEY = ""  # Insert your VT API here.
    GRAPH_ID = ""  # Insert yout graph id here.


    # Retrieve the graph.
    graph = vt_graph_api.VTGraph.load_graph(GRAPH_ID, API_KEY)

    # modify your graph here

    # save it in VirusTotal.
    graph.save_graph()

    # Get the graph id
    print("Graph Id: %s" % graph.graph_id)

    # Visualizing the Graph
    print(graph.get_ui_link())  # Open the url in the browser
