# pylint: disable=superfluous-parens
"""Advanced VTGraph usage example."""


from vt_graph_api import VTGraph
from vt_graph_api.errors import NodeNotFoundError


API_KEY = ""  # Add your VT API Key here.


g = VTGraph(
    API_KEY,
    verbose=False,
    private=True,
    name="First private Graph API test",
    user_editors=["jinfantes"],
    group_viewers=["virustotal"]
)

# Adding first node. WannyCry hash
g.add_node(
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "file",
    label="Investigation node"
)

print("Expanding... this might take a few seconds.")
g.expand_n_level(
    level=1,
    max_nodes_per_relationship=10,
    max_nodes=200
)

# Adding second node, Kill Switch domain
g.add_node(
    "www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
    "domain",
    label="Kill Switch",
    fetch_information=True
)

# Expanding the communicating files of the kill switch domain.
g.expand(
    "www.ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
    "communicating_files",
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
    g.delete_node(node)
  except NodeNotFoundError:
    pass  # Ignoring if the node does not exist in the graph.

g.save_graph()

print("Graph ID: %s" % g.graph_id)
