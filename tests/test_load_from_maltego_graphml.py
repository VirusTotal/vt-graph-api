"""Test load graph from maltego graphml format."""


import os
import pytest
import vt_graph_api.errors
import vt_graph_api.load.maltego


API_KEY = "DUMMY_API_KEY"
FILENAME = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "resources/maltego_graph.graphml"
)

NOT_EXIST_FILENAME = "DUMMY_FILE"

FILENAME_WRONG_FORMAT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "resources/virustotal_graph_id.json"
)

FILENAME_GRAPHML_WITH_ERRORS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "resources/maltego_graph_errors.graphml"
)

def test_load_maltego_graph_ml_without_errors():
  """Test load maltego graphml file without errors."""
  nodes = [
      "www.paterva.com",
      "403b83200f44e90131f02b124fb3470efc76cf176c165e3c71b8611638f407e2",
      "f62018028b4dbd2fc9516e4086672bf4265e0b23132ecdcddacad389b837a965",
      "John Doe",
      "paterva.com",
      "443",
      "ns1.linode.com",
      "5057e192331eede43a96da474a8625ceac72a5dc2097b8b2b442b017fecc032b",
      "80:Apache",
      "74.207.243.85",
      "li85-85.members.linode.com",
      "finance.spartancash.co.ke",
      "mail.paterva.com",
      "Some Document",
      "af30fca836142d6a0b8672f1e8f53acf",
      "74.207.243.254",
      "74.207.243.255"
  ]
  links = [
      (
          "www.paterva.com",
          "403b83200f44e90131f02b124fb3470efc76cf176c165e3c71b8611638f407e2",
          "downloaded_files"
      ),
      (
          "www.paterva.com",
          "f62018028b4dbd2fc9516e4086672bf4265e0b23132ecdcddacad389b837a965",
          "downloaded_files"
      ),
      (
          "www.paterva.com",
          "5057e192331eede43a96da474a8625ceac72a5dc2097b8b2b442b017fecc032b",
          "downloaded_files"
      ),
      (
          "paterva.com", "John Doe", "manual"
      ),
      (
          "443", "ns1.linode.com", "manual"
      ),
      (
          "80:Apache", "443", "manual"
      ),
      (
          "74.207.243.85", "li85-85.members.linode.com", "resolutions"
      ),
      (
          "74.207.243.85", "finance.spartancash.co.ke", "resolutions"
      ),
      (
          "74.207.243.85", "paterva.com", "resolutions"
      ),
      (
          "74.207.243.85", "www.paterva.com", "resolutions"
      ),
      (
          "ns1.linode.com", "80:Apache", "manual"
      ),
      (
          "mail.paterva.com", "ns1.linode.com", "manual"
      ),
      (
          "443", "mail.paterva.com", "manual"
      ),
      (
          "443", "John Doe", "manual"
      ),
      (
          "74.207.243.85", "John Doe", "manual"
      ),
      (
          "paterva.com", "74.207.243.85", "manual"
      )
  ]
  test_graph = vt_graph_api.load.maltego.from_graphml(FILENAME, API_KEY, False)
  for node in nodes:
    assert test_graph.nodes[node]
  for source, target, connection_type in links:
    assert test_graph.links[(source, target, connection_type)]
  assert len(test_graph.nodes) == len(nodes)


def test_load_maltego_graph_ml_file_not_found():
  with pytest.raises(vt_graph_api.errors.LoaderError,
                     match=(
                         r"File: {filename} not found!"
                         .format(filename=NOT_EXIST_FILENAME)
                     )):
    vt_graph_api.load.maltego.from_graphml(
        NOT_EXIST_FILENAME,
        API_KEY,
        False
    )


def test_load_maltego_graph_ml_incorrect_format():
  with pytest.raises(vt_graph_api.errors.LoaderError,
                     match=("Invalid file format!")):
    vt_graph_api.load.maltego.from_graphml(
        FILENAME_WRONG_FORMAT,
        API_KEY,
        False
    )


def test_load_maltego_graph_ml_with_file_errors():
  with pytest.raises(vt_graph_api.errors.LoaderError,
                     match=(
                         "The graphml file does not have the correct structure."
                     )):
    vt_graph_api.load.maltego.from_graphml(
        FILENAME_GRAPHML_WITH_ERRORS,
        API_KEY,
        False
    )
