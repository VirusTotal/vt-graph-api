[![Build Status](https://travis-ci.com/VirusTotal/vt-graph-api.svg?branch=master)](https://travis-ci.com/VirusTotal/vt-graph-api)

# VirusTotal Graph API

VirusTotal Graph API allows you programatically interact with VirusTotal dataset.

## Installing the API
Install VirusTotal Graph Python API.
```
git clone https://github.com/VirusTotal/vt_graph_api
cd vt_graph_api
pip install . --user
```

## Verifying the installation

```python
>>> import vt_graph_api
>>> vt_graph_api.__version__
X.X.X
```

## Documentation

For more information about how to use **vt_graph_api** visit the [documentation](https://virustotal.github.io/vt-graph-api/) page.

You may also want to take a look at some of our [example scripts](https://github.com/VirusTotal/vt-graph-api/tree/master/examples),
which besides doing useful work for you can be used as a guidance on how to use **vt_graph_api**.

In addition, you can find the documentation for the VirusTotal Graph REST API at the [API reference](https://developers.virustotal.com/v3.0/reference#graphs)

# Test it!

Use tox to test:

```
>>> tox
```

# Changelog

### V1.1.2
- Bug fixing.

### V1.1.1
- Bug fixing.
- Fixing documentation.

### V1.1.0
- Added download graph screenshot from VirusTotal.

### V1.0.1
- Fixing documentation.

### V1.0.0
---
- Added autosearch algorithm to find links between graph's nodes.
- Accept **MD5** and **SHA1** as valid ID for nodes with **file type**.
- Added **VTIntelligence** search for nodes without any information.
- Accept custom node types.
- Added load graph from VirusTotal.
- Added clone graph from VirusTotal.
