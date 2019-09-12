# VirusTotal Graph API

VirusTotal Graph API allows you programatically interact with VirusTotal dataset. See also [vt_graph_data_importers](https://github.com/virustotal/vt-graph-data-importers) module in order to generate graphs from other tools.

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

# Documentation

https://developers.virustotal.com/v3.0/docs/api-documentation


# Tutorials

https://developers.virustotal.com/v3.0/docs/simple-tutorials  
https://developers.virustotal.com/v3.0/docs/advanced-tutorials

# Test it!

Use tox to test:

```
>>> tox
```

# Changelog

### V1.0.0
---
- Added autosearch algorithm to find links between graph's nodes.
- Added regular expression to detect node types.
- Accept **MD5** and **SHA1** as valid ID for nodes with **file type**.
- Added **VTIntelligence** search for nodes without any information.
- Accept custom node types.
- Now it is possible to add a list of nodes to graph concurrently.
- Added load graph from **virustotal graph id**.
