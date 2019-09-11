"""vt_graph_api.load.maltego.legend.

This modules provides attributes that will be used in maltego loaders for
convert information from maltego to VTGraph.
"""


MALTEGO_TYPES_CONVERSOR = {
    "maltego.DNSName": "domain",
    "maltego.Domain": "domain",
    "maltego.IPv4Address": "ip_address",
    "maltego.MXRecord": "domain",
    "maltego.NSRecord": "domain",
    "maltego.Netblock": "ip_address",
    "maltego.Website": "domain",
    "maltego.URL": "url",
    "maltego.Hash": "file",
    "maltego.Document": "file",
    "maltego.Email": "email",
    "maltego.Person": "actor",
    "maltego.Organization": "department",
    "maltego.Company": "department",
    "maltego.Service": "service",
    "maltego.Port": "port"
}


MALTEGO_EDGE_CONVERSOR = {
    "maltego.link.manual-link": "manual",
    "": "",
}
