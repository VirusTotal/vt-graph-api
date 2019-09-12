"""vt_graph_api.load.maltego.legend.

This modules provides attributes that will be used in maltego loaders for
convert information from maltego to VTGraph.
"""


MALTEGO_TYPES_REFERENCE = {
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
    "maltego.Person": "victim",
    "maltego.Organization": "department",
    "maltego.Company": "department",
    "maltego.Service": "service",
    "maltego.Port": "port"
}


MALTEGO_EDGE_REFERENCE = {
    "maltego.DNSName": {
        "To DNS Name [Enumerate hostname numerically]": "subdomains",
        "To Domains [DNS]": "subdomains",
        "To IP Address [DNS]": "resolutions",
        "To Web site [Query ports]": "subdomains"
    },
    "maltego.Domain": {
        "To DNS Name (interesting) [Robtex]": "subdomains",
        "To DNS Name - MX (mail server)": "subdomains",
        "To DNS Name - NS (name server)": "subdomains",
        "To DNS Name - SOA (Start of Authority)": "manual",
        "To DNS Name [Attempt zone transfer]": "subdomains",
        "To DNS Name [Find common DNS names]": "subdomains",
        "To DNS Name [Robtex]": "subdomains",
        "To DNS Name [Using Name Schema dictionary]": "subdomains",
        "To Domains [DNS]": "subdomains",
        "To Files (Interesting) [using Search Engine]": "communicating_files",
        "To Files (Office) [using Search Engine]": "referrer_files",
        "To Website [Quick lookup]": "siblings",
        "To Website mentioning domain [Bing]": "siblings",
        "To Website using domain [Bing]": "siblings",
        "[Threat Miner] Domain to IP (pDNS)": "resolutions",
        "[Threat Miner] Domain to URI": "urls",
        "[VTPUB] Detected URLs": "urls",
        "[VTPUB] Domain Resolutions": "resolutions",
        "[VTPUB] Downloaded Samples": "downloaded_files",
        "[VTPUB] Get Domain Siblings": "siblings",
        "[VTPUB] Get Subdomains": "subdomains",
        "[VTPUB] String References": "referrer_files"
    },
    "maltego.IPv4Address": {
        "To DNS Name [Reverse DNS]": "resolutions",
        "To DNS Name from passive DNS [Robtex]": "resolutions",
        "To Domain [Dataprovider]": "resolutions",
        "To Domain [Sharing this MX]": "resolutions",
        "To Domain [Sharing this NS]": "resolutions",
        "To Netblock [Blocks delegated to this IP as NS]": "resolutions",
        "To Netblock [Using natural boundaries]k": "resolutions",
        "To Netblock [Using routing info]": "resolutions",
        "To Netblock [Using whois info]": "resolutions",
        "To Website [Dataprovider.com]": "resolutions",
        "To Website mentioning IP [Bing]": "resolutions",
        "To Website using IP: [Bing]": "resolutions",
        "[DNSDB] To DNSNames with this": "resolutions",
        "[Threat Miner] IP to Domain (pDNS)": "resolutions",
        "[Threat Miner] IP to Samples": "downloaded_files",
        "[Threat Miner] IP to URI": "urls",
        "[VTPUB] Communicating Samples": "communicating_files",
        "[VTPUB] Detected URLs": "urls",
        "[VTPUB] Downloaded Samples": "downloaded_files",
        "[VTPUB] IP Resolutions": "resolutions",
        "[VTPUB] String References": "referrer_files",
    },
    "maltego.MXRecord": {
        "To Domains [Sharing this MX]": "subdomains",
    },
    "maltego.NSRecord": {
        "To Domains [Sharing this NS]": "subdomains",
        "To Netblock [Blocks delegated to this NS]": "resolutions"
    },
    "maltego.Netblock": {
        "To DNS Names in netblock [Reverse DNS]": "resolutions",
        "To IP addresses [Found in Netblock]": "resolutions",
        "To Netblocks [Cuts Netblock into smaller ones]": "",
        "To Wikipedia Edits": "resolutions",
        "[DNSDB] To DNSNames with this value": "resolutions"
    },
    "maltego.Website": {
        "Mirror: External links found": "urls",
        "To Domain [Dataprovider.com]": "subdomains",
        "To IP [Dataprovider.com]": "resolutions",
        "To IP's (reverse) [Dataprovider.com]": "resolutions",
        "To Incoming Links [Dataprovider.com]": "urls",
        "To Similar HTML [Dataprovider.com]": "siblings",
        "To Subdomains [Dataprovider.com]": "subdomains",
        "To URLs [show Search Engine results]": "urls",
        "To Website [Replace with thumbnail]": "subdomains"
    },
    "maltego.URL": {
        "To Images [Found on webpage]": "contacted_domains",
        "To Website [Convert]": "contacted_domains",
        "To Website [Links on this web page]": "contacted_domains",
        "URL to Title": "contacted_domains",
        "[DNSDB] To DNSNames from this URL": "contacted_domains",
    },
    "maltego.Hash": {
        "[Threat Miner] Malware to Domains": "embedded_domains",
        "[Threat Miner] Malware to Filename": "similar_files",
        "[Threat Miner] Malware to Hosts": "embedded_ips",
        "[Threat Miner] Malware to URL": "embedded_urls",
        "vtprivCheckHash": "Phrase",

    },
    "maltego.Document": {
        "To URL [Show SE results]": "embedded_urls",
        "[Threat Miner] APTNotes To Domains": "embedded_domains",
        "[Threat Miner] APTNotes To IP": "embedded_ips",
        "[Threat Miner] APTNotes To Samples": "similar_files",
    }
}
