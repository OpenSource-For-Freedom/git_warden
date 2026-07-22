# From n3mes1s/supply-stream, a supply-chain malware DETECTION corpus builder that
# confirmed AUTO on the 2026-07-22 sweep. Every string below is a search QUERY the
# tool runs to FIND malware in package archives. Matching them is the same mistake
# as reading a YARA ruleset as a payload.
QUERIES = [
    'type:gzip name:".tgz" content:"discord.com/api/webhooks/" content:"child_process"',
    'type:gzip name:".tgz" content:"api.telegram.org/bot" content:"child_process"',
    'type:gzip name:".tgz" content:".ssh/id_rsa" content:"http.request("',
    'type:zip name:".whl" content:"os.environ" content:"requests.post("',
]


def build(client):
    for q in QUERIES:
        yield from client.search(q)
