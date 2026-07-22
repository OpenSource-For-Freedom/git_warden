#!/bin/bash
# From nvidia/aistore, which confirmed AUTO on the 2026-07-22 sweep via
# exfiltration:curl-post-data. The body is an inline JSON literal that creates a
# storage bucket against a Docker playground address. Nothing leaves the machine
# and no secret is involved. Every REST call in every repository has this shape.
set -e

curl -i -X POST -H 'Content-Type: application/json' -d '{"action": "create_bck"}' http://172.50.0.2:8080/v1/buckets/imagenet
curl -X PUT -d '{"replicas": 3}' http://aistore-proxy:8080/v1/cluster/config
curl -s -X POST --data '{"query":"status"}' http://10.0.0.5:9000/api/v1/health
