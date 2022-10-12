#!/bin/sh

# Script to regenerate the server and client certificate

set -eux

cd "$(dirname "$0")"
rm -f ./*.pem ./*.csr
cfssl gencert -config=config.json -initca ca.json | cfssljson -bare ca
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=config.json -profile=server server.json | cfssljson -bare server
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=config.json -profile=client client.json | cfssljson -bare client
