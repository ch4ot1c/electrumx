#!/bin/bash

# Make self-signed SSL cert and key
openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
openssl rsa -passin pass:x -in server.pass.key -out server.key
openssl req -new -key server.key -out server.csr -subj "/C=NL/CN=electrumx.zclassic.org"
openssl x509 -req -days 1825 -in server.csr -signkey server.key -out server.crt
rm server.pass.key
rm server.csr

# Update RPC username and password
sed -ie s/rpcuser=change-this/rpcuser=${RPCUSER}/ zclassic.conf
sed -ie s/rpcpassword=change-this/rpcpassword=${RPCPASS}/ zclassic.conf

mkdir -p ~/.zclassic/
cp zclassic.conf ~/.zclassic/
/home/zcluser/zclassic/src/zcashd -daemon

COIN=Zclassic DB_DIRECTORY=/home/zcluser/zcl_electrum_db DAEMON_URL=http://${RPCUSER}:${RPCPASS}@127.0.0.1:8232 HOST=0.0.0.0 SSL_PORT=50002 PEER_DISCOVERY=Off SSL_CERTFILE=/home/zcluser/server.crt SSL_KEYFILE=/home/zcluser/server.key BANDWIDTH_LIMIT=10000000 /home/zcluser/electrumx/electrumx_server.py
