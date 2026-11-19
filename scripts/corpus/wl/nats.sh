#!/bin/bash
# NATS server (with JetStream on disk) and a raw-protocol python client.
# programs: conda-nats-server
set -euo pipefail; shopt -s inherit_errexit
$PROGS/conda-nats-server/2.15.3/bin/nats-server -a 127.0.0.1 -p 41093 -js -sd $PWD/js >nats.log 2>&1 & pid=$!
/usr/bin/python3 -I $GUEST/nats-client.py
kill -TERM $pid; wait $pid || echo "nats exit $?"
