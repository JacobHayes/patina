#!/bin/bash
# Node.js: http server + keep-alive client, fetch, worker threads.
# programs: node/26.13.0
set -euo pipefail; shopt -s inherit_errexit
exec $PROGS/node/26.13.0/bin/node $GUEST/node-http.js
