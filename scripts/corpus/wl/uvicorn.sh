#!/bin/bash
# uvicorn (2 workers) serving an ASGI app; a threaded http.client makes 100 keep-alive requests; SIGTERM stops it.
# programs: built/uvenv
set -euo pipefail; shopt -s inherit_errexit
V=$PROGS/built/uvenv
cd $GUEST
$V/bin/python -m uvicorn --workers 2 --host 127.0.0.1 --port 41084 --log-level warning uv-app:app & pid=$!
cd - >/dev/null
/usr/bin/python3 -I $GUEST/uv-client.py
kill -TERM $pid; wait $pid || echo "uvicorn exit $?"
