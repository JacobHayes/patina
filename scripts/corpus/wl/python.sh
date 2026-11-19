#!/bin/bash
# CPython: asyncio server+clients, multiprocessing (fork, spawn, forkserver), threads, queues.
set -euo pipefail; shopt -s inherit_errexit
exec /usr/bin/python3 -I $GUEST/py-asyncio.py
