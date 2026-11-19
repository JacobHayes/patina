#!/bin/bash
# busybox httpd serves a 1 MiB file; curl and wget fetch it (also a 404 and a keep-alive pair).
set -euo pipefail; shopt -s inherit_errexit
mkdir -p www; head -c 1048576 /dev/zero | tr '\0' 'a' > www/big; echo hi > www/small
busybox httpd -f -p 127.0.0.1:41080 -h www & pid=$!
for i in $(seq 1 100); do curl -sf -o /dev/null http://127.0.0.1:41080/small && break; sleep 0.05; done
curl -sf -o c.big http://127.0.0.1:41080/big
wget -q -O w.big http://127.0.0.1:41080/big
curl -sf http://127.0.0.1:41080/small http://127.0.0.1:41080/small
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:41080/nope); echo "404 -> $code"
cmp c.big www/big; cmp w.big www/big
kill $pid; wait $pid || true
echo done
