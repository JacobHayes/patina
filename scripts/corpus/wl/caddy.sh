#!/bin/bash
# Caddy: a file server and a reverse proxy in front of it (Caddyfile), curl clients, graceful stop.
# programs: caddy/2.11.4
set -euo pipefail; shopt -s inherit_errexit
mkdir -p www; seq 1 50000 > www/data.txt; echo hello > www/index.html
cat > Caddyfile <<CF
{
	admin 127.0.0.1:41089
	auto_https off
	storage file_system $PWD/caddy-data
}
:41086 {
	root * $PWD/www
	file_server
}
:41087 {
	reverse_proxy 127.0.0.1:41086
}
CF
XDG_DATA_HOME=$PWD XDG_CONFIG_HOME=$PWD $PROGS/caddy/2.11.4/caddy run --config Caddyfile --adapter caddyfile >caddy.log 2>&1 & pid=$!
for i in $(seq 1 200); do curl -sf -o /dev/null http://127.0.0.1:41087/ && break; sleep 0.05; done
for i in $(seq 1 20); do curl -sf http://127.0.0.1:41087/data.txt | md5sum; done | uniq -c
curl -sf http://127.0.0.1:41086/index.html
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:41087/missing
$PROGS/caddy/2.11.4/caddy stop --address 127.0.0.1:41089
wait $pid; echo "caddy exit $?"
