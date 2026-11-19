#!/bin/bash
# nginx single process (master_process off, sidesteps FIOASYNC) serving static files and proxying to a second server block; curl clients; graceful QUIT.
# programs: conda-nginx
set -euo pipefail; shopt -s inherit_errexit
B=$PROGS/conda-nginx/1.31.8
mkdir -p www logs tmp; seq 1 50000 > www/data.txt; echo hello > www/index.html
cat > nginx.conf <<C
worker_processes 2;
master_process off;
pid $PWD/nginx.pid;
error_log $PWD/logs/error.log;
events { worker_connections 64; }
http {
  access_log $PWD/logs/access.log;
  client_body_temp_path $PWD/tmp; proxy_temp_path $PWD/tmp; fastcgi_temp_path $PWD/tmp; uwsgi_temp_path $PWD/tmp; scgi_temp_path $PWD/tmp;
  server { listen 127.0.0.1:41091; root $PWD/www; }
  server { listen 127.0.0.1:41092; location / { proxy_pass http://127.0.0.1:41091; } }
}
C
$B/bin/nginx -p $PWD -c $PWD/nginx.conf -g 'daemon off;' & pid=$!
for i in $(seq 1 200); do curl -sf -o /dev/null http://127.0.0.1:41092/ && break; sleep 0.05; done
for i in $(seq 1 20); do curl -sf http://127.0.0.1:41092/data.txt | md5sum; done | uniq -c
curl -sf http://127.0.0.1:41091/index.html
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:41092/missing
kill -QUIT $pid; wait $pid; echo "nginx exit $?"; wc -l < logs/access.log
