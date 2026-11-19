#!/bin/bash
# PHP 8.5 built-in web server (2 workers) with a router script; 40 curl requests; SIGTERM.
# programs: conda-php
set -euo pipefail; shopt -s inherit_errexit
PHP_CLI_SERVER_WORKERS=2 $PROGS/conda-php/8.5.12/bin/php -n -d max_execution_time=0 -S 127.0.0.1:41098 $GUEST/php-router.php >php.log 2>&1 & pid=$!
for i in $(seq 1 200); do curl -sf -o /dev/null http://127.0.0.1:41098/ && break; sleep 0.05; done
for i in $(seq 1 40); do curl -sf -d "x$i" http://127.0.0.1:41098/r$((i%4)); echo; done | sort | uniq -c
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:41098/missing
$PROGS/conda-php/8.5.12/bin/php -n -r 'echo array_sum(range(1, 1000)), " ", PHP_VERSION_ID > 80000 ? "ok" : "old", "\n";'
kill -TERM $pid; wait $pid || true
