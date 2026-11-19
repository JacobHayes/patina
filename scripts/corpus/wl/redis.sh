#!/bin/bash
# Redis 8: server with AOF (everysec) and RDB; redis-cli SET/GET/LPUSH, redis-benchmark (8 clients, 2000 requests), BGSAVE (fork), SHUTDOWN.
# programs: conda-redis-server
set -euo pipefail; shopt -s inherit_errexit
B=$PROGS/conda-redis-server/8.10.3/bin
$B/redis-server --port 41090 --bind 127.0.0.1 --dir $PWD --appendonly yes --save 60 1 --daemonize no --logfile $PWD/redis.log & pid=$!
for i in $(seq 1 400); do grep -q 'Ready to accept' redis.log 2>/dev/null && break; sleep 0.05; done
for i in $(seq 1 50); do echo "SET k$i v$i"; echo "LPUSH l $i"; done | $B/redis-cli -p 41090 >/dev/null
$B/redis-cli -p 41090 GET k42; $B/redis-cli -p 41090 LLEN l
$B/redis-benchmark -p 41090 -q -n 2000 -c 8 -t set,get,incr,lpush >bench.txt; wc -l <bench.txt
$B/redis-cli -p 41090 BGSAVE; for i in $(seq 1 100); do $B/redis-cli -p 41090 INFO persistence | grep -q 'rdb_bgsave_in_progress:0' && break; sleep 0.05; done
$B/redis-cli -p 41090 DBSIZE
$B/redis-cli -p 41090 SHUTDOWN SAVE || true; wait $pid || true
ls dump.rdb appendonlydir >/dev/null && echo persisted
