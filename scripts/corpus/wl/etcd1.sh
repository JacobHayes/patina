#!/bin/bash
# etcd single member (bbolt maps its default 10 GiB backend MAP_SHARED): put 50 keys, get, a watch in the background, compaction, snapshot save.
# programs: conda-etcd
set -euo pipefail; shopt -s inherit_errexit
B=$PROGS/conda-etcd/3.7.3/bin
$B/etcd --name s --data-dir $PWD/s --listen-client-urls http://127.0.0.1:41120 --advertise-client-urls http://127.0.0.1:41120 --listen-peer-urls http://127.0.0.1:41121 --log-level error >s.log 2>&1 & pid=$!
E="$B/etcdctl --endpoints=127.0.0.1:41120 --command-timeout=20s"
for i in $(seq 1 300); do grep -q 'serving client' s.log 2>/dev/null && break; $E endpoint health >/dev/null 2>&1 && break; sleep 0.1; done
$E watch w --prefix >watch.out 2>&1 & wp=$!
for i in $(seq 1 50); do $E put k$i v$i >/dev/null; done
$E put w1 x >/dev/null
$E get k1 k99 --print-value-only; $E get k --prefix --keys-only | grep -c k
rev=$($E get k1 -w json | grep -o '"revision":[0-9]*' | head -1 | cut -d: -f2); $E compact $rev >/dev/null
$E snapshot save snap.db >/dev/null 2>&1; ls snap.db
kill $wp; kill $pid; wait $pid || true
