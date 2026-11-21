#!/bin/bash
# etcd: a 3-member cluster on loopback; etcdctl put/get/txn, member list, a leader-kill and recovery read.
# programs: conda-etcd
# run: disk-mb = 1024
set -euo pipefail; shopt -s inherit_errexit
B=$PROGS/conda-etcd/3.7.3/bin
cl=n1=http://127.0.0.1:41101,n2=http://127.0.0.1:41102,n3=http://127.0.0.1:41103
pids=()
for i in 1 2 3; do
  $B/etcd --name n$i --data-dir $PWD/n$i --listen-peer-urls http://127.0.0.1:4110$i --initial-advertise-peer-urls http://127.0.0.1:4110$i     --listen-client-urls http://127.0.0.1:4111$i --advertise-client-urls http://127.0.0.1:4111$i --initial-cluster $cl --initial-cluster-state new --log-level error >n$i.log 2>&1 &
  pids+=($!)
done
E="$B/etcdctl --endpoints=127.0.0.1:41111,127.0.0.1:41112,127.0.0.1:41113 --command-timeout=20s"
for i in $(seq 1 300); do $E endpoint health >/dev/null 2>&1 && break; sleep 0.1; done
for i in $(seq 1 30); do $E put k$i v$i >/dev/null; done
$E get k17 --print-value-only
$E member list | wc -l
kill ${pids[0]}; wait ${pids[0]} || true
$E --endpoints=127.0.0.1:41112,127.0.0.1:41113 put after kill >/dev/null; $E --endpoints=127.0.0.1:41112 get after --print-value-only
kill ${pids[1]} ${pids[2]}; wait || true
