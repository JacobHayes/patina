#!/bin/bash
# MinIO server on one directory; curl with SigV4 creates a bucket, puts and gets 20 objects, lists.
# programs: conda-minio-server
set -euo pipefail; shopt -s inherit_errexit
export MINIO_ROOT_USER=minioadmin MINIO_ROOT_PASSWORD=minioadmin MINIO_BROWSER=off
$PROGS/conda-minio-server/2025.10.15.17.29.55/bin/minio server --address 127.0.0.1:41094 --quiet $PWD/data >minio.log 2>&1 & pid=$!
c="curl -sf --aws-sigv4 aws:amz:us-east-1:s3 --user minioadmin:minioadmin"
for i in $(seq 1 300); do curl -sf -o /dev/null http://127.0.0.1:41094/minio/health/ready && break; sleep 0.1; done
$c -X PUT http://127.0.0.1:41094/bkt
seq 1 20000 > obj
for i in $(seq 1 20); do $c -T obj http://127.0.0.1:41094/bkt/o$i; done
for i in 1 20; do $c http://127.0.0.1:41094/bkt/o$i | md5sum; done
$c "http://127.0.0.1:41094/bkt?list-type=2" | grep -o '<Key>' | wc -l
kill -TERM $pid; wait $pid || echo "minio exit $?"
