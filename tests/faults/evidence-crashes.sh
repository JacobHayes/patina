# Evidence (faults items 7, 8 and 10): ack-log crash and restart over
# 200 seeds per model, the nofsync variant under process crashes over 100 seeds, and crash-point
# coverage over 500 seeds.
#@ tier=evidence budget=900 slots=8
set -e
here=$(dirname "$0")
ACK_SEEDS=${ACK_SEEDS:-200} T07_JOBS=8 sh "$here/07-acklog.sh"
PCRASH_SEEDS=${PCRASH_SEEDS:-100} T07_JOBS=8 sh "$here/08-process-crash.sh"
COV_SEEDS=${COV_SEEDS:-500} sh "$here/10-coverage.sh"
