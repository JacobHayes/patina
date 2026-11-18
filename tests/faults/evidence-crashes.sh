# Evidence (crash and restart): ack-log crash and restart over
# 200 seeds per model, the nofsync variant under process crashes over 100 seeds, and crash-point
# coverage over 500 seeds.
#@ tier=evidence budget=900 slots=8 arch=x86_64
here=$(dirname "$0")
ACK_SEEDS=${ACK_SEEDS:-200} T07_JOBS=8 bash -euo pipefail -O inherit_errexit "$here/07-acklog.sh"
PCRASH_SEEDS=${PCRASH_SEEDS:-100} T07_JOBS=8 bash -euo pipefail -O inherit_errexit "$here/08-process-crash.sh"
COV_SEEDS=${COV_SEEDS:-500} bash -euo pipefail -O inherit_errexit "$here/10-coverage.sh"
