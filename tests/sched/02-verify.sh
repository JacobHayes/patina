# 2. patina verify --vary cpu,load identical (seed 1, 4 runs), each guest.
#@ tier=quick slots=1.5
. "$(dirname "$0")/lib.inc"
. "$(dirname "$0")/verify.inc"
verify_all 02-verify
