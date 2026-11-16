# 1. The SDK in C, Rust, Go and Python, one guest each running the same script
#    (tests/guests/sdk): natively every call is inert (one failed system call, by hand with
#    strace -c); under Patina a failed `always` ends the run `violation` with `label: detail`
#    and the trap in the log, a declared site never reached is in the table with
#    `evaluated: 0`, and the four site tables and fault-point decisions are equal.
#@ tier=quick budget=30
set -eu
exec python3 -I "$(dirname "$0")/lib/languages.py"
