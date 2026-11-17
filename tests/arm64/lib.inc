# Shared helpers for the arm64 scripts (sourced, not run): those of tests/cli.
. "$(dirname "$0")/../cli/lib.inc"
# stop DIR: "OUTCOME STOP" of a run directory
stop() { echo "$(field "$1/result.json" outcome) $(field "$1/result.json" stop)"; }
