#!/usr/bin/env bash
# checkout-retry-idempotency — explicit-context retry/idempotency simulator.
#
# Runs a tiny checkout simulator directly with cargo. The program under test is
# ordinary Rust checkout logic; the binary builds a Patina virtual world around
# it: virtual UDP client/service actors, fixed virtual link latency, a
# timeout-driven retry, and an invariant that one logical order is charged once.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: testbeds/checkout-retry-idempotency/run-sim.sh [--selftest]

Runs the passing idempotent checkout scenario. With --selftest, also runs the
planted buggy scenario and requires it to fail with CHECKOUT_IDEMPOTENCY_VIOLATION.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") mode=run ;;
  --selftest) mode=selftest ;;
  *) printf 'checkout-retry-idempotency: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
run_guest() {
  PATINA_SEED=7 PATINA_SCHEDULE_REPORT=0 cargo run --quiet --manifest-path "$here/Cargo.toml" -- "$@"
}

correct_out="$(run_guest correct)"
printf '%s\n' "$correct_out"
if ! grep -q '^CHECKOUT_IDEMPOTENCY_RESULT .*attempts=2 .*timeouts=1 .*duplicate_requests=1 .*charges=1 .*status=ok$' <<<"$correct_out"; then
  echo "checkout-retry-idempotency: FAIL correct scenario did not prove idempotent retry behavior" >&2
  exit 1
fi

if [[ "$mode" == selftest ]]; then
  set +e
  buggy_out="$(run_guest buggy 2>&1)"
  buggy_status=$?
  set -e
  printf '%s\n' "$buggy_out"
  if [[ "$buggy_status" -eq 0 ]]; then
    echo "checkout-retry-idempotency: FAIL planted bug unexpectedly passed" >&2
    exit 1
  fi
  if ! grep -q '^CHECKOUT_IDEMPOTENCY_VIOLATION .*attempts=2 .*timeouts=1 .*duplicate_requests=1 .*charges=2 .*reason=retry_charged_twice$' <<<"$buggy_out"; then
    echo "checkout-retry-idempotency: FAIL planted bug did not emit the expected violation" >&2
    exit 1
  fi
  echo "CHECKOUT_IDEMPOTENCY_SELFTEST passed"
fi
