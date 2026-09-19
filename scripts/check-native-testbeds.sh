#!/usr/bin/env bash
# Native ecosystem gates with independent capability and execution receipts.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/testbeds/native}"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/patina-native-testbeds.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

usage() {
  printf '%s\n' 'usage: scripts/check-native-testbeds.sh [--selftest|--help]' \
    'Runs FIFO, rustix-default and cap-std-dirfd; requires SUD execution receipts on capable kernels.'
}

require_receipt() {
  local script=$1 expected=$2
  if ! "$script" >"$tmp/child.log" 2>&1; then
    cat "$tmp/child.log" >&2
    echo "FAIL: $script exited unsuccessfully" >&2
    return 1
  fi
  cat "$tmp/child.log"
  if [[ $(grep -Fxc "$expected" "$tmp/child.log" || true) != 1 ]]; then
    echo "FAIL: $script did not print exactly one receipt: $expected" >&2
    return 1
  fi
}

require_sud() {
  if [[ ${PATINA_REQUIRE_SUD:-0} == 1 && $1 != 1 ]]; then
    echo 'FAIL: PATINA_REQUIRE_SUD=1 but the host lacks syscall-user-dispatch' >&2
    return 1
  fi
}

selftest() {
  local stub="$tmp/child" receipt='RUSTIX_LEGS_RAN branch=sud legs=test'
  printf '#!/usr/bin/env bash\nprintf "rustix-default: SKIPPED 1 (false-negative probe)\\n"\n' >"$stub"
  chmod +x "$stub"
  if require_receipt "$stub" "$receipt" >"$tmp/false-negative.log" 2>&1; then
    echo 'FAIL: successful false-negative capability skip was accepted' >&2; return 1
  fi
  if ! grep -q 'did not print exactly one receipt' "$tmp/false-negative.log"; then
    echo 'FAIL: false-negative child failed without the expected receipt diagnostic' >&2
    cat "$tmp/false-negative.log" >&2
    return 1
  fi
  printf '#!/usr/bin/env bash\nprintf "%s\\n"\n' "$receipt" >"$stub"
  require_receipt "$stub" "$receipt" >/dev/null
  printf '#!/usr/bin/env bash\nprintf "%s\\n%s\\n"\n' "$receipt" "$receipt" >"$stub"
  if require_receipt "$stub" "$receipt" >/dev/null 2>&1; then
    echo 'FAIL: duplicate receipt accepted' >&2; return 1
  fi
  printf '#!/usr/bin/env bash\nprintf "%s\\n"\nexit 1\n' "$receipt" >"$stub"
  if require_receipt "$stub" "$receipt" >/dev/null 2>&1; then
    echo 'FAIL: failed script with receipt accepted' >&2; return 1
  fi
  if PATINA_REQUIRE_SUD=1 require_sud 0 >"$tmp/required.log" 2>&1; then
    echo 'FAIL: required SUD absence accepted' >&2; return 1
  fi
  if ! grep -q 'PATINA_REQUIRE_SUD=1' "$tmp/required.log"; then
    echo 'FAIL: required SUD absence lacked its diagnostic' >&2; return 1
  fi
  PATINA_REQUIRE_SUD=1 require_sud 1
  PATINA_REQUIRE_SUD=0 require_sud 0
  echo 'NATIVE_TESTBEDS_SELFTEST_RAN cases=false-negative-probe,valid,duplicate,failed-child,required-sud'

}

case "${1:-}" in
  --help|-h) usage; exit 0 ;;
  --selftest) selftest; exit 0 ;;
  '') ;;
  *) usage >&2; exit 2 ;;
esac

selftest
sud=0
if [[ $(uname -s) == Linux ]]; then
  "${CC:-cc}" -Wall -Wextra -Werror testbeds/native-boundary/sud_support.c -o "$tmp/sud"
  status=0
  "$tmp/sud" || status=$?
  case $status in
    0) sud=1 ;;
    1) ;;
    *) echo "FAIL: independent SUD probe exited $status" >&2; exit 1 ;;
  esac
fi

require_sud "$sud"

require_receipt testbeds/fifo-ipc/run-patina.sh \
  'FIFO_LEGS_RAN legs=audit-clean,run,seed-stable,record-replay,seed-sweep'
if ((sud)); then
  require_receipt testbeds/rustix-default/run-patina.sh \
    'RUSTIX_LEGS_RAN branch=sud legs=audit-sud-managed,run,seed-stable,seed-varying-entropy,record-replay'
  require_receipt testbeds/cap-std-dirfd/run-patina.sh \
    'CAPSTD_LEGS_RAN branch=sud legs=audit-sud-managed,run,seed-stable,record-replay'
else
  for name in rustix-default cap-std-dirfd; do
    require_receipt "testbeds/$name/run-patina.sh" \
      "$name: SKIPPED 1 (host lacks syscall-user-dispatch: $(uname -s) $(uname -m); SUD is x86_64 Linux >= 5.11)"
  done
fi
