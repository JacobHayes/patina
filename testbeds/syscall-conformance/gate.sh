#!/usr/bin/env bash
###############################################################################
# gate.sh — the family gate for a frozen oracle
# (docs/arcs/syscall-conformance-signals.md §5). One outcome, one gate:
#
#   gate.sh --family <f>
#
# prints the remaining work as plain lines, then ONE verdict line,
# `FAMILY_GATE <f>: PASS|FAIL`. It passes when:
#   1. frozen paths — the oracle (frozen.toml `paths`: the family's probes and
#      expectations, the harness, this script, frozen.toml) carries no
#      uncommitted change. Version control is the tamper evidence: a builder
#      never commits, the coordinator lands.
#   2. declarations — the family's probes carry only frozen declarations
#      (nothing new or relabeled), every by-design abort is still there, and
#      every `pending` one is gone.
#   3. rustfmt, clippy -D warnings, the registry↔manifest cross-gate.
#   4. the full conformance run is green (every probe, all modes, all vehicles).
#   5. design obligations — what green probes cannot show, since a shallow
#      model can satisfy behaviour-only probes: each required unit test exists,
#      is not #[ignore]d and passes (`cargo test -p <crate> -- --exact <path>`),
#      and each probe's RECORDED trace is at the required format and carries
#      exactly the probe's generations as `signal_generated` ops.
# Every step runs. The work lines say which probes are still pending or differ,
# which required unit tests are missing, ignored or failing, and which trace
# facts are unmet; each step's full log is under target/conformance/gate/.
#
#   gate.sh --selftest    prove each mechanism can refuse: a frozen-path edit,
#                         a relabeled declaration, a missing and an #[ignore]d
#                         required test, a filtered/failed run, raw child stderr,
#                         a recorded trace without the required
#                         op, a termination the guest did not have.
#
# Exit codes: 0 PASS, 1 FAIL, 2 usage, 3 FATAL (a check could not run).
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target/testbeds/syscall-conformance}"
export CARGO_TARGET_DIR="$target_dir"
frozen="$here/frozen.toml"
conform="$target_dir/release/conform"

usage() {
  cat <<'EOF'
usage: testbeds/syscall-conformance/gate.sh --family <f>
       testbeds/syscall-conformance/gate.sh --selftest

  --family     the frozen family to gate (a `[family.<f>]` table in frozen.toml)
  --selftest   prove each of the gate's mechanisms can refuse
EOF
}

family=""
selftest=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --family) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; family=$2; shift 2 ;;
    --selftest) selftest=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "gate.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [[ $selftest == 0 && -z "$family" ]]; then
  usage >&2; exit 2
fi

# Step 1: the uncommitted changes under PATHS (relative to ROOT) in the checkout
# at ROOT — jj, or git where there is no jj repo. Fails closed when neither can
# answer.
check_frozen_paths() {
  local root=$1 changed
  shift
  if (cd "$root" && jj root >/dev/null 2>&1); then
    changed="$(cd "$root" && jj diff --name-only -- "$@")" || { echo "jj diff failed in $root"; return 1; }
  elif changed="$(git -C "$root" status --porcelain -- "$@" 2>/dev/null)"; then
    :
  else
    echo "cannot verify the frozen paths: $root is in neither a jj nor a git checkout"
    return 1
  fi
  [[ -z "$changed" ]] && return 0
  sed 's/^/frozen path has an uncommitted change: /' <<<"$changed"
  return 1
}

# Step 5a: the required unit tests (TSV: crate, test) against the workspace at
# MANIFEST. One `--list` and one run per crate; every verdict is
# read from cargo's own per-test lines.
check_unit_tests() {
  local manifest=$1 due=$2 rc=0 crate
  for crate in $(cut -f1 "$due" | sort -u); do
    local list run c test path matches verdict stderr_file run_status crate_failed
    stderr_file="$(mktemp "${TMPDIR:-/tmp}/gate-unit-stderr.XXXXXX")" || return 1
    if ! list="$(cargo test --manifest-path "$manifest" -p "$crate" -- --list 2>"$stderr_file")"; then
      echo "unit tests do not build: $crate (cargo test -p $crate)"
      cat "$stderr_file" >&2
      rm -f "$stderr_file"
      rc=1; continue
    fi
    local paths=()
    while IFS=$'\t' read -r c test; do
      [[ "$c" == "$crate" ]] || continue
      matches="$(sed -n 's/: test$//p' <<<"$list" | awk -v t="$test" '$0 == t || (length($0) > length(t) + 1 && substr($0, length($0) - length(t) - 1) == "::" t)' | sort -u)"
      case "$(grep -c . <<<"$matches")" in
        0) echo "unit test missing: $crate $test"; rc=1 ;;
        1) paths+=("$matches") ;;
        *) echo "unit test ambiguous: $crate $test matches $(tr '\n' ' ' <<<"$matches")"; rc=1 ;;
      esac
    done <"$due"
    if [[ ${#paths[@]} == 0 ]]; then
      rm -f "$stderr_file"
      continue
    fi
    # Serial libtest prints `test NAME ...` before running the body. A child's
    # compiler stderr can arrive before `ok`; never parse the merged streams.
    run="$(cargo test --manifest-path "$manifest" -p "$crate" -- --exact "${paths[@]}" 2>"$stderr_file")"
    run_status=$?
    crate_failed=0
    for path in "${paths[@]}"; do
      verdict="$(awk -v p="$path" '$1 == "test" && $2 == p && / \.\.\. / { print $NF }' <<<"$run" | sort | tr '\n' ' ')"
      case "$verdict" in
        "ok ") ;;
        "ignored ") echo "unit test ignored: $crate $path (it must run and pass)"; crate_failed=1 ;;
        *) echo "unit test failing: $crate $path (${verdict:-it did not run})"; crate_failed=1 ;;
      esac
    done
    if [[ $run_status != 0 ]]; then
      echo "unit test command failed: $crate (exit $run_status)"
      crate_failed=1
    fi
    if [[ $crate_failed == 1 ]]; then
      printf 'unit test stdout (%s):\n%s\n' "$crate" "$run" >&2
      printf 'unit test stderr (%s):\n' "$crate" >&2
      cat "$stderr_file" >&2
      rc=1
    fi
    rm -f "$stderr_file"
  done
  return $rc
}

# Step 5: one line per unmet obligation.
check_obligations() {
  local root=$1 fam=$2 outdir=$3 rc=0 due
  due="$(mktemp "${TMPDIR:-/tmp}/gate-unit-tests.XXXXXX")"
  "$conform" obligations "$frozen" "$fam" unit-tests >"$due" || rc=1
  "$conform" obligations "$frozen" "$fam" traces "$outdir" || rc=1
  if [[ -s "$due" ]]; then
    check_unit_tests "$root/Cargo.toml" "$due" || rc=1
  fi
  rm -f "$due"
  return $rc
}

if ! cargo build --release --quiet --manifest-path "$here/Cargo.toml" --bin conform; then
  echo "gate.sh: FATAL: cannot build conform" >&2; exit 3
fi

# ---- --selftest ------------------------------------------------------------
if [[ $selftest == 1 ]]; then
  status=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/conformance-gate.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  # Each case sets $out/$rc from a run, then judges it: `accepted` for the
  # control, `refused` for the plant (it must fail AND say why).
  accepted() {
    if [[ $rc != 0 ]]; then
      echo "GATE SELFTEST FAILED: control: $1:" >&2; echo "$out" >&2; status=1
    fi
  }
  refused() {
    if [[ $rc == 0 ]] || ! grep -qF -- "$2" <<<"$out"; then
      echo "GATE SELFTEST FAILED: $1 was not refused with '$2':" >&2; echo "$out" >&2; status=1
    fi
  }

  # 1. A frozen-path edit, in a scratch checkout with one committed probe.
  repo="$tmp/repo"
  mkdir -p "$repo/probes" && echo "fn main() {}" >"$repo/probes/a.rs"
  if command -v jj >/dev/null 2>&1; then
    (cd "$repo" && jj git init . && jj commit -m oracle) >/dev/null 2>&1
  else
    (cd "$repo" && git init -q . && git add . && git -c user.name=gate -c user.email=gate@selftest.invalid commit -q -m oracle) >/dev/null 2>&1
  fi
  out="$(check_frozen_paths "$repo" probes 2>&1)"; rc=$?
  accepted "a committed oracle carries no uncommitted change"
  echo "// weakened" >>"$repo/probes/a.rs"
  out="$(check_frozen_paths "$repo" probes 2>&1)"; rc=$?
  refused "planted frozen-path edit" "probes/a.rs"

  # 2. A relabeled declaration: an M2 entry retagged M5.
  #    (The control: every line the rule prints for this tree is a frozen
  #    pending declaration still present — nothing new, nothing removed.)
  out="$("$conform" gate "$frozen" "$here/divergences.toml" signals 2>&1 | grep -v '^still pending: ')"; rc=$((1 - $?))
  accepted "the tree's declarations are all in the frozen set"
  sed 's/^reason = "by design: fork is a process-lifecycle trap/reason = "by design (relabeled): fork is a process-lifecycle trap/' "$here/divergences.toml" >"$tmp/divergences.toml"
  out="$("$conform" gate "$frozen" "$tmp/divergences.toml" signals 2>&1)"; rc=$?
  refused "planted relabeled declaration" "not in the frozen set"

  # 3. Required unit tests, against a real scratch crate: one passes, one is
  #    missing, one is #[ignore]d.
  mkdir -p "$tmp/crate/src"
  printf '[workspace]\n[package]\nname = "gate-selftest"\nversion = "0.0.0"\nedition = "2021"\n' >"$tmp/crate/Cargo.toml"
  cat >"$tmp/crate/src/lib.rs" <<'RS'
#[cfg(test)]
mod tests {
    #[test]
    fn present_and_passing() {}
    #[test]
    fn passing_with_child_stderr() {
        assert!(std::process::Command::new("sh")
            .args(["-c", "printf 'child compiler chatter build.rs\\n' >&2"])
            .status().unwrap().success());
    }
    #[test]
    fn present_but_failing() {
        println!("planted stdout diagnostic");
        assert!(std::process::Command::new("sh")
            .args(["-c", "printf 'planted stderr diagnostic\\n' >&2"])
            .status().unwrap().success());
        panic!("planted body failure");
    }
    #[test]
    #[ignore]
    fn present_but_ignored() {}
}
RS
  printf 'gate-selftest\tpresent_and_passing\n' >"$tmp/due.tsv"
  out="$(check_unit_tests "$tmp/crate/Cargo.toml" "$tmp/due.tsv" 2>&1)"; rc=$?
  accepted "a required unit test that exists, runs and passes is met"
  printf 'gate-selftest\tpassing_with_child_stderr\n' >"$tmp/due.tsv"
  out="$(RUST_TEST_THREADS=1 check_unit_tests "$tmp/crate/Cargo.toml" "$tmp/due.tsv" 2>&1)"; rc=$?
  accepted "serial test verdict survives raw child stderr"
  printf 'gate-selftest\tpresent_but_failing\n' >"$tmp/due.tsv"
  out="$(check_unit_tests "$tmp/crate/Cargo.toml" "$tmp/due.tsv" 2>&1)"; rc=$?
  refused "planted body failure" "unit test failing: gate-selftest tests::present_but_failing"
  refused "failed test keeps stdout" "planted stdout diagnostic"
  refused "failed test keeps stderr" "planted stderr diagnostic"
  printf 'gate-selftest\tpresent_and_passing\n' >"$tmp/due.tsv"
  # A real zero-test cargo run, despite a successful --list lookup, must refuse.
  out="$(
    cargo() {
      if [[ " $* " == *" --list "* ]]; then
        command cargo "$@"
      else
        command cargo "$@" --skip tests::present_and_passing
      fi
    }
    check_unit_tests "$tmp/crate/Cargo.toml" "$tmp/due.tsv" 2>&1
  )"; rc=$?
  refused "planted filtered-to-empty run" "it did not run"
  printf 'gate-selftest\tunmask_delivers_pending_before_return\ngate-selftest\tpresent_but_ignored\n' >"$tmp/due.tsv"
  out="$(check_unit_tests "$tmp/crate/Cargo.toml" "$tmp/due.tsv" 2>&1)"; rc=$?
  refused "planted missing required test" "unit test missing: gate-selftest unmask_delivers_pending_before_return"
  refused "planted #[ignore]d required test" "unit test ignored: gate-selftest tests::present_but_ignored"

  # 4. A recorded trace without the required op, through the frozen
  #    obligation of signal/basic (kill, tgkill, tkill to self).
  mkdir -p "$tmp/traces/signal-basic"
  plant_trace() {
    local v
    for v in libc syscall raw; do
      echo '{"format_version":9}' >"$tmp/traces/signal-basic/replay.$v.trace-info.json"
      printf '%s\n' "$1" >"$tmp/traces/signal-basic/replay.$v.trace-events.jsonl"
    done
  }
  plant_trace '{"kind":"signal_generated","operation":{"sig":10,"target":"process"}}
{"kind":"signal_generated","operation":{"sig":10,"target":{"task":1}}}
{"kind":"signal_generated","operation":{"sig":10,"target":{"task":1}}}'
  out="$("$conform" obligations "$frozen" signals traces "$tmp/traces" 2>&1 | grep -F 'signal/basic[')"; rc=$((1 - $?))
  accepted "a recorded trace carrying the probe's generations in order is met"
  plant_trace '{"kind":"scheduler_next","operation":{}}'
  out="$("$conform" obligations "$frozen" signals traces "$tmp/traces" 2>&1)"; rc=$?
  refused "planted recorded trace without the required op" "trace fact unmet: signal/basic[libc]: signal_generated ops recorded [], the probe generates [10:p 10:t 10:t]"

  # 5. A termination the guest did not have. signal/default_term is blessed to
  #    die by SIGTERM; the differ compares the OBSERVED outcome and never fills
  #    one in, so a stream that lacks it, or that exited instead, fails.
  blessed="$here/expected/signal/default_term.linux-x86_64.jsonl"
  grep -v '"header"' "$blessed" >"$tmp/died.jsonl"
  out="$("$conform" diff native signal/default_term libc "$blessed" "$tmp/died.jsonl" "$here/divergences.toml" 2>&1)"; rc=$?
  accepted "the observed death the blessing records passes"
  grep -v '__termination' "$tmp/died.jsonl" >"$tmp/unobserved.jsonl"
  out="$("$conform" diff native signal/default_term libc "$blessed" "$tmp/unobserved.jsonl" "$here/divergences.toml" 2>&1)"; rc=$?
  refused "planted stream with no observed termination" "no termination line observed"
  sed 's/"fields":{"core":false,"kind":"signaled","signal":15}/"fields":{"code":143,"kind":"exited"}/' "$tmp/died.jsonl" >"$tmp/exited.jsonl"
  out="$("$conform" diff native signal/default_term libc "$blessed" "$tmp/exited.jsonl" "$here/divergences.toml" 2>&1)"; rc=$?
  refused "planted exit(128+SIGTERM) where the blessing died by SIGTERM" "__termination"

  if [[ $status != 0 ]]; then
    echo "gate.sh: SELFTEST FAILED — the gate cannot fail" >&2; exit 1
  fi
  echo "GATE_SELFTEST_RAN cases=frozen-path-edit,relabeled-declaration,missing-and-ignored-unit-test,child-stderr,failed-and-empty-unit-test,trace-without-required-op,unobserved-termination"
  exit 0
fi

# ---- --family --------------------------------------------------------------
# Each step's output goes to its log; a failed step contributes work lines:
# the log itself when the step prints work lines (`lines`), the failing legs of
# the conformance run (`legs`), or one line naming the log (`log`).
logs="$target_dir/conformance/gate"
mkdir -p "$logs"
work=()
step() {
  local name=$1 kind=$2 log line
  shift 2
  log="$logs/${name// /-}.log"
  "$@" >"$log" 2>&1 && return 0
  case "$kind" in
    lines) mapfile -t -O "${#work[@]}" work <"$log" ;;
    legs) mapfile -t -O "${#work[@]}" work < <(sed -n 's/^FAIL \([^ ]*\[[^]]*\]\): \(.*\)/probe differs: \1: \2/p' "$log")
      work+=("(every difference of those legs: $log)") ;;
  esac
  if [[ "$kind" == log ]] || ! grep -q . "$log"; then
    work+=("$name failed (log: $log)")
  elif [[ "$kind" == legs ]] && ! grep -q '^FAIL [^ ]*\[' "$log"; then
    work+=("$name failed without a failing leg (log: $log)")
  fi
}

mapfile -t frozen_paths < <("$conform" frozen-paths "$frozen" "$family")
if [[ ${#frozen_paths[@]} == 0 ]]; then
  echo "gate.sh: FATAL: frozen.toml freezes no family '$family'" >&2; exit 3
fi
step "frozen paths" lines check_frozen_paths "$repo_root" "${frozen_paths[@]}"
step "declarations" lines "$conform" gate "$frozen" "$here/divergences.toml" "$family"
step "rustfmt" log cargo fmt --all --manifest-path "$repo_root/Cargo.toml" -- --check
step "clippy" log cargo clippy --workspace --all-targets --manifest-path "$repo_root/Cargo.toml" -- -D warnings
step "registry cross-gate" log cargo test --manifest-path "$repo_root/Cargo.toml" -p cargo-patina --test syscall_registry
step "conformance run" legs "$here/run.sh"
step "design obligations" lines check_obligations "$repo_root" "$family" "$target_dir/conformance"

if [[ ${#work[@]} == 0 ]]; then
  echo "FAMILY_GATE $family: PASS"
  exit 0
fi
printf '  %s\n' "${work[@]}"
echo "FAMILY_GATE $family: FAIL (${#work[@]} line(s) of work above)"
exit 1
