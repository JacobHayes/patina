#!/usr/bin/env bash
###############################################################################
# Shared cooperative-SUT (buggify) campaign library.
#
# Sourced by the buggify-aware sweeps (workq/fuzz-sweep.sh and
# workq/run-patina.sh leg [6]) so the buggify classifier, the PATINA_SDK_REPORT
# parser, the cross-generation campaign-state accumulator, and their selftests
# live in ONE place and are proven once. Nothing here mutates a caller's existing
# classifier state; it only ADDS the two buggify classes and the campaign-level
# coverage oracle.
#
# The two new classes:
#   ALWAYS_VIOLATION  per-gen, top severity (peer of a safety bug): a
#                     `PATINA_VERDICT ... kind=violation` line means an `always!`
#                     invariant was violated (the SDK lowers `always!` to the
#                     verdict ABI; the line is the run's structured outcome
#                     channel, not a marker). Fires even on exit 0 and is never
#                     downgraded.
#   SOMETIMES_UNMET   campaign-level, evaluated at sweep end: a `sometimes!` site
#                     that was reached in the campaign but never satisfied is a
#                     coverage gap; a campaign with any unmet sometimes-site exits
#                     nonzero.
#
# Everything here is pure (a function of its arguments / an out-dir state file),
# so `buggify_campaign_selftest` can prove each detector bites with canned input.
###############################################################################

# Detect a per-generation buggify finding from a run's streams. Prints the class
# name (ALWAYS_VIOLATION, or the runtime's buggify fatal markers as
# UNEXPECTED_CRASH-peers) or nothing when there is no buggify-specific finding —
# in which case the caller keeps its own classification. An `always!` violation
# is the top-priority finding: it is returned regardless of exit code and must
# not be masked by anything else the caller would compute.
buggify_class() {
  # args: exit_code stdout stderr
  local combined="$2
$3"
  if printf '%s' "$combined" | /usr/bin/grep -Eq 'PATINA_VERDICT .*kind=violation'; then
    echo ALWAYS_VIOLATION; return
  fi
  if printf '%s' "$combined" | /usr/bin/grep -q 'PATINA_BUGGIFY_DUPLICATE_LABEL'; then
    echo BUGGIFY_DUPLICATE_LABEL; return
  fi
  if printf '%s' "$combined" | /usr/bin/grep -q 'PATINA_BUGGIFY_SETUP_NEVER_CALLED'; then
    echo BUGGIFY_SETUP_NEVER_CALLED; return
  fi
  # No buggify-specific finding.
  return 0
}

# Extract the single PATINA_SDK_REPORT line (if any) from a stderr file.
sdk_report_line() {
  # args: stderr_file
  /usr/bin/grep -m1 '^PATINA_SDK_REPORT ' "$1" 2>/dev/null || true
}

# Extract a scalar field (enabled, sites_activated, total_firings, ...) from a
# PATINA_SDK_REPORT line. Empty if absent.
sdk_field() {
  # args: field_name sdk_line
  printf '%s' "$2" | /usr/bin/grep -o "$1=[0-9][0-9]*" | head -1 | cut -d= -f2
}

# Accumulate one generation's PATINA_SDK_REPORT into the campaign-state JSON,
# tracking per-site kind/reached/activated/fired counts and — for `sometimes`
# sites — whether the assertion was ever satisfied across the whole campaign.
# Creates the state file if absent. A gen with no SDK_REPORT line only bumps the
# generation counter, so a mixed or buggify-free campaign is handled cleanly.
#
# Labels and site identities are decoded with the runtime's report-token
# escaping (`patina_dst_abi::report_token`); the header must carry
# `encoding=escaped` before any site row, as `cargo patina` requires, and a line
# without it or with a malformed escape fails the accumulation loudly.
campaign_accumulate() {
  # args: state_file sdk_report_line
  local state_file="$1" sdk_line="$2"
  BUGGIFY_STATE_FILE="$state_file" BUGGIFY_SDK_LINE="$sdk_line" python3 - <<'PY'
import json, os, re

state_file = os.environ["BUGGIFY_STATE_FILE"]
line = os.environ["BUGGIFY_SDK_LINE"].strip()

NAMED_ESCAPES = {"\\": "\\", "s": " ", "t": "\t", "r": "\r", "n": "\n", "p": "|"}

def unescape(value):
    """Mirror of patina_dst_abi::report_token::unescape; exits on a bad escape."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        i += 1
        if ch != "\\":
            out.append(ch)
            continue
        code = value[i] if i < len(value) else ""
        i += 1
        if code in NAMED_ESCAPES:
            out.append(NAMED_ESCAPES[code])
            continue
        match = re.match(r"\{([0-9a-fA-F]+)\}", value[i:]) if code == "u" else None
        point = int(match.group(1), 16) if match else -1
        if not (0 <= point <= 0x10FFFF) or 0xD800 <= point <= 0xDFFF:
            raise SystemExit(f"malformed escape in PATINA_SDK_REPORT field: {value!r}")
        out.append(chr(point))
        i += match.end()
    return "".join(out)

try:
    with open(state_file) as fh:
        state = json.load(fh)
except (FileNotFoundError, ValueError):
    state = {"generations": 0, "gens_with_report": 0, "sites": {}}

state["generations"] = state.get("generations", 0) + 1
sites = state.setdefault("sites", {})

if line.startswith("PATINA_SDK_REPORT"):
    state["gens_with_report"] = state.get("gens_with_report", 0) + 1
    encoded = False
    for token in filter(None, line.split(" ")):
        if token.startswith("encoding="):
            if token != "encoding=escaped":
                raise SystemExit(f"unknown PATINA_SDK_REPORT encoding: {token}")
            encoded = True
            continue
        if token.startswith(("site=", "declared_site=")) and not encoded:
            raise SystemExit("PATINA_SDK_REPORT lacks encoding=escaped before its site rows")
        if not token.startswith("site="):
            continue
        # site=<label>|<kind>|a<0|1>|e<n>|f<n>|r<0|1>|s<0|1>|v<0|1>|k<v|->|@<file:line>
        body = token[len("site="):]
        parts = body.split("|")
        if len(parts) != 10 or not parts[9].startswith("@") or len(parts[9]) == 1:
            raise SystemExit(f"malformed PATINA_SDK_REPORT site token (expected Wave 2 @file:line): {token}")
        label, kind = unescape(parts[0]), parts[1]
        if not label:
            raise SystemExit(f"PATINA_SDK_REPORT site token has an empty label: {token}")
        active = parts[2] == "a1"
        evals = int(parts[3][1:]) if parts[3][1:].isdigit() else 0
        fires = int(parts[4][1:]) if parts[4][1:].isdigit() else 0
        reached = parts[5] == "r1"
        satisfied = parts[6] == "s1"
        violated = parts[7] == "v1"
        site = unescape(parts[9][1:])
        rec = sites.setdefault(label, {
            "kind": kind, "site": site, "reached": False, "activated_gens": 0,
            "fired_gens": 0, "total_fires": 0, "sometimes_satisfied": False,
            "always_violated": False,
        })
        rec["kind"] = kind
        rec["site"] = site
        rec["reached"] = rec["reached"] or reached
        if active:
            rec["activated_gens"] += 1
        if fires > 0:
            rec["fired_gens"] += 1
        rec["total_fires"] += fires
        if satisfied:
            rec["sometimes_satisfied"] = True
        if violated:
            rec["always_violated"] = True
    if not encoded:
        raise SystemExit("PATINA_SDK_REPORT lacks its encoding=escaped header")

tmp = state_file + ".tmp"
with open(tmp, "w") as fh:
    json.dump(state, fh, indent=2, sort_keys=True)
os.replace(tmp, state_file)
PY
}

# Print the labels of `sometimes` sites that were reached during the campaign but
# never satisfied — the SOMETIMES_UNMET set — one per line, in the report's own
# escaped form, so a label holding a newline (or any whitespace) is still exactly
# one non-empty line for a caller's `read -r` loop. Empty output means every
# reached sometimes-site was satisfied at least once. This legacy shell helper tracks the
# SOMETIMES_UNMET class only; first-class `cargo patina campaign` consumes
# `declared_site=` rows and gates never-reached `reachable!` sites too.
campaign_sometimes_unmet() {
  # args: state_file
  [[ -f "$1" ]] || return 0
  BUGGIFY_STATE_FILE="$1" python3 - <<'PY'
import json, os

# Unicode White_Space, the set Rust's char::is_whitespace (and so
# patina_dst_abi::report_token::escape) escapes as \u{hex}.
WHITE_SPACE = set("\t\n\x0b\x0c\r \x85\xa0\u1680\u2028\u2029\u202f\u205f\u3000")
WHITE_SPACE |= {chr(c) for c in range(0x2000, 0x200B)}
NAMED = {"\\": "\\\\", " ": "\\s", "\t": "\\t", "\r": "\\r", "\n": "\\n", "|": "\\p"}

def escape(value):
    """Mirror of patina_dst_abi::report_token::escape."""
    return "".join(
        NAMED.get(ch) or (f"\\u{{{ord(ch):x}}}" if ch in WHITE_SPACE else ch) for ch in value
    )

with open(os.environ["BUGGIFY_STATE_FILE"]) as fh:
    state = json.load(fh)
for label, rec in sorted(state.get("sites", {}).items()):
    if rec.get("kind") == "sometimes" and rec.get("reached") and not rec.get("sometimes_satisfied"):
        print(escape(label))
PY
}

# Fold one generation's stderr report into the campaign state. A report the
# accumulator refuses (no encoding marker, a malformed row or escape) is a loud
# failure naming the evidence file; every caller must stop on it and keep that
# file, never count the generation as clean.
campaign_observe() {
  # args: state_file stderr_file
  if ! campaign_accumulate "$1" "$(sdk_report_line "$2")"; then
    echo "FATAL: the PATINA_SDK_REPORT in $2 was refused; that generation's evidence is kept" >&2
    return 1
  fi
}

# Assert that a raw run stderr joins cleanly against the testbed's static sites.
# This is the Wave 2 invariant-visibility gate for direct-macro testbeds:
# every runtime label in the SDK report must match a static row (or the scan/parser
# drifted). Prints one concise evidence line on success.
buggify_sites_join_assert() {
  # args: cargo_patina_exe package_dir stderr_file
  local patina="$1" package_dir="$2" stderr_file="$3" out err unmatched
  out="$(mktemp)"; err="$(mktemp)"
  if ! (cd "$package_dir" && "$patina" sites --no-cache --exercised "$stderr_file" --format json >"$out" 2>"$err"); then
    echo "FATAL: cargo patina sites --exercised failed for $stderr_file" >&2
    cat "$out" >&2; cat "$err" >&2
    rm -f "$out" "$err"
    return 1
  fi
  if ! unmatched="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['unmatched_runtime_labels'])" "$out")"; then
    echo "FATAL: could not read unmatched_runtime_labels from sites --exercised output" >&2
    cat "$out" >&2; cat "$err" >&2
    rm -f "$out" "$err"
    return 1
  fi
  if [[ "$unmatched" != 0 ]]; then
    echo "FATAL: sites --exercised found unmatched runtime labels ($unmatched) for $stderr_file" >&2
    cat "$out" >&2
    rm -f "$out" "$err"
    return 1
  fi
  echo "PATINA_SITES_JOIN unmatched_runtime_labels=0 report=$stderr_file"
  rm -f "$out" "$err"
}

###############################################################################
# Selftest: prove both detectors bite and neither downgrades a real finding.
# Returns 0 on success, 1 on any failure. Caller wires this into its --selftest.
###############################################################################
buggify_campaign_selftest() {
  local fail=0
  _bc_expect() { # want got name
    if [[ "$1" == "$2" ]]; then printf '  ok   %-32s -> %s\n' "$3" "$2"
    else printf '  FAIL %-32s -> %s (want %s)\n' "$3" "$2" "$1"; fail=1; fi
  }

  echo "== buggify campaign selftest =="

  # ALWAYS_VIOLATION is fireable and fires even on exit 0 (a violated invariant
  # is a bug no matter how the process exited).
  _bc_expect ALWAYS_VIOLATION \
    "$(buggify_class 0 'RESULT ok' 'PATINA_VERDICT seq=0 kind=violation label=fired-in-bounds detail=src/x.rs:9')" \
    "always-violation-on-exit-0"
  # Not downgraded: present alongside otherwise-clean output, still fires.
  _bc_expect ALWAYS_VIOLATION \
    "$(buggify_class 0 'RESULT ok
PATINA_SDK_REPORT enabled=1 sites_registered=3' 'PATINA_VERDICT seq=0 kind=violation label=x detail=src/x.rs:9')" \
    "always-violation-not-downgraded"
  # The runtime's buggify fatal markers are surfaced too.
  _bc_expect BUGGIFY_DUPLICATE_LABEL \
    "$(buggify_class 134 '' 'PATINA_BUGGIFY_DUPLICATE_LABEL label=same')" "duplicate-label"
  _bc_expect BUGGIFY_SETUP_NEVER_CALLED \
    "$(buggify_class 134 '' 'PATINA_BUGGIFY_SETUP_NEVER_CALLED ...')" "setup-never-called"
  # A clean run yields no buggify-specific class (caller keeps its own verdict).
  _bc_expect "" \
    "$(buggify_class 0 'RESULT ok' 'PATINA_SDK_REPORT enabled=1 sites_registered=2')" \
    "clean-no-buggify-class"

  # SOMETIMES_UNMET is fireable: a sometimes-site reached but never satisfied
  # across the campaign is reported; a satisfied one and a fault site are not.
  local tmp; tmp="$(mktemp)"
  # Gen 1: the "torn-page" sometimes site is reached (r1) but unsatisfied (s0);
  # the "recovery" sometimes site is satisfied (s1).
  campaign_accumulate "$tmp" \
    'PATINA_SDK_REPORT encoding=escaped enabled=1 fire_permille=250 activation_permille=250 cutoff_nanos=0 cutoff_reached=0 sites_registered=3 sites_activated=1 total_firings=2 cutoff_suppressed=0 after_setup=0 setup_complete=1 site=torn-page-rejected|sometimes|a0|e5|f0|r1|s0|v0|k-|@src/main.rs:10 site=recovery-exercised|sometimes|a0|e3|f0|r1|s1|v0|k-|@src/main.rs:11 site=commit-early|fault|a1|e5|f2|r1|s0|v0|k-|@src/main.rs:12'
  # Gen 2: torn-page reached again, still unsatisfied.
  campaign_accumulate "$tmp" \
    'PATINA_SDK_REPORT encoding=escaped enabled=1 sites_registered=3 site=torn-page-rejected|sometimes|a0|e4|f0|r1|s0|v0|k-|@src/main.rs:10'
  local unmet; unmet="$(campaign_sometimes_unmet "$tmp")"
  _bc_expect "torn-page-rejected" "$unmet" "sometimes-unmet-fires"

  # Once the site is satisfied in a later gen, it drops out of the unmet set.
  campaign_accumulate "$tmp" \
    'PATINA_SDK_REPORT encoding=escaped enabled=1 sites_registered=3 site=torn-page-rejected|sometimes|a0|e4|f1|r1|s1|v0|k-|@src/main.rs:10'
  _bc_expect "" "$(campaign_sometimes_unmet "$tmp")" "sometimes-unmet-clears-when-satisfied"

  # The accumulator counts generations and fault fires correctly.
  local gens fires
  gens="$(python3 -c "import json;print(json.load(open('$tmp'))['generations'])")"
  fires="$(python3 -c "import json;print(json.load(open('$tmp'))['sites']['commit-early']['total_fires'])")"
  _bc_expect 3 "$gens" "campaign-generation-count"
  _bc_expect 2 "$fires" "campaign-fault-fire-count"
  rm -f "$tmp"

  # Labels and site identities arrive escaped: `retry\\site` encodes the label
  # `retry\site`, so its unsatisfied and satisfied reports are ONE site, keyed
  # by its decoded label (and reported, like every unmet label, escaped).
  tmp="$(mktemp)"
  campaign_accumulate "$tmp" \
    'PATINA_SDK_REPORT encoding=escaped enabled=1 site=retry\\site|sometimes|a0|e1|f0|r1|s0|v0|k-|@src/a\sb.rs:1'
  _bc_expect 'retry\\site' "$(campaign_sometimes_unmet "$tmp")" "unmet-label-reported-escaped"
  _bc_expect 'src/a b.rs:1' \
    "$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['sites']['retry\\\\site']['site'])" "$tmp")" \
    "escaped-site-identity-decodes"
  campaign_accumulate "$tmp" \
    'PATINA_SDK_REPORT encoding=escaped enabled=1 site=retry\\site|sometimes|a0|e1|f0|r1|s1|v0|k-|@src/a\sb.rs:1'
  _bc_expect "" "$(campaign_sometimes_unmet "$tmp")" "escaped-label-satisfied-once-clears"
  # A report without the encoding marker (written before escaping) or with a
  # malformed escape is refused rather than decoded under a guess.
  local refused
  for refused in \
    'PATINA_SDK_REPORT enabled=1 site=retry\site|sometimes|a0|e1|f0|r1|s0|v0|k-|@src/main.rs:1' \
    'PATINA_SDK_REPORT encoding=escaped enabled=1 site=retry\q|sometimes|a0|e1|f0|r1|s0|v0|k-|@src/main.rs:1'; do
    if campaign_accumulate "$tmp" "$refused" 2>/dev/null; then
      _bc_expect refused accepted "undecodable-report-refused"
    else
      _bc_expect refused refused "undecodable-report-refused"
    fi
  done
  rm -f "$tmp"

  # A label that decodes to a newline is still ONE unmet site through the
  # callers' own `read -r` loop, which drops empty lines.
  tmp="$(mktemp)"
  campaign_accumulate "$tmp" \
    'PATINA_SDK_REPORT encoding=escaped enabled=1 site=\n|sometimes|a0|e1|f0|r1|s0|v0|k-|@src/main.rs:1'
  local unmet_sites=() line
  while IFS= read -r line; do [[ -n "$line" ]] && unmet_sites+=("$line"); done < <(campaign_sometimes_unmet "$tmp")
  _bc_expect 1 "${#unmet_sites[@]}" "newline-label-counts-as-one-unmet-site"
  _bc_expect '\n' "${unmet_sites[0]:-}" "newline-label-reported-escaped"
  rm -f "$tmp"

  # campaign_observe, the callers' entry point, fails on a refused report.
  tmp="$(mktemp)"; local err; err="$(mktemp)"
  echo 'PATINA_SDK_REPORT enabled=1 site=x|sometimes|a0|e1|f0|r1|s0|v0|k-|@src/main.rs:1' > "$err"
  if campaign_observe "$tmp" "$err" 2>/dev/null; then
    _bc_expect failed observed "observe-fails-on-a-refused-report"
  else
    _bc_expect failed failed "observe-fails-on-a-refused-report"
  fi
  rm -f "$tmp" "$err"

  echo
  if (( fail )); then echo "BUGGIFY CAMPAIGN SELFTEST FAILED"; return 1; fi
  echo "BUGGIFY CAMPAIGN SELFTEST PASSED"
  return 0
}

###############################################################################
# Direct-invocation CLI. This file is a LIBRARY meant to be SOURCED; the guard
# below is inert when sourced (BASH_SOURCE[0] != $0) so a caller's own $1 is never
# consumed. Executed directly it only self-checks or prints help.
###############################################################################
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-}" in
    -h|--help)
      cat <<'EOF'
buggify-campaign.sh — shared cooperative-SUT (buggify) campaign LIBRARY.

This file is meant to be SOURCED by the buggify-aware sweeps
(testbeds/workq/fuzz-sweep.sh, testbeds/workq/run-patina.sh, and
testbeds/buggify-wasi/wasi-buggify-sweep.sh). It provides the buggify classifier
(ALWAYS_VIOLATION / the buggify fatal markers), the SOMETIMES_UNMET campaign
oracle, the PATINA_SDK_REPORT parser, the cross-generation campaign-state
accumulator, and their selftest. Sourced, it defines functions only and honors no
arguments; it runs no campaign on its own.

Usage (direct invocation is only for its own self-check):
  buggify-campaign.sh --selftest    run the shared campaign-layer selftest.
  buggify-campaign.sh -h | --help   show this help.

Exit status: 0 = help or selftest passed; 1 = selftest failed; 2 = usage error.
EOF
      exit 0 ;;
    --selftest)
      [[ $# -gt 1 ]] && { echo "buggify-campaign.sh: --selftest takes no arguments" >&2; exit 2; }
      buggify_campaign_selftest; exit $? ;;
    "")
      echo "buggify-campaign.sh is a sourced library; run --selftest to self-check or --help for details" >&2
      exit 2 ;;
    *)
      echo "buggify-campaign.sh: unknown argument '${1}' (expected --selftest or --help)" >&2
      exit 2 ;;
  esac
fi
