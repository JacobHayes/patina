#!/usr/bin/env bash
###############################################################################
# Shared cooperative-SUT (buggify) campaign library.
#
# Sourced by the buggify-aware fuzz sweeps (raft-harness/fuzz-sweep.sh and
# redb-harness/buggify-sweep.sh) so the buggify classifier, the PATINA_SDK_REPORT
# parser, the cross-generation campaign-state accumulator, and their selftests
# live in ONE place and are proven once. Nothing here mutates a caller's existing
# classifier state; it only ADDS the two buggify classes and the campaign-level
# coverage oracle.
#
# The two new classes:
#   ALWAYS_VIOLATION  per-gen, top severity (peer of a safety bug): a
#                     PATINA_ALWAYS_VIOLATION marker means an `always!` invariant
#                     was violated. Fires even on exit 0 and is never downgraded.
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
  if printf '%s' "$combined" | /usr/bin/grep -q 'PATINA_ALWAYS_VIOLATION'; then
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
campaign_accumulate() {
  # args: state_file sdk_report_line
  local state_file="$1" sdk_line="$2"
  BUGGIFY_STATE_FILE="$state_file" BUGGIFY_SDK_LINE="$sdk_line" python3 - <<'PY'
import json, os

state_file = os.environ["BUGGIFY_STATE_FILE"]
line = os.environ["BUGGIFY_SDK_LINE"].strip()

try:
    with open(state_file) as fh:
        state = json.load(fh)
except (FileNotFoundError, ValueError):
    state = {"generations": 0, "gens_with_report": 0, "sites": {}}

state["generations"] = state.get("generations", 0) + 1
sites = state.setdefault("sites", {})

if line.startswith("PATINA_SDK_REPORT"):
    state["gens_with_report"] = state.get("gens_with_report", 0) + 1
    for token in line.split():
        if not token.startswith("site="):
            continue
        # site=<label>|<kind>|a<0|1>|e<n>|f<n>|r<0|1>|s<0|1>|v<0|1>|k<v|->
        body = token[len("site="):]
        parts = body.split("|")
        if len(parts) < 9:
            continue
        label, kind = parts[0], parts[1]
        active = parts[2] == "a1"
        evals = int(parts[3][1:]) if parts[3][1:].isdigit() else 0
        fires = int(parts[4][1:]) if parts[4][1:].isdigit() else 0
        reached = parts[5] == "r1"
        satisfied = parts[6] == "s1"
        violated = parts[7] == "v1"
        rec = sites.setdefault(label, {
            "kind": kind, "reached": False, "activated_gens": 0,
            "fired_gens": 0, "total_fires": 0, "sometimes_satisfied": False,
            "always_violated": False,
        })
        rec["kind"] = kind
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

tmp = state_file + ".tmp"
with open(tmp, "w") as fh:
    json.dump(state, fh, indent=2, sort_keys=True)
os.replace(tmp, state_file)
PY
}

# Print the labels of `sometimes` sites that were reached during the campaign but
# never satisfied — the SOMETIMES_UNMET set. Empty output means every reached
# sometimes-site was satisfied at least once. A `reachable` site that was never
# reached is the documented never-reached blind spot, NOT reported here.
campaign_sometimes_unmet() {
  # args: state_file
  [[ -f "$1" ]] || return 0
  BUGGIFY_STATE_FILE="$1" python3 - <<'PY'
import json, os
with open(os.environ["BUGGIFY_STATE_FILE"]) as fh:
    state = json.load(fh)
for label, rec in sorted(state.get("sites", {}).items()):
    if rec.get("kind") == "sometimes" and rec.get("reached") and not rec.get("sometimes_satisfied"):
        print(label)
PY
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
    "$(buggify_class 0 'RESULT ok' 'PATINA_ALWAYS_VIOLATION label=fired-in-bounds')" \
    "always-violation-on-exit-0"
  # Not downgraded: present alongside otherwise-clean output, still fires.
  _bc_expect ALWAYS_VIOLATION \
    "$(buggify_class 0 'RESULT ok
PATINA_SDK_REPORT enabled=1 sites_registered=3' 'PATINA_ALWAYS_VIOLATION label=x')" \
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
    'PATINA_SDK_REPORT enabled=1 fire_permille=250 activation_permille=250 cutoff_nanos=0 cutoff_reached=0 sites_registered=3 sites_activated=1 total_firings=2 cutoff_suppressed=0 after_setup=0 setup_complete=1 site=torn-page-rejected|sometimes|a0|e5|f0|r1|s0|v0|k- site=recovery-exercised|sometimes|a0|e3|f0|r1|s1|v0|k- site=commit-early|fault|a1|e5|f2|r1|s0|v0|k-'
  # Gen 2: torn-page reached again, still unsatisfied.
  campaign_accumulate "$tmp" \
    'PATINA_SDK_REPORT enabled=1 sites_registered=3 site=torn-page-rejected|sometimes|a0|e4|f0|r1|s0|v0|k-'
  local unmet; unmet="$(campaign_sometimes_unmet "$tmp")"
  _bc_expect "torn-page-rejected" "$unmet" "sometimes-unmet-fires"

  # Once the site is satisfied in a later gen, it drops out of the unmet set.
  campaign_accumulate "$tmp" \
    'PATINA_SDK_REPORT enabled=1 sites_registered=3 site=torn-page-rejected|sometimes|a0|e4|f1|r1|s1|v0|k-'
  _bc_expect "" "$(campaign_sometimes_unmet "$tmp")" "sometimes-unmet-clears-when-satisfied"

  # The accumulator counts generations and fault fires correctly.
  local gens fires
  gens="$(python3 -c "import json;print(json.load(open('$tmp'))['generations'])")"
  fires="$(python3 -c "import json;print(json.load(open('$tmp'))['sites']['commit-early']['total_fires'])")"
  _bc_expect 3 "$gens" "campaign-generation-count"
  _bc_expect 2 "$fires" "campaign-fault-fire-count"
  rm -f "$tmp"

  echo
  if (( fail )); then echo "BUGGIFY CAMPAIGN SELFTEST FAILED"; return 1; fi
  echo "BUGGIFY CAMPAIGN SELFTEST PASSED"
  return 0
}
