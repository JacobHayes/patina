#!/usr/bin/env bash
# Append overhead-benchmark records to the `bench-data` branch and push it.
#
# usage: scripts/bench-publish.sh RECORDS_JSONL DATA_FILE
#
# RECORDS_JSONL is scripts/bench.py's output; its lines are appended to
# DATA_FILE (for example data/linux-x86_64.jsonl) on origin's `bench-data`
# branch, a history of data files only that shares no commits with main. The
# first publish creates the branch as a root commit.
#
# It publishes only from a GitHub Actions run of main, and only records of
# that run's commit: it refuses unless GITHUB_ACTIONS=true and
# GITHUB_REF=refs/heads/main, and unless every record is a patina.bench/v1
# record whose commit is GITHUB_SHA. A developer machine's data is never
# publishable.
#
# Concurrent jobs publish to the same branch, so the push can find a tip newer
# than the one the append was made on. Git refuses that push (it is never
# forced), and the script then fetches the new tip, appends again on top of it
# and retries, with a jittered back-off. It writes through a temporary worktree
# and never touches the checkout it runs from. The commit identity comes from
# the environment (GIT_AUTHOR_* and GIT_COMMITTER_*).
set -euo pipefail

branch=bench-data
attempts=6
usage() { sed -n '4,4p' "$0" | sed 's/^# //'; }
fail() { echo "bench-publish: FAILED: $*" >&2; exit 1; }
case ${1:-} in
  -h|--help) usage; exit 0 ;;
esac
if [[ $# -ne 2 ]]; then usage >&2; exit 2; fi

if [[ ${GITHUB_ACTIONS:-} != true || ${GITHUB_REF:-} != refs/heads/main ]]; then
  fail "publishes only from a GitHub Actions run of main" \
    "(GITHUB_ACTIONS=${GITHUB_ACTIONS:-unset}, GITHUB_REF=${GITHUB_REF:-unset})"
fi
[[ -n ${GITHUB_SHA:-} ]] || fail "GITHUB_SHA is unset"

records=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
data_file=$2
[[ -s $records ]] || fail "no records in $1"
python3 - "$records" "$GITHUB_SHA" <<'EOF' || fail "refusing $1: not all records are this run's"
import json, sys
path, sha = sys.argv[1], sys.argv[2]
with open(path) as fh:
    for number, line in enumerate(fh, 1):
        try:
            record = json.loads(line)
        except ValueError as error:
            sys.exit(f'bench-publish: {path}:{number}: not JSON ({error})')
        if not isinstance(record, dict) or record.get('schema') != 'patina.bench/v1':
            sys.exit(f'bench-publish: {path}:{number}: not a patina.bench/v1 record')
        if record.get('commit') != sha:
            sys.exit(f'bench-publish: {path}:{number}: commit {record.get("commit")!r} '
                     f'is not GITHUB_SHA {sha}')
EOF

wt=$(mktemp -d "${TMPDIR:-/tmp}/bench-publish.XXXXXX")
drop_worktree() { git worktree remove -f "$wt" >/dev/null 2>&1 || true; rm -rf "$wt"; }
trap drop_worktree EXIT
message="bench: $(basename "$data_file" .jsonl) records for $GITHUB_SHA"

for ((attempt = 1; attempt <= attempts; attempt++)); do
  drop_worktree
  parent=()
  if git fetch -q --depth 1 origin "+refs/heads/$branch:refs/remotes/origin/$branch" 2>/dev/null; then
    git worktree add -q -d "$wt" "origin/$branch"
    parent=(-p "origin/$branch")
  else
    # No branch yet: start from an empty tree. Should the fetch have failed
    # for another reason, this root commit cannot replace the existing branch:
    # the push below is rejected as a non-fast-forward and the loop retries.
    git worktree add -q -d "$wt"
    git -C "$wt" rm -rq .
  fi
  mkdir -p "$(dirname "$wt/$data_file")"
  cat "$records" >>"$wt/$data_file"
  git -C "$wt" add "$data_file"
  commit=$(git -C "$wt" commit-tree "$(git -C "$wt" write-tree)" ${parent[@]+"${parent[@]}"} -m "$message")
  if push_error=$(git push -q origin "$commit:refs/heads/$branch" 2>&1); then
    echo "bench-publish: appended $(wc -l <"$records" | tr -d ' ') record(s) to $branch:$data_file ($commit)"
    exit 0
  fi
  echo "bench-publish: push attempt $attempt of $attempts failed:" >&2
  printf '  %s\n' "${push_error//$'\n'/$'\n'  }" >&2
  if ((attempt < attempts)); then
    # Usually a concurrent job moved the branch; refetch and append again.
    sleep $((attempt * 2 + RANDOM % 5))
  fi
done
fail "the push failed on all $attempts attempts (the last error is above)"
