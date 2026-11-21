# 1. scripts/land in a scratch jj repository with a local origin, `mise` and `gh` stubbed (no
#    network, no check, no CI): it refuses a working copy with changes, an undescribed commit, the
#    bookmark main and a revision that is not the working copy's parent (the gate would check
#    another tree); a required job that passed only on a re-run, unless --accept-rerun; and
#    main having moved while CI ran. Each refusal leaves main@origin off the commit and no branch
#    on origin; otherwise main@origin is fast-forwarded to the commit and the branch is gone.
#@ tier=quick budget=15 slots=0.5
: "${RUNS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
die() { echo "FAIL: $*"; exit 1; }
command -v jj >/dev/null || die "no jj on PATH (mise.toml installs it)"
s=$RUNS/land
mkdir -p "$s/bin"
# jj without the host's configuration; the scratch commits carry a fixture identity (jj pushes
# none without one).
printf '[ui]\npaginate = "never"\n[user]\nname = "fixture"\nemail = "fixture@example.invalid"\n' >"$s/jj.toml"
export JJ_CONFIG=$s/jj.toml
printf '#!/bin/sh\nexit 0\n' >"$s/bin/mise"
# gh: one CI run, whose first-attempt and latest job results come from FIRST and LAST; `run
# watch` (while CI "runs") executes WHILE_CI.
cat >"$s/bin/gh" <<'EOF'
#!/bin/sh
case "$1 $2" in
    "run list") echo 7 ;;
    "run watch") sh -c "${WHILE_CI:-:}" ;;
    "repo view") echo o/r ;;
    "api repos/o/r/actions/runs/7/attempts/1/jobs") printf '%s\n' "$FIRST" | tr , '\n' ;;
    "run view") case "$*" in *jobs*) printf '%s\n' "$LAST" | tr , '\n' ;; *) echo https://ci.invalid/runs/7 ;; esac ;;
    *) echo "gh stub: $*" >&2; exit 1 ;;
esac
EOF
chmod 755 "$s/bin/mise" "$s/bin/gh"
export PATH="$s/bin:$PATH" FIRST="check success,check-arm64 success" LAST="check success,check-arm64 success"
git init -q --bare --initial-branch=main "$s/origin.git"
jj git init --quiet "$s/seed"
(cd "$s/seed" && echo 0 >f && jj commit --quiet -m base && jj bookmark set --quiet main -r @- &&
    jj git remote add origin "$s/origin.git" && jj git push --quiet --bookmark main)
jj git clone --quiet "$s/origin.git" "$s/w"
cd "$s/w"
main() { jj log --no-graph -r main@origin -T commit_id; }
# land ARGS: sets $st and keeps the output in $s/out.
land() { st=0; bash "$root/scripts/land" "$@" >"$s/out" 2>&1 || st=$?; }
ontopic() { git --git-dir="$s/origin.git" branch --list topic; }
# refused ARGS: land exits non-zero, main@origin did not move to the commit, origin has no branch.
refused() {
    before=$(main); land "$@"
    after=$(main); head=$(jj log --no-graph -r @- -T commit_id); topic=$(ontopic)
    { [ "$after" = "$before" ] || [ "$after" != "$head" ]; } && [ "$st" != 0 ] && [ -z "$topic" ] ||
        die "not refused ($*): $(cat "$s/out")"
    echo "refused ($1): $(grep -m1 refused "$s/out")"
}

echo 1 >f
refused topic
jj commit --quiet -m one
refused main
echo 2 >f; jj commit --quiet -m ''
refused topic
jj abandon --quiet @-
echo 3 >h; jj commit --quiet -m two
refused -r @-- topic
jj abandon --quiet @-
FIRST="check failure,check-arm64 success" refused topic
WHILE_CI="cd $s/seed && jj git fetch --quiet && echo m >g && jj commit --quiet -m moved && jj bookmark set --quiet main -r @- && jj git push --quiet --bookmark main" refused topic
FIRST="check failure,check-arm64 success" land --accept-rerun "the stub's planted re-run" topic
[ "$st" = 0 ] || die "--accept-rerun: exit $st: $(cat "$s/out")"
lhs=$(main); rhs=$(jj log --no-graph -r @- -T commit_id)
[ "$lhs" = "$rhs" ] || die "main@origin is not the landed commit"
topic=$(ontopic)
[ -z "$topic" ] || die "the branch bookmark is still on origin"
echo "landed with --accept-rerun: main@origin is the commit; the branch bookmark is gone from origin"

