# Shared helpers for the scripts of this area (sourced, not run).
# Environment from ./check: PATINA, PATINA_GUESTS, RUNS. gdb: PATINA_GDB, else gdb on PATH; the
# scripts SKIP without one (or one older than 12, or without Python), or where the host lets no
# debugger attach (Yama ptrace scope 2 or 3, a container that refuses ptrace).
: "${PATINA:?}" "${PATINA_GUESTS:?}" "${RUNS:?}"
die() { echo "FAIL: $*"; exit 1; }
# field FILE KEY[.SUB]: one (possibly nested) field of a JSON file
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v=v[int(k)] if isinstance(v,list) else v[k]
print(json.dumps(v) if isinstance(v,(list,dict)) or v is None else v)' "$1" "$2"; }

if [ -n "${PATINA_GDB:-}" ]; then
    GDB=$PATINA_GDB
elif command -v gdb >/dev/null; then
    GDB=$(command -v gdb)
else
    echo "SKIP: no gdb (PATH, PATINA_GDB)"
    exit 0
fi
scope=0
[ ! -r /proc/sys/kernel/yama/ptrace_scope ] || scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
if [ "$scope" -ge 2 ]; then
    echo "SKIP: this host lets no debugger attach without privilege (kernel.yama.ptrace_scope = $scope)"
    exit 0
fi
probe=0
"$GDB" -batch -nx -ex 'python assert int(gdb.VERSION.split(".")[0]) >= 12' -ex run --args /bin/true \
    >"$RUNS/gdb-probe.txt" 2>&1 || probe=$?
if [ "$probe" != 0 ]; then
    echo "SKIP: $GDB cannot debug here (gdb 12 or later with Python, and ptrace): $(tail -2 "$RUNS/gdb-probe.txt")"
    exit 0
fi

# prun OUT [run options] -- CMD...: `patina run` into OUT (it must leave a result).
prun() {
    out=$1; shift
    rm -rf "${out:?}"
    timeout 300 "$PATINA" run --out "$out" "$@" >"$out.txt" 2>&1 || [ -f "$out/result.json" ] \
        || die "patina run $*: no result.json: $(tail -3 "$out.txt")"
}

# session RUNDIR SCRIPT [debug options]: `patina debug RUNDIR --no-gdb`, and gdb in batch mode on
# the helper it writes, then SCRIPT (a session after another: the command clears RUNDIR/debug). gdb's output is in RUNDIR.gdb, patina's in RUNDIR.debug, the
# verdict in RUNDIR/debug/session.json; $dst is patina's exit status. GDB_DIES=1: gdb may exit
# with a failure (a script that kills it).
session() {
    local run=$1 scr=$2
    shift 2
    # The rest of an earlier session's directory stays (patina debug replaces it); its helper
    # goes, so that the wait below is for this session's.
    rm -f "$run/debug/patina-gdb.py"
    timeout 600 "$PATINA" debug "$run" --no-gdb "$@" >"$run.debug" 2>&1 &
    local pid=$!
    while [ ! -f "$run/debug/patina-gdb.py" ] && kill -0 "$pid" 2>/dev/null; do sleep 0.1; done
    if [ -f "$run/debug/patina-gdb.py" ]; then
        local gst=0
        timeout 300 "$GDB" -batch -nx -x "$run/debug/patina-gdb.py" -x "$scr" >"$run.gdb" 2>&1 || gst=$?
        # gdb releases the world when it leaves; if it died first, the session must still end.
        touch "$run/debug/release"
        [ "$gst" = 0 ] || [ "${GDB_DIES:-}" = 1 ] || { wait "$pid" || :; die "gdb: exit $gst: $(tail -5 "$run.gdb")"; }
    fi
    dst=0
    wait "$pid" || dst=$?
    [ -f "$run/debug/session.json" ] || die "patina debug: exit $dst, no session.json: $(tail -5 "$run.debug")"
}

# identical RUNDIR: the session ended as the recorded run.
identical() {
    [ "$dst" = 0 ] && [ "$(field "$1/debug/session.json" identical)" = True ] \
        || die "$1: not identical (exit $dst): $(tail -3 "$1.debug")"
}

# gdbpy: a gdb script's python lines print FACT KEY VALUE; fact RUNDIR KEY: the value.
fact() {
    local v
    v=$(awk -v k="$2" '$1 == "FACT" && $2 == k { $1 = ""; $2 = ""; sub(/^  /, ""); print; exit }' "$1.gdb")
    [ -n "$v" ] || die "$1: gdb printed no fact $2: $(tail -8 "$1.gdb")"
    echo "$v"
}
