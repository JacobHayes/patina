# 1. Machines: isolation and scripted cuts. Main and machine b (tests/guests/machines/iso.py) each
# see their own disk, /tmp, /dev/shm, System V shared memory and hostname; b's loopback
# listener is not on its address; b's processes are ESRCH to main's kill and absent from
# its /proc, and getsid/getpgid do not find them; b gets EPERM for a control call and cannot
# change its view; each machine has its own abstract AF_UNIX names, and names read back carry no
# prefix; UDP between machines carries the machines' addresses; b's first process starts with the
# main's process state; a cut stops a connect and loses a datagram, and a heal lets both
# through; a socket's TCP_SYNCNT and TCP_USER_TIMEOUT set its own limits across a cut. The link
# faults act on main's links like any machine's, and `[machine.main] faults = false` leaves main
# out. A machine given with --machine whose command
# cannot run ends the run at once, naming the machine. Identical under verify --vary cpu,aslr,sandbox,repeat
# (and load in the area tier).
# What is not available yet is refused, naming the feature; without machines a control call is
# EINVAL, from a shell script too (`patina ctl`, as in a run with machines). The C, Rust and Go SDKs' control calls answer main and give
# another machine EPERM (the Rust and Go SDKs' in the area tier).
#@ tier=quick budget=20 slots=0.5
. "$(dirname "$0")/lib.inc"
o=$RUNS/01-isolation; mkdir -p "$o"
# Quick: no load generator. Its two threads spin for the whole verify, most of this
# script's CPU time; on a slow, busy runner the script, which holds half a CPU, was starved past
# its budget.
[ "${CHECK_TIER:-}" != quick ] || VARY=cpu,aslr,sandbox,repeat
conf "$o/iso.toml" b python3 /guest/iso.py machine
verify_ok "$o/iso" 1 2 --config "$o/iso.toml" -- python3 /guest/iso.py main
sed 's/^/    /' "$o/iso/run-0/boot-1/stdout"
r=$o/iso/run-0
[ "$(field "$r/result.json" machines.list.1.name)" = b ] || die "result.json: machine b"
[ "$(field "$r/result.json" machines.list.1.address)" = 10.0.0.2 ] || die "result.json: b's address"
[ "$(field "$r/result.json" machines.net.heals)" -ge 1 ] || die "result.json: no heal counted"
[ -f "$r/machine/b/boot-1/stdout" ] || die "no stdout for machine b"

# The link faults act on main's links like any machine's; main with faults = false is left out.
run_ok "$o/links" 1 --config "$o/iso.toml" --fault net-reset-permille=1 -- python3 /guest/iso.py main
e=$(field "$o/links/result.json" faults.counts.net-reset.eligible)
[ "$e" -gt 0 ] || die "net-reset not drawn on main's links"
on=$(field "$o/links/result.json" faults.on)
cp "$o/iso.toml" "$o/drv.toml"; main_unfaulted "$o/drv.toml"
run_ok "$o/links-drv" 1 --config "$o/drv.toml" --fault net-reset-permille=1 -- python3 /guest/iso.py main
d=$(field "$o/links-drv/result.json" faults.on)
[ "$d" != "$on" ] && ! grep -q main <<<"$d" || die "faults = false: main still faulted: $d"
echo "link faults: $e reads drawn on main's links; with main's faults = false, faults on $d"
c=$(run "$o/noexec" 1 --machine a=/etc/hostname -- /bin/true)
stop=$(field "$o/noexec/result.json" stop); m=$(field "$o/noexec/result.json" message)
[ "$c" = error ] && [ "$stop" = exec ] && grep -q 'machine a' <<<"$m" || die "a machine that cannot run: $c ($stop): $m"
echo "--machine a=/etc/hostname: $c ($stop): $m"

# Not available yet: each refused before the run, naming what it asked for.
refused() {
    what=$1; shift
    st=0; "$PATINA" run --out "$o/refused" --mount "$PATINA_GUESTS":/guest:copy "$@" -- /bin/true >/dev/null 2>"$o/refused.err" || st=$?
    [ "$st" != 0 ] && [ ! -e "$o/refused" ] || die "$what: not refused"
    grep -q -- "$what" "$o/refused.err" || die "$what: the refusal does not name it: $(cat "$o/refused.err")"
    echo "refused: $what"
}
# Only the disk and memory keys are a machine's own; a scope names machines of the run.
refused "no machine nope" --config "$o/iso.toml" --fault fs-error-permille=10@nope
printf '[machine.c]\nrun = ["/bin/true"]\n[machine.c.faults]\nnet-drop-permille = 5\n' >"$o/own.toml"
refused machine.c.faults --config "$o/own.toml"
printf '[machine.c]\nrun = ["/bin/true"]\nfaults = "net"\n' >"$o/faults.toml"
refused machine.c.faults --config "$o/faults.toml"
for taken in rest localhost; do
    printf '[machine.%s]\nrun = ["/bin/true"]\n' "$taken" >"$o/taken.toml"
    refused "machine.$taken" --config "$o/taken.toml"
done
refused "machine.main" --machine main=/bin/true

# Without machines: no network to act on.
run_ok "$o/none" 1 -- python3 -c '
import errno, sys
sys.path.insert(0, "/guest")
import patina
try:
    patina.control("heal")
except OSError as e:
    print("done" if e.errno == errno.EINVAL else e)'
[ "$(cat "$o/none/boot-1/stdout")" = done ] || die "patina ctl without machines"
[ "$(field "$o/none/result.json" machines 2>/dev/null || echo none)" = none ] || die "machines in a run without them"
echo "without machines: a control call is refused"

# From a shell script, in a run without machines and in one with: `patina` is on the PATH and
# `heal` answers as above; and although the host's PATH has a patina too, no hint calls the
# guest's missing (env tries each PATH directory in turn, where a shell looks first).
cat >"$o/ctl.sh" <<'EOF'
st=0; env patina ctl heal 2>/dev/null || st=$?
echo "heal: $st"
EOF
rm -f "$o/one.toml"
conf "$o/one.toml" c sleep 1  # lint-allow: sleep — the guest's, in virtual time
for k in none one; do
    cfg=(); [ $k = none ] || cfg=(--config "$o/one.toml")
    PATH="$(dirname "$PATINA"):$PATH" run_ok "$o/sh-$k" 1 --faults disk "${cfg[@]}" --mount "$o":/s -- sh /s/ctl.sh
    want=2; [ $k = none ] || want=0
    [ "$(cat "$o/sh-$k/boot-1/stdout")" = "heal: $want" ] || die "sh, machines $k: $(cat "$o/sh-$k/boot-1/stdout")"
    [ "$(jq -r '[.missing[]? | select(.name == "patina")] | length' "$o/sh-$k/result.json")" = 0 ] || die "sh, machines $k: patina is called missing"
done
echo "from a shell script: patina ctl answers with and without machines; patina is not called missing"

# The C SDK's control call: answers from main and from another machine.
conf "$o/ctl.toml" c /guest/ctl machine
run_ok "$o/ctl" 1 --config "$o/ctl.toml" -- /guest/ctl
d=$(cat "$o/ctl/boot-1/stdout"); n=$(cat "$o/ctl/machine/c/boot-1/stdout")
want="partition main c: ok
heal --from main --to c: ok
partition main nobody: ENOENT
net cut main c: EINVAL
pause c: ok
pause c: EALREADY
resume c: ok
resume c: EALREADY
pause main: EINVAL
clock c +1s: ok
clock main +1s: EINVAL"
[ "$d" = "$want" ] || die "C control from main: $d"
[ "$n" = "heal: EPERM" ] || die "C control from another machine: $n"
echo "C control: main's answered, another machine's EPERM"

# The Rust and Go SDKs' control calls: the same answers (errno 2 ENOENT, 1 EPERM).
[ "${CHECK_TIER:-}" != quick ] || exit 0
for sdk in rs go; do
    rm -f "$o/ctl-$sdk.toml"
    conf "$o/ctl-$sdk.toml" c /guest/sdk-$sdk control machine
    run_ok "$o/ctl-$sdk" 1 --config "$o/ctl-$sdk.toml" -- /guest/sdk-$sdk control
    d=$(cat "$o/ctl-$sdk/boot-1/stdout"); n=$(cat "$o/ctl-$sdk/machine/c/boot-1/stdout")
    [ "$d" = "partition main c: ok
heal: ok
partition main nobody: errno 2" ] || die "$sdk control from main: $d"
    [ "$n" = "heal: errno 1" ] || die "$sdk control from another machine: $n"
done
echo "Rust and Go control: main's answered, another machine's EPERM"
