# Run as root (sudo), the guest sees what it sees run as an ordinary user: the same digest for
# the crosshost guest, which stats host and sandbox files and reads the mount table. SKIP where
# `sudo -n` cannot run. Each sudo call is recorded in $PATINA_CHECK_DIR/sudo-log.txt; its files
# are given back to the caller and its runtime cache is under $RUNS.
#@ tier=quick budget=20 slots=1
. "$(dirname "$0")/lib/common.inc"
if ! sudo -n true 2>/dev/null; then
    echo "SKIP: sudo -n cannot run here"
    exit 0
fi
out=$RUNS/root
mkdir -p "$out"
log=$PATINA_CHECK_DIR/sudo-log.txt
run() { # run NAME [sudo...]
    n=$1; shift
    timeout 120 "$@" "$PATINA" run --seed 1 --out "$out/$n" --mount "$G17":/guest:copy -- /guest/crosshost >"$out/$n.txt" 2>&1 || true
}
run user env
echo "$(date -Iseconds) sudo -n patina run (tests/sandbox/10-root.sh)" >>"$log"
st=0
run root sudo -n env XDG_CACHE_HOME="$out/cache" || st=$?
sudo -n chown -R "$(id -u):$(id -g)" "$out" || die "chown back: $?"
echo "$(date -Iseconds) sudo -n chown -R $(id -u):$(id -g) $out (tests/sandbox/10-root.sh)" >>"$log"
for n in user root; do
    [ "$(class "$out/$n")" = ok ] || die "$n: $(class "$out/$n") ($(tail -2 "$out/$n.txt"))"
done
a=$(digest "$out/user") b=$(digest "$out/root")
[ "$a" = "$b" ] || die "as root the guest sees otherwise: digest $b, as a user $a"
echo "as root (sudo) and as a user: digest $a"
