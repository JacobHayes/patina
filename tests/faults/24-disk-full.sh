# 24. A full disk is a small disk: with [run] disk-mb 4, a program appending fsynced records to
#     /work meets ENOSPC where the records fill the 4 MiB, the same in every run of a seed;
#     after a machine crash part way, the next boot keeps the synced records and fills the
#     rest (kept + written fill the disk), the operation log's self-check passes and the run
#     replays identically; a node's own disk-mb, a range, is drawn per seed within it.
#@ tier=quick budget=10 slots=0.5
. "$(dirname "$0")/lib/common.inc"
o=$RUNS/24-disk-full
mkdir -p "$o"
printf '[run]\ndisk-mb = 4\n' >"$o/run.toml"
records=$(((4 << 20) / 4096))
go() {
    out=$1; shift
    rm -rf "${out:?}"
    timeout 600 "$PATINA" run --config "$o/run.toml" --out "$out" --mount "$PATINA_GUESTS":/guest "$@" >/dev/null 2>"$out.err" \
        || [ -f "$out/result.json" ] || die "patina run $*: no result.json ($(tail -2 "$out.err"))"
    [ "$(field "$out/result.json" outcome)" = ok ] || die "$*: $(field "$out/result.json" message)"
}
full() { sed -n 's/^full after //p' "$1"; }
kept() { sed -n 's/^kept //p' "$1"; }

go "$o/a" --seed 1 -- python3 /guest/diskfull.py
go "$o/b" --seed 1 -- python3 /guest/diskfull.py
n=$(full "$o/a/inc-0/stdout")
[ "$n" -gt 0 ] && [ "$n" -le "$records" ] || die "filled $n records of $records"
[ "$(field "$o/a/result.json" digest)" = "$(field "$o/b/result.json" digest)" ] || die "two runs of seed 1 differ"
[ "$(field "$o/a/result.json" tmpfs.enospc)" -ge 1 ] || die "no ENOSPC counted"

# A crash part way through the fill: the second boot keeps what was synced and fills the rest.
at=$((n * 3 / 2))
go "$o/c" --seed 1 --fault crash-at=$at -- python3 /guest/diskfull.py
k=$(kept "$o/c/inc-1/stdout"); m=$(full "$o/c/inc-1/stdout")
[ -n "$k" ] && [ "$k" -gt 0 ] && [ "$((k + m))" = "$n" ] || die "after the crash: kept $k, then $m more, of $n"
"$PATINA" replay "$o/c" --out "$o/c-replay" >"$o/c-replay.txt" 2>&1 || true
grep -q '^identical' "$o/c-replay.txt" || die "replay: $(head -1 "$o/c-replay.txt")"

# A node's own disk, drawn per seed from a range within the run's.
printf '[run]\ndisk-mb = 4\n\n[node.a]\ncmd = ["python3", "/guest/diskfull.py"]\ndisk-mb = "1..4"\n' >"$o/node.toml"
sizes=
for s in 1 2 3 4 5 6; do
    rm -rf "${o:?}/n$s"
    timeout 600 "$PATINA" run --seed $s --config "$o/node.toml" --out "$o/n$s" --mount "$PATINA_GUESTS":/guest -- python3 /guest/diskfull.py 1 >/dev/null 2>&1 || true
    r=$(full "$o/n$s/node/a/inc-0/stdout")
    [ -n "$r" ] && [ "$r" -ge 1 ] && [ "$r" -le "$records" ] || die "seed $s: node a filled ${r:-nothing}"
    sizes="$sizes $r"
done
[ "$(tr ' ' '\n' <<<"$sizes" | sort -u | grep -c .)" -gt 1 ] || die "node disk sizes do not vary by seed:$sizes"
echo "disk full: $n records into 4 MiB, the same twice; after a crash $k kept and $m more; node disk sizes by seed:$sizes"
