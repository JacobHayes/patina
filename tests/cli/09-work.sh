# 9. The work tree at the guest path a program expects (--work DIR:GUEST): it starts with
#    DIR's files, is the working directory, and is the tree crashes model. A machine crash
#    after a failed fsync loses an acknowledged record there as at /work (the same outcome and
#    message; the digest differs by the paths the records name). A mount that would shadow the sandbox's own paths is refused, naming
#    why; one under /etc or /tmp is not.
#@ tier=quick budget=10
. "$(dirname "$0")/lib.inc"
d=$RUNS/work
mkdir -p "$d/init"
echo seeded >"$d/init/seed"
prun "$d/sh" --seed 1 --work "$d/init:/var/lib/app" -- /bin/sh -c 'pwd; cat seed; echo x >new; ls'
[ "$st" = 0 ] || die "--work DIR:GUEST: exit $st ($(tail -3 "$d/sh.txt"))"
[ "$(cat "$d/sh/inc-0/stdout")" = "$(printf '/var/lib/app\nseeded\nnew\nseed')" ] ||
    die "--work DIR:GUEST: $(cat "$d/sh/inc-0/stdout")"
echo "--work $d/init:/var/lib/app: the guest starts there, with seed"

# The crash model: as tests/faults/09-failed-fsync.sh, at /work and at /var/lib/app.
g() { timeout 60 "$PATINA" run --seed 1 --mount "$PATINA_GUESTS":/guest:copy --fault fsync-error-at=3 "$@" >/dev/null 2>&1 || true; } # lint-allow: seed — the fault is the 3rd fsync, on every seed
g --out "$d/probe" -- /guest/ack-log retry
set -- $(python3 -I "$(dirname "$0")/../faults/lib/faults.py" point-after "$d/probe/inc-0" Fsync acks 1)
at=$1 aseq=$2
for w in /work /var/lib/app; do
    g --out "$d/crash$(echo "$w" | tr / -)" --work ":$w" --fault crash-at="$at" -- /guest/ack-log retry
done
a=$d/crash-work b=$d/crash-var-lib-app
for o in "$a" "$b"; do
    [ "$(field "$o/result.json" outcome)" = failure ] && field "$o/result.json" message | grep -q acked-record-lost ||
        die "$o: $(field "$o/result.json" outcome) $(field "$o/result.json" message)"
    [ "$(jq '.crashes[0].seq' "$o/result.json")" = "$aseq" ] || die "$o: crashed at seq $(jq '.crashes[0].seq' "$o/result.json"), not after the acks fsync at seq $aseq"
done
lhs=$(field "$a/result.json" message); rhs=$(field "$b/result.json" message)
[ "$lhs" = "$rhs" ] ||
    die "the crash differs at /var/lib/app: $(field "$b/result.json" message)"
echo "a machine crash loses the acknowledged record at /var/lib/app as at /work: $(field "$b/result.json" message)"

# Mounts: under /etc and /tmp, yes; over the sandbox's own paths, no, naming why.
prun "$d/etc" --seed 1 --mount "$d/init:/etc/app" --mount "$d/init:/tmp/in" -- /bin/cat /etc/app/seed /tmp/in/seed
[ "$st" = 0 ] || die "mounts under /etc and /tmp: exit $st ($(tail -3 "$d/etc.txt"))"
for bad in /etc/passwd /usr/local /proc/x /tmp; do
    prun "$d/bad" --seed 1 --mount "$d/init:$bad" -- /bin/true
    [ "$st" = "$(exit_of error)" ] && grep -q "$bad" "$d/bad.txt" || die "--mount at $bad: exit $st: $(cat "$d/bad.txt")"
    echo "--mount at $bad: $(cat "$d/bad.txt")"
    rm -rf "${d:?}/bad"
done
