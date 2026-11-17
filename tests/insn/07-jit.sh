# 7. Code made at run time. Anonymous memory made executable is not scanned: the run is labelled
# with unscanned_exec_mappings >= 1 (x86: an rdrand there runs unpatched and its value differs
# between runs of one seed; arm64: a counter read there is still trapped, the same in every
# run, and an RNDR there runs natively: SIGILL on a host without it). The same code in a file,
# mapped executable (mmap hook) or made executable later (mprotect hook), is patched (x86: the
# rdrand's value is the seed's; arm64: its yield is a pause point, its RNDR answered from the
# seed); mapped shared, not patched (it would write into the file) and labelled.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
o=$RUNS/07-jit
for i in 1 2 3; do
    patina_run "$o/r$i" 1 insn-jit
    [ "$(field "$o/r$i/result.json" outcome)" = ok ] || die "run $i: $(field "$o/r$i/result.json" message)"
    u=$(field "$o/r$i/result.json" labels.unscanned_exec_mappings)
    [ "$u" -ge 1 ] || die "run $i: unscanned_exec_mappings $u"
    echo "run $i: $(cat "$o/r$i/inc-0/stdout"), unscanned_exec_mappings $u, digest $(field "$o/r$i/result.json" digest)"
done
d=$(for i in 1 2 3; do cat "$o/r$i/inc-0/stdout"; done | sort -u | wc -l)
if [ "$ARCH" = x86_64 ]; then
    [ "$d" -ge 2 ] || die "the unscanned rdrand gave the same value in 3 runs"
    echo "the labelled gap: $d distinct values in 3 runs of seed 1"
    modes="file-mmap file-mprotect file-shared"
else
    [ "$d" = 1 ] || die "the counter read in anonymous code gave $d values in 3 runs"
    echo "anonymous code: its counter read is trapped (one value in 3 runs)"
    INSN_ARGS="--config $("$PATINA_CFG" emulate-rndr=true)"
    patina_run "$o/anon-rndr" 1 insn-jit anon-rndr
    f=$o/anon-rndr/result.json
    [ "$(field "$f" labels.unscanned_exec_mappings)" -ge 1 ] || die "anon-rndr: not labelled"
    if ! grep -qw rng /proc/cpuinfo; then
        [ "$(field "$f" outcome)/$(field "$f" guest.signal)" = crash/4 ] || die "anon-rndr on a host without RNDR: $(field "$f" outcome) $(field "$f" message)"
    fi
    echo "anonymous RNDR: unpatched, $(field "$f" outcome) $(field "$f" message), labelled"
    modes="file-mmap file-mprotect file-shared file-mmap:rndr file-mprotect:rndr"
fi
for m in $modes; do
    for i in 1 2; do
        # shellcheck disable=SC2046
        patina_run "$o/$m-$i" 1 insn-jit $(echo "$m" | tr : ' ')
        [ "$(field "$o/$m-$i/result.json" outcome)" = ok ] || die "$m: $(field "$o/$m-$i/result.json" message)"
    done
    f=$o/$m-1/result.json
    echo "$m: $(cat "$o/$m-1/inc-0/stdout") / $(cat "$o/$m-2/inc-0/stdout"); patched $(field "$f" counters.insn.patched_sites), emulated $(field "$f" counters.insn.emulated), pause points $(field "$f" sched.pause_points), unscanned $(field "$f" labels.unscanned_exec_mappings)"
    u=$(field "$f" labels.unscanned_exec_mappings)
    case $ARCH/$m in
        x86_64/file-shared) [ "$u" -ge 1 ] && [ "$(field "$f" counters.insn.patched_sites.rdrand)" = 0 ] || die "$m: not labelled" ;;
        x86_64/*) [ "$(field "$f" counters.insn.emulated.rdrand)" = 1 ] && [ "$u" = 0 ] || die "$m: not patched" ;;
        */file-shared) [ "$u" -ge 1 ] && [ "$(field "$f" sched.pause_points)" = 0 ] || die "$m: not labelled" ;;
        */*:rndr) [ "$(field "$f" counters.insn.emulated.rndr)" = 1 ] && [ "$u" = 0 ] || die "$m: not patched" ;;
        *) [ "$(field "$f" sched.pause_points)" -ge 1 ] && [ "$u" = 0 ] || die "$m: not patched" ;;
    esac
    [ "$m" = file-shared ] || cmp -s "$o/$m-1/inc-0/stdout" "$o/$m-2/inc-0/stdout" || die "$m: runs differ"
done
