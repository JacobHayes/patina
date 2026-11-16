# 7. JIT label: rdrand written into anonymous memory made executable runs unpatched; the run
# completes with unscanned_exec_mappings >= 1 and the value differs between runs of one seed.
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
[ "$d" -ge 2 ] || die "the unscanned rdrand gave the same value in 3 runs"
echo "the labelled gap: $d distinct values in 3 runs of seed 1"
# The other mapping paths: the same bytes in a file, mapped executable (mmap hook) or made
# executable later (mprotect hook): patched, so the value is the seed's, identical over runs;
# mapped shared: not patched (it would write into the file), labelled like the JIT.
for m in file-mmap file-mprotect file-shared; do
    for i in 1 2; do
        patina_run "$o/$m-$i" 1 insn-jit "$m"
        [ "$(field "$o/$m-$i/result.json" outcome)" = ok ] || die "$m: $(field "$o/$m-$i/result.json" message)"
    done
    f=$o/$m-1/result.json
    echo "$m: $(cat "$o/$m-1/inc-0/stdout") / $(cat "$o/$m-2/inc-0/stdout"); patched $(field "$f" counters.insn.patched_sites.rdrand), emulated $(field "$f" counters.insn.emulated.rdrand), unscanned $(field "$f" labels.unscanned_exec_mappings)"
    if [ "$m" = file-shared ]; then
        [ "$(field "$f" labels.unscanned_exec_mappings)" -ge 1 ] && [ "$(field "$f" counters.insn.patched_sites.rdrand)" = 0 ] || die "$m: not labelled"
    else
        cmp -s "$o/$m-1/inc-0/stdout" "$o/$m-2/inc-0/stdout" || die "$m: runs differ"
        [ "$(field "$f" counters.insn.emulated.rdrand)" = 1 ] && [ "$(field "$f" labels.unscanned_exec_mappings)" = 0 ] || die "$m: not patched"
    fi
done
