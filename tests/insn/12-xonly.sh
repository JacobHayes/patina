# 12. An image whose code segment is execute-only (insn-xonly: its R+X segment's read flag
# cleared after linking): the loader patches its sites (the segment is still writable then) and
# the patched spin hint is emulated where it runs (a pause point taken), so the run ends ok
# with the program's own output.
#@ tier=quick budget=10
. "$(dirname "$0")/lib.inc"
o=$RUNS/12-xonly
patina_run "$o" 1 insn-xonly
[ "$(field "$o/result.json" outcome)" = ok ] || die "insn-xonly: $(field "$o/result.json" message)"
grep -qx 'xonly ok' "$o/inc-0/stdout" || die "insn-xonly printed $(cat "$o/inc-0/stdout")"
n=$(field "$o/result.json" sched.pause_points)
[ "$n" -ge 1 ] || die "the patched spin hint was not taken: pause_points $n"
echo "execute-only code: $(field "$o/result.json" counters.insn.patched_sites.pause) sites patched, $n pause point(s) taken, ok"
