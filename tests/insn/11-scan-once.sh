# 11. A read-only file's mapping is scanned once per run: a shell that runs the same program
# twice maps the program and its libraries again in each child, and those mappings take the
# first scan's verdicts (scan.reused_mappings). Catches the per-run scan silently turning into
# a scan per process, which costs whole seconds on a large program and changes no digest.
#@ tier=quick budget=15
. "$(dirname "$0")/lib.inc"
o=$RUNS/11-scan-once
patina_run "$o" 1 /bin/sh -c '/bin/true; /bin/true'
[ "$(field "$o/result.json" outcome)" = ok ] || die "$(field "$o/result.json" message)"
scan=$(field "$o/result.json" counters.insn.scan)
echo "scan: $scan"
n=$(field "$o/result.json" counters.insn.scan.reused_mappings)
[ "$n" -ge 2 ] || die "only $n mappings took an earlier scan's verdicts: $scan"
