# Evidence (docs/EVIDENCE.md, scheduling points): stock Go's spin-wait stalls at the default CPU
# count, with and without spin probes (pause points on throughout). W4 (go-static all) and the
# reproducer go-sweep over seeds 1-RUNTIMES_STALL_SEEDS (100), each with spin probes on and off;
# go-sweep also at --cpus 24 with probes on and off. stall-ms = 3000. With probes on every run
# must be ok; a run that is neither ok nor compute-stall fails the script.
#@ tier=evidence budget=1200 slots=8
. "$(dirname "$0")/lib.inc"
export SWEEP_JOBS=8
G=go-static
N=${RUNTIMES_STALL_SEEDS:-100}
for spec in "w4 /guest/go-static all" "sweep /guest/go-sweep" "sweep24 --cpus 24 -- /guest/go-sweep"; do
    name=${spec%% *}; rest=${spec#* }
    case $rest in --cpus*) opts=${rest%% -- *}; cmd=${rest#* -- } ;; *) opts=""; cmd=$rest ;; esac
    for probes in true false; do
        n=$name-probes-$probes
        # shellcheck disable=SC2086
        t=$(PATINA_TEST_STALL_MS=3000 PATINA_TEST_SPIN_PROBES=$probes sweep "$n" $G 1-"$N" -- $opts -- $cmd | cut -d';' -f1)
        echo "$name, spin probes $probes: ok $(count "$n" ok), compute-stall $(stalls "$n") of $N ($t)"
        other=$(( N - $(count "$n" ok) - $(stalls "$n") ))
        [ "$other" = 0 ] || fail "$n: $other outcomes other than ok/compute-stall"
        [ "$probes" = false ] || [ "$(count "$n" ok)" = "$N" ] || fail "$n: not every seed ok with spin probes"
    done
done
finish
