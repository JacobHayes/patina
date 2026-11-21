#!/bin/bash
# Throwaway measurement: per-run phases and walls of main's build and this one.
set -euo pipefail
new=$1 old=$2 guests=$3
export XDG_CACHE_HOME=$RUNNER_TEMP/xdg
printf '[sched]\npreempt = "traps"\n' > $RUNNER_TEMP/traps.toml
echo "== cpu: $(grep -m1 -i 'model name\|CPU part' /proc/cpuinfo) nproc $(nproc)"
for i in 1 2; do  # warm both caches
  for p in $new $old; do $p run --seed 1 --out $RUNNER_TEMP/w$i$RANDOM -- /usr/bin/python3 -c pass >/dev/null 2>&1 || true; $p run --seed 1 --out $RUNNER_TEMP/w$i$RANDOM --mount $guests:/guest -- /guest/hello-dyn >/dev/null 2>&1 || true; done
done
for round in 1 2; do
 for p in $old $new; do
  echo "== build $p round $round"
  for g in hello-static hello-dyn; do python3 tiny.py $p $guests 30 $g; done
  python3 tiny.py $p $guests 30 hello-dyn --config $RUNNER_TEMP/traps.toml
  python3 py.py $p 15 -- /usr/bin/python3 -c pass
  python3 py.py $p 15 --config $RUNNER_TEMP/traps.toml -- /usr/bin/python3 -c pass
 done
done
echo "== phases of the new build"
python3 marks.py $new $guests 30 hello-dyn
python3 marks.py $new - 15 /usr/bin/python3 -c pass
