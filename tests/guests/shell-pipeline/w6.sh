#!/bin/sh
# W6 shell-pipeline: run as `sh w6.sh` and `bash w6.sh`, over the system coreutils.
# Lines that depend on time, PIDs or temporary names start with "~ " (masked when compared
# with a native run; identical between patina runs of one seed). Errors stop the script
# (`set -e`). The last line is "done".
set -eu
dir=$(mktemp -d)
echo "~ mktemp -d $dir"
cd "$dir"
echo "pipeline: $(seq 1 2000 | sort -rn | head -3 | tr '\n' ' ')"
echo "count: $(seq 1 500 | grep -c 7)"
n=$(printf 'a\nb\nc\n' | wc -l)
echo "subst: $n lines, nested $(echo "$(echo inner)" | tr a-z A-Z)"
cat <<HERE
here-doc line 1, n=$n
here-doc line 2: $(echo command in here-doc)
HERE
cat <<'RAW' | sed 's/^/raw: /'
no $expansion here
RAW
mkdir -p tree/a/b tree/c
for i in 1 2 3 4 5 6 7 8; do echo "file $i" >"tree/a/f$i.txt"; done
echo deep >tree/a/b/deep.txt
echo other >tree/c/other.txt
echo "find|sort|xargs: $(find tree -type f | sort | xargs cat | tr '\n' ',')"
echo "find|sort|xargs -n2: $(find tree -name '*.txt' | sort | xargs -n2 echo | wc -l) lines"
echo "xargs -P4 wc: $(find tree -name 'f*.txt' | sort | xargs -P4 -n1 wc -c | awk '{s+=$1} END {print s}')"
(sleep 0.2; echo "bg one done") >bg1.out &
p1=$!
(echo "bg two done") >bg2.out &
p2=$!
(seq 1 300 | sort -n | tail -1 >bg3.out) &
echo "~ background pids $p1 $p2"
wait
cat bg1.out bg2.out bg3.out
(exit 3) &
p3=$!
if wait "$p3"; then st=0; else st=$?; fi
echo "wait status: $st"
tar cf t.tar tree
echo "tar list: $(tar tf t.tar | sort | tr '\n' ' ')"
mkdir out
tar xf t.tar -C out
diff -r tree out/tree && echo "tar extract: identical"
echo "tar sha256: $(tar cf - -C out tree --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner | sha256sum | cut -c1-16)"
ls -l --time-style=full-iso tree/a | sed 's/^/~ ls -l /'
ls -l --time-style=+%s out/tree/a | sed 's/^/~ ls -l out /'
echo "ls names: $(ls tree/a | tr '\n' ' ')"
echo "ls -t after touch -d: $(touch -d @1000 tree/a/f3.txt && ls -t tree/a | tail -1)"
echo "~ date $(date)"
t0=$(date +%s)
echo "~ date +%s $t0"
t=$(mktemp)
echo "~ mktemp $t"
echo payload >"$t"
echo "mktemp content: $(cat "$t")"
sleep 5
t1=$(date +%s)
echo "sleep 5: elapsed >= 5: $([ $((t1 - t0)) -ge 5 ] && echo yes || echo no)"
x=0
while [ "$x" -lt 20 ]; do x=$((x + 1)); done
echo "loop: $x"
case "$(uname -s)" in Linux) echo "uname: Linux" ;; *) echo "uname: other" ;; esac
echo "pipefail-free: $(false | true; echo $?)"
echo "sha256: $(seq 1 1000 | sha256sum | cut -c1-16)"
cd /
rm -r "$dir" "$t"
echo "done"
