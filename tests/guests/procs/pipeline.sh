#!/bin/sh
# W6 shell-pipeline: run as `sh pipeline.sh` and `bash pipeline.sh`. Lines that depend on
# time, PIDs or temporary names start with "~ " (masked when compared with a native run).
set -eu
dir=$(mktemp -d)
echo "~ tmpdir $dir"
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
for i in 1 2 3 4 5; do echo "file $i" >"tree/a/f$i.txt"; done
echo deep >tree/a/b/deep.txt
echo other >tree/c/other.txt
echo "find|sort|xargs: $(find tree -type f | sort | xargs cat | tr '\n' ',')"
echo "xargs -n2: $(find tree -name '*.txt' | sort | xargs -n2 echo | wc -l) lines"
(sleep 0.2; echo "bg one done") >bg1.out &
p1=$!
(echo "bg two done") >bg2.out &
p2=$!
echo "~ background pids $p1 $p2"
wait
cat bg1.out bg2.out
(exit 3) &
p3=$!
if wait "$p3"; then st=0; else st=$?; fi
echo "wait status: $st"
tar cf t.tar tree
echo "tar list: $(tar tf t.tar | sort | tr '\n' ' ')"
mkdir out
tar xf t.tar -C out
diff -r tree out/tree && echo "tar extract: identical"
ls -l tree/a | sed 's/^/~ /'
echo "ls names: $(ls tree/a | tr '\n' ' ')"
echo "~ date $(date)"
echo "~ date +%s $(date +%s)"
t=$(mktemp)
echo "~ mktemp $t"
echo payload >"$t"
echo "mktemp content: $(cat "$t")"
sleep 0.1
echo "after sleep"
x=0
while [ "$x" -lt 20 ]; do x=$((x + 1)); done
echo "loop: $x"
case "$(uname -s)" in Linux) echo "uname: Linux" ;; *) echo "uname: other" ;; esac
echo "pipefail-free: $(false | true; echo $?)"
cd /
rm -rf "$dir"
echo "done"
