#!/bin/sh
# Build the process guests into $1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
cc=${CC:-gcc}
$cc -O1 -static -o "$out/exec-show-static" "$here/exec-show.c"
$cc -O1 -static-pie -fPIE -o "$out/exec-show-spie" "$here/exec-show.c"
$cc -O1 -o "$out/exec-show-dyn" "$here/exec-show.c"
rustc -O --edition 2021 -o "$out/exec-show-rs" "$here/exec-show.rs"
gocache=$PATINA_BUILD_DIR/gocache
(cd "$here/exec-show-go" && GOCACHE=$gocache GOTOOLCHAIN=local CGO_ENABLED=0 go build -o "$out/exec-show-go" .)
for g in exec-matrix fork-exec exit-order zombies xsig daemons shm sysv-shm spawn-cost; do
    $cc -O1 -pthread -o "$out/$g" "$here/$g.c"
done
# Files the exec matrix runs: scripts, and the failure cases.
f=$out/exec-files
mkdir -p "$f" "$f/adir"
for s in show.sh show.py show-arg.py; do
    cp "$here/$s" "$f/$s"
    chmod 755 "$f/$s"
done
printf '#!/bin/sh\necho no execute bit\n' >"$f/noexec.sh"
chmod 644 "$f/noexec.sh"
printf 'just text, no interpreter line\n' >"$f/plain.txt"
chmod 755 "$f/plain.txt"
for s in pipeline.sh subproc.py; do
    cp "$here/$s" "$f/$s"
    chmod 755 "$f/$s"
done
