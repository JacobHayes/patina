#!/bin/sh
# tests/guests.sh: build the guests once per source change and print the directory of the set.
#
# Each tests/guests/<name>/ (and tests/determinism/attack/, tests/sandbox/guests/) is built by
# its build.sh into $PATINA_CHECK_DIR/guests/cache/<name>-<key>, where <key> hashes that
# directory's files, the machine and the compiler versions. A cache entry is built once, then made
# read-only. The set for this tree, $PATINA_CHECK_DIR/guests/sets/<key of all keys>/, holds
# hard links:
#   guests/      every guest-style build (build.sh writes into its argument)
#   workloads/   whole-program workloads, one directory each (go-static, cpython, fjall-harness, ...)
#   attack/      the determinism attack guests
#   sandbox/     the sandbox guests
# so a set never changes once made: checks of different trees, in parallel, read their own.
# Builds take the build lock and share PATINA_BUILD_DIR (cargo targets, the Go cache). Sets
# and cache entries unused for 3 days are deleted.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
base=${PATINA_CHECK_DIR:-$root/target/patina-check}
export PATINA_BUILD_DIR="$base/build"
cache=$base/guests/cache
sets=$base/guests/sets
mkdir -p "$cache" "$sets" "$PATINA_BUILD_DIR"

workload_style=" c-sqlite cpython fjall-harness go-static rust-threads-files shell-pipeline tokio-mt "
# During the arm64 port the guests of the parts not ported yet are not built there: branch
# counters (counters), the SDKs and compute points (sdk, compute, examples).
case $(uname -m) in
    x86_64) skipped="" ;;
    *) skipped=" counters sdk compute examples " ;;
esac
tools=$( (uname -m; gcc --version | head -1; rustc -V; go version; clang --version 2>/dev/null | head -1) | sha256sum | cut -c1-16)

# key DIR: hash of the files under the directory, the repository paths its `deps` file lists
# (sources it builds from outside it, such as the SDKs), and the tool versions
key() {
    (cd "$root" && { find "$1" -type f -not -path '*/target/*'; [ ! -f "$1/deps" ] || find $(cat "$1/deps") -type f -not -path '*/target/*'; } |
        LC_ALL=C sort | xargs sha256sum; echo "$tools") |
        sha256sum | cut -c1-16
}

# name BUILD_SH: the entry name of a build script
name() {
    case $1 in
        "$root"/tests/determinism/attack/build.sh) echo attack ;;
        "$root"/tests/sandbox/guests/build.sh) echo sandbox ;;
        *) basename "$(dirname "$1")" ;;
    esac
}

entries=""
for b in "$root"/tests/guests/*/build.sh "$root"/tests/determinism/attack/build.sh "$root"/tests/sandbox/guests/build.sh; do
    rel=$(dirname "$b"); rel=${rel#"$root"/}
    case $skipped in *" $(name "$b") "*) continue ;; esac
    entries="$entries $(name "$b")-$(key "$rel")"
done
setkey=$(echo "$entries" | sha256sum | cut -c1-16)
set=$sets/$setkey

if [ ! -d "$set" ]; then
    exec 9>"$base/guests/build.lock"
    flock 9
    for e in $entries; do
        [ -d "$cache/$e" ] && continue
        n=${e%-*}
        case $n in
            attack) b=$root/tests/determinism/attack/build.sh ;;
            sandbox) b=$root/tests/sandbox/guests/build.sh ;;
            *) b=$root/tests/guests/$n/build.sh ;;
        esac
        tmp=$cache/.tmp-$e
        chmod -R u+w "$tmp" 2>/dev/null || true
        rm -rf "$tmp"; mkdir -p "$tmp"
        t0=$(date +%s)
        sh "$b" "$tmp" >"$tmp.log" 2>&1 || { tail -20 "$tmp.log" >&2; echo "guests.sh: $b failed (log $tmp.log)" >&2; exit 1; }
        chmod -R a-w "$tmp"
        mv "$tmp" "$cache/$e"
        rm -f "$tmp.log"
        echo "guests.sh: built $n ($(( $(date +%s) - t0 )) s)" >&2
    done
    tmp=$sets/.tmp-$setkey
    rm -rf "$tmp"; mkdir -p "$tmp/guests" "$tmp/workloads" "$tmp/attack" "$tmp/sandbox"
    for e in $entries; do
        n=${e%-*}
        case $n in
            attack) cp -al "$cache/$e/." "$tmp/attack/" ;;
            sandbox) cp -al "$cache/$e/." "$tmp/sandbox/" ;;
            *) case $workload_style in
                   *" $n "*) cp -al "$cache/$e/$n" "$tmp/workloads/$n" ;;
                   *) cp -al "$cache/$e/." "$tmp/guests/" ;;
               esac ;;
        esac
        chmod u+w "$tmp/guests" "$tmp/attack" "$tmp/sandbox"
    done
    chmod a-w "$tmp/guests" "$tmp/workloads" "$tmp/attack" "$tmp/sandbox"
    mv "$tmp" "$set"
    # Unused for 3 days: deleted (every check touches its set and the entries it uses).
    for old in $(find "$sets" "$cache" -mindepth 1 -maxdepth 1 -mtime +3 2>/dev/null); do
        chmod -R u+w "$old" 2>/dev/null || true
        rm -rf "$old"
    done
    flock -u 9
fi
touch "$set"
for e in $entries; do touch "$cache/$e"; done
echo "$set"
