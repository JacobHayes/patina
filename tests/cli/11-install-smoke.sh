# 11. Install from a local release artifact: this build of patina, packed as this machine's
#     release archive with its SHA256SUMS, installed by install.sh from a file:// release; then
#     scripts/install-smoke.sh with the installed patina (the README's first examples built
#     outside the checkout: found, fixed, replayed). SKIP where AppArmor restricts unprivileged
#     user namespaces and the installed path has no AppArmor profile.
#@ tier=release budget=30
. "$(dirname "$0")/lib.inc"
root=$(cd "$(dirname "$0")/../.." && pwd)
case $(uname -m) in aarch64) t=aarch64-unknown-linux-musl ;; *) t=x86_64-unknown-linux-musl ;; esac
d=$RUNS/release
mkdir -p "$d/dist"
tar -czf "$d/dist/patina-$t.tar.gz" -C "$(dirname "$PATINA")" patina -C "$root" LICENSE-APACHE
(cd "$d/dist" && sha256sum "patina-$t.tar.gz" >SHA256SUMS)
# lint-allow: plain-sh — install.sh runs as users run it: piped into sh
PATINA_RELEASE_URL="file://$d/dist" sh "$root/install.sh" --prefix "$d/prefix" >"$d/install.txt" 2>&1 ||
    die "install.sh: $(tail -5 "$d/install.txt")"
echo "installed patina-$t.tar.gz: $(grep -m1 . "$d/install.txt")"
# A host that restricts unprivileged user namespaces admits patina only at a path with an
# AppArmor profile; the per-run prefix has none (doctor's case: user namespaces refused, the
# restriction on, not in a container). Only that refusal skips; any other failure fails below.
st=0
timeout 60 "$d/prefix/bin/patina" doctor --format json >"$d/doctor.json" 2>"$d/doctor.err" || st=$?
container=0
if [ -e /.dockerenv ] || [ -e /run/.containerenv ]; then container=1; fi
why=$(python3 -I - "$d/doctor.json" "$st" "$container" <<'PY'
import json, sys
st, container = int(sys.argv[2]), sys.argv[3] == "1"
if st == 0 or container:
    sys.exit(0)
r = json.load(open(sys.argv[1]))
ns = [c for c in r["checks"] if c["name"] == "user namespaces"]
refused = ns and not ns[0]["ok"] and any(e in ns[0]["detail"] for e in ("(os error 1)", "(os error 13)"))
if refused and r["host"].get("apparmor_restrict_unprivileged_userns") == "1":
    print("this host restricts unprivileged user namespaces and the installed path has no AppArmor profile (patina doctor: %s)" % ns[0]["detail"])
PY
)
if [ -n "$why" ]; then
    echo "SKIP: $why"
    exit 0
fi
# The smoke's projects live outside this checkout, where its toolchain file does not reach.
RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-$(awk -F'"' '/^channel/ {print $2}' "$root/rust-toolchain.toml")}
PATH="$d/prefix/bin:$PATH" RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN bash "$root/scripts/install-smoke.sh" >"$d/smoke.txt" 2>&1 ||
    die "install-smoke: $(tail -5 "$d/smoke.txt")"
tail -1 "$d/smoke.txt"
