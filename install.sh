#!/bin/sh
# Install the patina tool from a GitHub release.
#
#   curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh -s -- --version 0.15.0
#
# The copy attached to a release installs that release unless given --version (the release
# workflow writes its version into `default_version`, scripts/stamp-install); this one, the
# latest.
#
# Downloads the release's archive for this machine (a static Linux x86_64 or aarch64 binary),
# checks it against the release's SHA256SUMS, installs <prefix>/bin/patina, then runs `patina doctor`, which names
# anything the host still needs (bwrap, user namespaces) and the command that fixes it. It
# installs no packages and changes no settings.

set -eu

repository="https://github.com/JacobHayes/patina"

usage() {
  cat <<EOF
usage: install.sh [--version X.Y.Z] [--prefix DIR]

  --version X.Y.Z  the release to install (default: $default_version)
  --prefix DIR     install DIR/bin/patina (default: ~/.local)

PATINA_RELEASE_URL names a directory URL that holds the release's files, in
place of the GitHub release (a mirror, or file:// for a local build).
EOF
}

fail() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

default_version=latest
version=$default_version
prefix=
while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || fail "--version takes a release, such as 0.15.0"; version=$2; shift 2 ;;
    --prefix) [ $# -ge 2 ] || fail "--prefix takes a directory"; prefix=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument: $1" ;;
  esac
done
if [ -z "$prefix" ]; then
  [ -n "${HOME:-}" ] || fail "HOME is not set; pass --prefix DIR"
  prefix="$HOME/.local"
fi

system="$(uname -s)/$(uname -m)"
case "$system" in
  Linux/x86_64) target=x86_64-unknown-linux-musl ;;
  Linux/aarch64|Linux/arm64) target=aarch64-unknown-linux-musl ;;
  Darwin/arm64) fail "patina runs on Linux x86_64 and arm64, not macOS; on an Apple Silicon Mac, run it inside a Linux arm64 VM with 4 KiB pages and a 6.12+ kernel" ;;
  Darwin/*) fail "patina runs on Linux x86_64 and arm64, not macOS; on an Intel Mac, run it inside a Linux x86_64 VM" ;;
  *) fail "patina runs on Linux x86_64 and arm64 only, and this machine is $system" ;;
esac

if [ -n "${PATINA_RELEASE_URL:-}" ]; then
  base=${PATINA_RELEASE_URL%/}
elif [ "$version" = latest ]; then
  base="$repository/releases/latest/download"
else
  base="$repository/releases/download/v${version#v}"
fi

if command -v sha256sum >/dev/null 2>&1; then
  check="sha256sum -c"
elif command -v shasum >/dev/null 2>&1; then
  check="shasum -a 256 -c"
else
  fail "neither sha256sum nor shasum is installed, so the download cannot be checked"
fi
for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

if [ "$version" = latest ]; then
  printf 'installing the latest patina release from %s\n' "$base"
else
  printf 'installing patina %s from %s\n' "${version#v}" "$base"
fi

archive="patina-$target.tar.gz"
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
curl -fsSL -o "$work/$archive" "$base/$archive" || fail "could not download $base/$archive"
curl -fsSL -o "$work/SHA256SUMS" "$base/SHA256SUMS" || fail "could not download $base/SHA256SUMS"
grep " $archive\$" "$work/SHA256SUMS" >"$work/expected" \
  || fail "$base/SHA256SUMS does not list $archive"
(cd "$work" && $check expected >/dev/null) || fail "$archive does not match its SHA256SUMS entry"
tar -xzf "$work/$archive" -C "$work" patina || fail "$archive holds no patina binary"

bin="$prefix/bin"
mkdir -p "$bin"
# Into place by rename, so a running patina keeps the file it started from.
cp "$work/patina" "$bin/.patina.$$"
chmod 755 "$bin/.patina.$$"
mv -f "$bin/.patina.$$" "$bin/patina"

installed=$("$bin/patina" --version) || fail "$bin/patina does not run on this machine"
printf 'installed %s\n' "$bin/patina"
printf '%s\n' "$installed" | sed 's/^/  /'

# A GitHub Actions job's later steps find it without another line of setup.
if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$bin" >>"$GITHUB_PATH"
fi
case ":${PATH:-}:" in
  *":$bin:"*) ;;
  *) printf 'add %s to PATH to run it as `patina`\n' "$bin" ;;
esac

# The host check: each requirement, and the fix for any that is missing.
printf '\n'
if ! "$bin/patina" doctor; then
  printf '\npatina is installed, but this host cannot run it until the FAIL lines above are fixed\n'
fi
