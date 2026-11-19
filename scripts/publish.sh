#!/usr/bin/env bash
# publish.sh — put the Rust SDK (`patina-dst`, crates/patina) on crates.io. A manual step with
# the owner's token, run after a release; nothing else is published there. A release is the
# `patina` binary on GitHub (.github/workflows/release.yml) and the SDKs at the release's git
# tag; neither needs this script.
#
#   scripts/publish.sh            dry run: list the package's files, check it carries the
#                                 licence, and `cargo publish --dry-run`. Uploads nothing.
#   scripts/publish.sh --execute  publish, only when the working copy is clean and the commit
#                                 carries the tag v<version> (jj: on @-, with @ empty).
#
# Exit codes: 0 = success, 1 = refused or a cargo step failed, 2 = bad usage.
set -euo pipefail; shopt -s inherit_errexit

mode=dry-run
case "${1:-}" in
  "") ;;
  --execute) mode=execute ;;
  -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
  *) printf 'publish.sh: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/.."

pkgid=$(cargo pkgid -p patina-dst)
version=${pkgid##*[@#]}
tag="v$version"

if [ "$mode" = execute ]; then
  dirty=$(jj log -r @ --no-graph -T 'diff.summary()')
  tags_here=$(jj log -r '@- & tags()' --no-graph -T 'tags.map(|t| t.name()).join("\n")')
  refuse=
  [ -z "$dirty" ] || refuse="the working copy is not clean"
  grep -qx "$tag" <<<"$tags_here" || refuse="${refuse:+$refuse; }tag $tag is not on @-"
  if [ -n "$refuse" ]; then
    printf 'publish.sh: refusing to publish %s: %s\n' "$tag" "$refuse" >&2
    exit 1
  fi
fi

files=$(cargo package -p patina-dst --no-verify --allow-dirty --list)
printf '%s\n' "$files" | sed 's/^/   /'
grep -qx LICENSE-APACHE <<<"$files" \
  || { printf 'publish.sh: the package lacks LICENSE-APACHE\n' >&2; exit 1; }

if [ "$mode" = dry-run ]; then
  cargo publish -p patina-dst --dry-run --allow-dirty
  printf 'publish.sh: dry run passed for patina-dst %s; nothing was uploaded\n' "$version"
else
  cargo publish -p patina-dst
  printf 'publish.sh: published patina-dst %s\n' "$version"
fi
