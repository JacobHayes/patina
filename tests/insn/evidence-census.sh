# Evidence (Instruction sites on arm64): every arm64 ELF file under /usr/bin,
# /usr/sbin, /usr/lib and /usr/libexec, every aligned word of its executable sections under the
# runtime's rule (RNDR/RNDRRS, the pause hints, PACGA) and the counter reads: how many match, and
# of those how many are data (read by a literal load, or under a `$d` mapping symbol); the words
# literal loads read and `$d` covers in all; the matches in non-executable sections, which the
# scan never searches. Prints every data match.
#@ tier=evidence budget=1200 arch=aarch64
. "$(dirname "$0")/lib.inc"
python3 -I "$HERE/lib/census.py" --summary /usr/bin /usr/sbin /usr/lib /usr/libexec | tee "$RUNS/census.txt"
grep -q '^summary' "$RUNS/census.txt" || die "no summary"
