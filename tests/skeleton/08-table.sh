# 8. patina table prints a row for every syscall number the host's kernel headers know for its architecture; rows not written show Stop.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
"$PATINA" table >"$RUNS/08-table.md"
# The host's numbers for its own architecture, from <asm/unistd.h> with the macros expanded
# (the generic header that arm64 used before Linux 6.11 defines some numbers through others,
# and two names that are no calls: the count and the start of the architecture's range).
echo '#include <asm/unistd.h>' | cc -dM -E - |
    awk '/^#define __NR_/ {n = substr($2, 6); if (n != "syscalls" && n != "arch_specific_syscall") print n, "__NR_" n}' >"$RUNS/08-names.txt"
{ echo '#include <asm/unistd.h>'; cat "$RUNS/08-names.txt"; } | cc -E -P - |
    awk 'NF == 2 && $2 ~ /^[0-9]+$/ {print $2, $1}' | sort -n >"$RUNS/08-header.txt"
[ "$(wc -l <"$RUNS/08-header.txt")" -eq "$(wc -l <"$RUNS/08-names.txt")" ] || die "a header number did not expand"
awk -F' [|] ' '/^[|] [0-9]/ {sub(/^[|] /,"",$1); print $1, $2}' "$RUNS/08-table.md" | sort -n >"$RUNS/08-rows.txt"
# The host's headers may be older than the table (which may know newer numbers), never newer.
missing=$(awk 'NR == FNR { row[$0] = 1; next } !($0 in row)' "$RUNS/08-rows.txt" "$RUNS/08-header.txt")
[ -z "$missing" ] || die "no table row for header entries: $(echo $missing)"
n=$(awk '$1<=462' "$RUNS/08-header.txt" | wc -l)
# every class is one of the defined ones; ptrace has no row yet and must show Stop
awk -F' [|] ' '/^[|] [0-9]/ && $3 !~ /^(Pass|Virt|Attempt|Rewrite|Place|Deny\([A-Z0-9]+\)|Stop)$/ {print; bad=1} END {exit bad}' "$RUNS/08-table.md" || die "unknown class"
awk -F' [|] ' '$2=="ptrace" && $3!="Stop" {exit 1}' "$RUNS/08-table.md" || die "ptrace does not show Stop"
echo "rows: $(wc -l <"$RUNS/08-rows.txt") (header numbers 0..=462: $n), all header numbers present"
