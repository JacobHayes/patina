# 8. patina table prints a row for every syscall number known to the kernel headers; rows not written show Stop.
#@ tier=quick
. "$(dirname "$0")/lib.inc"
h=/usr/include/x86_64-linux-gnu/asm/unistd_64.h
"$PATINA" table >"$RUNS/08-table.md"
awk '/^#define __NR_/ {sub("__NR_","",$2); print $3, $2}' "$h" | sort -n >"$RUNS/08-header.txt"
awk -F' [|] ' '/^[|] [0-9]/ {sub(/^[|] /,"",$1); print $1, $2}' "$RUNS/08-table.md" | sort -n >"$RUNS/08-rows.txt"
cmp "$RUNS/08-header.txt" "$RUNS/08-rows.txt" || die "table rows differ from the header's numbers"
n=$(awk '$1<=462' "$RUNS/08-header.txt" | wc -l)
# every class is one of the defined ones; ptrace has no row yet and must show Stop
awk -F' [|] ' '/^[|] [0-9]/ && $3 !~ /^(Pass|Virt|Attempt|Rewrite|Place|Deny\([A-Z0-9]+\)|Stop)$/ {print; bad=1} END {exit bad}' "$RUNS/08-table.md" || die "unknown class"
awk -F' [|] ' '$2=="ptrace" && $3!="Stop" {exit 1}' "$RUNS/08-table.md" || die "ptrace does not show Stop"
echo "rows: $(wc -l <"$RUNS/08-rows.txt") (numbers 0..=462: $n), all header numbers present"
