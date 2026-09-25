# patina-dst-conformance

Linux syscall conformance scenarios with the host kernel as the live oracle,
authoritative on the pinned kernel (below)
(design: `docs/arcs/syscall-conformance.md`). Unpublished; it exists for
`crates/cargo-patina/tests/native_conformance.rs`.

A scenario is a plain Rust function over the `Probe` call API
(`src/scenarios/<family>/<name>.rs`). Every scenario is built into one probe
binary, `conformance-probe <scenario> --vehicle libc|syscall|raw --dir DIR
[--strict]`, which writes one typed JSON event per observed call. Each
scenario's test runs it natively and under `cargo patina` through every
vehicle it has, and compares the two streams exactly, apart from the
normalizations the scenario declares at its call sites (allocated numbers,
identities, clock readings, documented alternative answers) and its declared
gaps. A gap is a strict expected failure (`Failure::Differs` with the exact
patina values, or `Failure::Stops` with the exact point, ending and
diagnostic): the test fails when patina fails differently, and when patina
starts passing, until the gap is removed. The patina run judged is the
recorded one (recording changes nothing it observes, which one test checks on
a few scenarios); one that completes is also replayed and run directly under
strace.

The kernel is pinned: the scenarios assert Ubuntu 24.04's GA kernel, Ubuntu's
build of Linux 6.8 (`patina_dst_syscalls::VIRTUAL_ABI`, the kernel the virtual
kernel mirrors), and moving to a newer one is an explicit, wholesale
migration. So only a host of that series (release `6.8.*`, any flavour:
`host::pinned`) is the authoritative oracle. On any other host (GitHub's
runners run 6.17) what sets the host apart from patina — a native check that
fails, a difference between the native and patina streams, a gap that no
longer matches — is reported and fails nothing: each line on stderr as
`DIVERGES (host 6.17, pinned 6.8) …`, and each scenario's lines as a Markdown
section appended to `$GITHUB_STEP_SUMMARY` when it is set.
`PATINA_REQUIRE_PINNED_KERNEL=1` judges any host as the pinned one. Native
vehicles that disagree with each other, patina's record/replay, trace and
strace checks, and a run that crashes or overruns its deadline fail on every
host.
A scenario declares the registry rows it covers (`covers`, `asserts_absent`),
the libc symbols its `libc` vehicle goes through, the host capabilities its
native oracle needs beyond those rows (`needs`: user xattrs, file handles or
whiteouts on the run directory's filesystem, inotify or lockable pages within
the caller's limits, an unprivileged caller, no controlling terminal, a
hardware or kernel-configuration feature such as protection keys or SysV IPC,
a host that restricts what the virtual kernel's declared configuration
restricts (unprivileged BPF, perf events, kernel-fault userfaultfd) — detected
live, an unmet one is reported not run and a detection that fails
unexpectedly is a failure), the
oldest kernel whose behaviour its checks assert (`kernel_floor`), its gaps, and
the facts its recorded trace must show. Where a host oracle is required
(`PATINA_REQUIRE_HOST_ORACLE=1`, CI), an unmet need or a kernel below a
scenario's floor fails the test — the runner is misconfigured — except a
machine fact found absent (`Need::hardware`: protection keys, shadow stacks,
secret memory, one NUMA node), which no runner is set up to provide: that
scenario is reported `NOT RUN` on the test's stderr, past libtest's capture,
so it shows in the job log. A killed native run can leave IPC objects behind;
the harness sweeps every name a run derives from its directory after each
native run (`owned::sweep`). A host kernel that implements an
asserted-absent row is still an oracle: the native run answers that row with
the declared ENOSYS (the probe binary's declared-absent mode) and patina is
judged against it. `EXCLUSIONS` lists registry
entries deliberately left without a scenario. `mise run conformance` runs the tests;
`mise run conformance:coverage` lists every registry entry of this target that
neither a scenario nor an exclusion accounts for, and exits 1 while any remain.

Adding a scenario: write `src/scenarios/<family>/<name>.rs` with its `run`
function and `SCENARIO` declaration, list it in `catalog::SCENARIOS`, add its
`#[test]` to `native_conformance.rs`, run the test, and declare what patina
does differently as gaps naming the responsible code.

The network scenarios (`net/*`, `readiness/*`) use the host's loopback stack
only — loopback addresses, AF_UNIX paths in the run directory and abstract
names derived from it, the kernel's rtnetlink — and compare host-allocated or
host-configured values (ports, buffer sizes, MTUs, interfaces other than `lo`)
by relation; IPv6 on `lo` and an unprivileged fanotify group are their needs. A libc symbol the shim leaves undefined cannot be imported by the
probe binary (the pre-run audit would refuse all of it), so its scenario
reaches glibc's definition through `dlsym` (`Probe::resolve`) and names it in
`resolves` (a scenario whose rows glibc has no wrapper for runs through
`Vehicle::KERNEL` only, not `syscall(2)` twice). Under patina that lookup
answers NULL: the shim's `__wrap_dlsym` routes
only a fixed list of names it defines (`c/posix/dlsym.c`
`patina_dlsym_route`), so such a scenario's gap lifts only when the shim
both defines the symbol and routes it. A catalog
test fails once a `resolves` name stops being registry-`Absent`: the
scenario then imports it directly.
