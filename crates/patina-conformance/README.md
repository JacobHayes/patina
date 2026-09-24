# patina-dst-conformance

Linux syscall conformance scenarios with the host kernel as the live oracle
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
starts passing, until the gap is removed. A patina run that completes is also
recorded and replayed and run directly under strace.

A scenario declares the registry rows it covers (`covers`, `asserts_absent`),
the libc symbols its `libc` vehicle goes through, the host capabilities its
native oracle needs beyond those rows (`needs`: user xattrs, file handles or
whiteouts on the run directory's filesystem, inotify or lockable pages within
the caller's limits, an unprivileged caller, a hardware or kernel-configuration
feature such as protection keys or SysV IPC — detected live, an unmet one is
reported not run and a detection that fails unexpectedly is a failure), the
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
judged against it; `EXCLUSIONS` lists registry entries deliberately
left without a scenario. `mise run conformance` runs the tests;
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
reaches glibc's definition through `dlsym` (`Probe::resolve`), which under
patina answers only what the shim defines.
