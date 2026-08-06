# Shim link args reach dependency cdylib targets

Status: fixed by scoping the shim link arguments to the guest's own final link.
Red-before/green-after verified on both macOS arm64 and Linux x86_64; see
"Evidence" and "Linux evidence". One rung of the original report — the
duplicate `rust_eh_personality` — could not be reproduced outside the real
SlateDB tree; that open question is recorded below and does not gate the fix.

## Field symptom

SlateDB dogfooding feedback (§1): on Linux x86_64, `cargo patina build .
--yield-points` failed while linking a **dependency** of the guest, not the
guest itself:

```
rust-lld: error: relocation R_X86_64_PC32 cannot be used against symbol 'environ'; recompile with -fPIC
>>> referenced by patina_posix.c
>>> .../patina_posix.o:(patina_environ_base)
```

crc-fast 1.10.0 (a transitive dependency of the guest's checksum path) was the
crate whose link failed. crc-fast's `[lib]` declares `crate-type = ["lib",
"cdylib", "staticlib"]` — it ships a C-compatible shared library for use from
other languages, in addition to the ordinary Rust `rlib`.

An initial fix compiled the shim's C objects `-fPIC`. Linux verification of the
real SlateDB tree proved that **insufficient**: the relocation error went away
and the same link failed one rung further in.

```
rust-lld: error: duplicate symbol: rust_eh_personality
>>> defined in <sysroot>/lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-*.rlib
>>> defined in .../libpatina_dst_native_shim.a
```

Two further facts came out of that round:

- A synthetic cdylib that only called `std::env::var`/`std::fs::metadata` linked
  green even with the shim injected, where crc-fast (17 codegen units) did not.
- The failure fires with and without `--yield-points`. That flag is incidental
  to this class (though it has a second-order consequence of its own; see
  "SanitizerCoverage" below).

**What the duplicate-symbol rung is, and is not.** It was observed on the real
SlateDB tree, and it is the reason the `-fPIC`-only fix was rejected. It has
*not* been reproduced synthetically. On x86_64 Linux this change's fixture was
run against a path dependency with genuine landing pads and a live
`rust_eh_personality` reference, in four shapes — `["rlib", "cdylib"]` and
`["rlib", "cdylib", "staticlib"]`, each in debug and release — and with `-fPIC`
restored, **every one of them linked clean**. So "the cdylib references the
unwind personality" is not by itself the trigger; something further about
crc-fast's graph is. Treat the exact trigger as open.

That does not weaken this fix. The scoping below keeps the shim off that link
whatever the trigger turns out to be, and the two failure modes that *are*
reproducible on demand — the `-fPIC` relocation error, and the whole shim being
embedded in a dependency artifact — are enough to gate it on both platforms.

## Root cause

`cargo patina build`/`run`/`audit`/`replay` of a Cargo package drives the
package's own Cargo build with the shim's cfg flags *and* its link arguments
injected together through `CARGO_ENCODED_RUSTFLAGS`. Cargo forwards `RUSTFLAGS`
to every crate it compiles from source in the invocation, and rustc forwards
`-C link-arg` to the system linker for every crate-type it actually links. An
`rlib` compile has no link step and ignores them; a `cdylib`/`dylib` compile
does link, so the dependency's own `.so`/`.dylib` link receives
`-C link-arg=<patina_posix.o>` and `-C link-arg=<libpatina_dst_native_shim.a>`
— the tokens meant only for the guest's binary.

That is the whole cause, and it is enough: an artifact nobody loads gets the
entire deterministic shim — Rust runtime and C POSIX layer — force-linked into
it. The shim's global constructor is always retained by the linker, so it is not
dead-stripped away. On x86_64 Linux that shared-object link is then refused
outright, because `patina_posix.c`'s `patina_environ_base`
(`crates/patina-native-shim/c/patina_posix.c:267`) takes `environ`'s address and
a non-PIC object cannot do that inside a shared object. macOS `cc` compiles PIC
by default, so there the same link silently succeeds and simply produces a
`.dylib` carrying ~13,800 `patina_*` symbols.

`libpatina_dst_native_shim.a` is additionally a Rust `staticlib`, so it bundles
its own copy of std — the ingredient behind the duplicate `rust_eh_personality`
seen on the real tree. At an executable link that is harmless: the linker pulls
an archive member only to satisfy an undefined symbol, and `rust_eh_personality`
is already defined by the guest's own libstd rlib. Why a `cdylib` link makes both
definitions live in crc-fast's case but not in any synthetic reproduction
attempted here is unresolved (see above).

### Not the explicit `--target`

The earlier version of this document blamed the explicit host `--target` that
`build_native_package` passes, on the theory that Cargo prunes a dependency's
unused crate-types only on an implicit-host build. **That is wrong**, and the
fix does not depend on it. Measured directly with cargo 1.97.1: a package
depending on a path crate declaring `crate-type = ["rlib", "cdylib"]` produces
`libdep.rlib` *and* `libdep.dylib` with `--target <host>`, without `--target`,
and under a plain `cargo build` with no flags at all. Cargo always builds every
declared crate type of a path dependency. The explicit `--target` earns its
keep for a different reason — it keeps the cfgs and instrumentation off build
scripts and proc macros — and it stays.

The dependency cdylib is therefore unavoidable, and unavoidably useless: nothing
loads it, and nothing can. The fix has to make its link succeed, not prevent it.

## Fix

**Scope the shim link arguments to one compilation unit.** The package build now
runs as `cargo rustc` rather than `cargo build`/`cargo test --no-run`, splitting
the two injections by what each actually needs:

| Injection | Mechanism | Scope |
|---|---|---|
| `cfg(patina)`/`cfg(dst)`/`cfg(patina_shim)`, `rustix_use_libc`, SanitizerCoverage codegen flags | `CARGO_ENCODED_RUSTFLAGS` | every crate compiled from source |
| `patina_posix.o`, `libpatina_dst_native_shim.a`, `patina_yield.o`, the platform link args (`-Wl,--wrap=dlsym`, `-lc`) | `cargo rustc … -- <args>` | the selected target's final link only |

`cargo rustc` passes its trailing arguments to the final compiler invocation for
the one target selected, and to nothing else — the stable, documented mechanism
for exactly this. The cfgs stay whole-graph because `cfg(patina)`-gated code in
dependencies needs them. Interposition is unchanged: the shim's strong symbol
definitions still land in the guest's own link exactly as before.

- `native_package_rustflags` and `native_package_link_args`,
  `crates/cargo-patina/src/lib.rs`.
- `build_native_package` (`cargo rustc --package P --bin B`) and
  `build_native_harness` (`cargo rustc --package P {--lib|--test N|--bin N}`).

`cargo rustc` compiles one target, so the harness path must now resolve
`--harness-target` to a single package and target kind *before* building, from
`cargo metadata` (`select_native_harness_target`). This replaces the previous
"build every test target, then filter the artifact stream by name" shape, and
fails closed earlier and more cheaply on an unknown or ambiguous name.
`cargo rustc` also rejects `--release` alongside `--profile`, and builds a
lib/bin target in test mode only under the `test`/`bench` profiles, so a release
harness build selects `--profile bench` — which inherits `release`, and so
carries the same codegen settings and the same `[profile.release]` overrides a
`cargo test --release` harness would get.

### SanitizerCoverage: one object stays whole-graph

Scoping alone breaks `--yield-points`, and the regression fixture caught it
immediately on macOS:

```
Undefined symbols for architecture arm64:
  "___sanitizer_cov_trace_pc_guard_init", referenced from:
      _sancov.module_ctor_trace_pc_guard in cdylib_dep.*.rcgu.o
```

The instrumentation flags are whole-graph on purpose — dependency code gains
yield points too, which is what makes an atomics-only race window inside a
dependency schedulable. A dependency's `cdylib` is built by the same
instrumented rustc invocation as its `rlib`, but unlike the `rlib` it links on
its own, and its instrumented calls have nothing to resolve against once
`patina_yield.o` is scoped away.

So exactly one small object is injected whole-graph:
`crates/cargo-patina/c/patina_sancov_stub.c`, holding **weak** no-op definitions
of the three SanitizerCoverage entry points, staged only under `--yield-points`.
A dependency's shared library resolves against inert stubs; the guest's own link
also carries `patina_yield.c`'s strong definitions, which override them. The
guest's hot path is unchanged — verified by disassembly, below — and the stubs
cannot mask a broken build, because they deliberately do not carry the
`PATINA_YIELD_POINTS_V1` marker that `cargo patina run` requires before treating
a binary as yield-instrumented.

### `-fPIC`: dropped from the shim objects, kept on the stub

The `-fPIC` flags added to `PATINA_POSIX_OBJECT` and `PATINA_YIELD_OBJECT` by
the first attempt are **removed**. Those objects now only ever land in an
executable link, where position-independence is not required — and the evidence
that it is not required is that every Patina release before this bug compiled
them without `-fPIC` while `scripts/validate-native-shim.sh` ran green on both
`ubuntu-latest` (x86_64) and `ubuntu-24.04-arm` on every push. Keeping the flag
would be a workaround for a link that no longer happens, and it never prevented
the class anyway: `-fPIC` cannot fix a duplicate `rust_eh_personality`.

`-fPIC` **is** kept on `patina_sancov_stub.c`, with the reason the first attempt
lacked: that object is deliberately whole-graph, so shared-library links are
precisely where it is meant to land.

## Evidence

Regression fixture:
`cargo test -p cargo-patina --test end_to_end native_build_package_keeps_shim_link_args_off_a_dependency_cdylib`

It builds a package depending on a local path crate declaring
`crate-type = ["rlib", "cdylib"]` under `cargo patina build --yield-points`,
then asserts, in order:

1. the dependency's `.so`/`.dylib` exists at all (else the class is not being
   exercised and the fixture would pass vacuously);
2. it references `rust_eh_personality`, which keeps the dependency a realistic
   stand-in for crc-fast rather than decaying into a trivial arithmetic crate —
   the exported function allocates, formats, and `catch_unwind`s to earn that
   reference. Note this is a realism guard, not a proven discriminator: such a
   dependency still links clean under `-fPIC` (see "What the duplicate-symbol
   rung is, and is not");
3. it contains neither `patina_environ_base` nor `patina_yield_point` — **this
   is the assertion that carries the fixture**, and the one that goes red on
   both platforms;
4. the guest binary still contains both, so scoping did not weaken
   interposition;
5. the guest runs and prints its result marker.

A unit test, `shim_link_args_never_travel_in_whole_graph_rustflags`, pins the
split itself: the only `link-arg=` token permitted in the whole-graph rustflags
is the SanitizerCoverage stub, and none at all in an uninstrumented build.

**Red-before/green-after (macOS, measured):** restoring the whole-graph
injection behind a temporary probe makes the fixture fail with
`shim symbol patina_environ_base leaked into the dependency cdylib …`. `nm` on
the dependency's `.dylib` in that state reports **13,829** `patina_*` symbols,
including `patina_environ_base` (1) and `patina_yield_point` (2), alongside
`rust_eh_personality` (1). With the fix: **0** `patina_*` symbols in the
dependency's `.dylib`, `rust_eh_personality` still present, and 13,824
`patina_*` symbols in the guest binary.

**Strong-over-weak resolution (macOS/ld64, measured):** `otool -tvV` on a
`--yield-points` guest shows the linked `___sanitizer_cov_trace_pc_guard`
incrementing the guard word and tail-calling `_patina_yield_point` — the strong
definition from `patina_yield.o`, not the weak stub. The four
`native_yield_points_*` end-to-end tests, including the one that asserts yield
accounting, pass unchanged.

## Linux evidence (x86_64, run)

Verified on a Tensorlake x86_64 sandbox at snapshot base `f3699ab3` with this
change applied. Every build below printed its `Compiling` lines from a fresh
tree, so none of this rides a stale relink.

1. **The original field failure reproduces.** Restoring the whole-graph
   injection makes the dependency's own `.so` link fail with exactly the SlateDB
   symptom: `rust-lld: error: relocation R_X86_64_PC32 cannot be used against
   symbol 'environ'; recompile with -fPIC`, `referenced by patina_posix.c …
   patina_posix.o:(patina_environ_base)` (and `patina_environ_install`). This is
   the ELF-only rung — macOS `cc` is PIC by default and never shows it.
2. **`-fPIC` alone is insufficient, and the fixture still bites.** With `-fPIC`
   restored *and* the whole-graph injection, that link succeeds — and the
   fixture fails on the assertion that carries it: `shim symbol
   patina_environ_base leaked into the dependency cdylib …/libcdylib_dep.so`.
3. **Fixed: green.** `cargo test -p cargo-patina --test end_to_end
   native_build_package_keeps_shim_link_args_off_a_dependency_cdylib` passes,
   and the dependency's `libdep.so` carries **0** `patina_*` symbols by both
   `nm` and `nm -D`.
4. **Strong-over-weak under lld.** On a `--yield-points` guest, `nm` reports
   `T __sanitizer_cov_pcs_init`, `T __sanitizer_cov_trace_pc_guard`, and
   `T __sanitizer_cov_trace_pc_guard_init` — strong, from `patina_yield.o`, not
   `W` — and `objdump -d --disassemble='__sanitizer_cov_trace_pc_guard'` shows
   `call <patina_yield_point>`. Had lld preferred the weak stub, yield points
   would have gone silently inert.

Still owed on Linux, neither blocking this change:

- **`scripts/validate-native-shim.sh`** with `PATINA_REQUIRE_STRACE=1` on x86_64
  and arm64 — the standing gate that covers non-PIC shim objects in a PIE
  executable link, and so the confirmation for dropping `-fPIC`. It currently
  aborts early on glibc at an unrelated putenv probe.
- **A real-tree rebuild** of a guest whose graph includes crc-fast 1.10.0, the
  only known way to exercise the duplicate-symbol rung.

## Decisions

- **`cargo rustc`, not a two-phase build or a build-script injection.** The
  alternatives the first attempt rejected were rejected against a wrong root
  cause. `cargo:rustc-link-arg-bins` would still mean writing a build script
  into the user's package; a two-phase build cannot express "link this
  dependency without these flags". `cargo rustc`'s trailing arguments are the
  stable, single-invocation mechanism for per-unit link flags and cost nothing
  but resolving the target up front — which the harness path benefits from
  anyway.
- **The stub is weak, not a runtime fallback.** Making `patina_yield.o` itself
  self-contained (weak *references* to the shim's Rust entry points, null-checked
  at each basic block) would have added a branch to the hottest path in an
  instrumented guest and created a genuinely silent inert mode. Weak
  *definitions* in a separate object resolve entirely at link time: the guest's
  code is byte-for-byte what it was.
- **No allowance added anywhere.** This is build plumbing, not a new
  escape/allowance; the default-deny audit and shim host-alias doctrine are
  untouched.
