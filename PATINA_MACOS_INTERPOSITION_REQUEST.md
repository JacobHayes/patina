# Request: macOS native-shim interposition gaps for async Rust guests

## Summary

Async Rust binaries cannot run under `cargo patina run` on macOS aarch64 because
a handful of blocking/time/scheduling symbols are detected-and-refused but have no
interposer. The pre-run gate is correct (fail-closed detection is complete); the
gap is purely on the interposition side. There are two tiers:

1. **`kqueue`/`kevent`** - hit by *any* Tokio guest (the reactor). This is the
   headline blocker.
2. **`os_unfair_lock_*`, `openat`, `clock_gettime_nsec_np`** - hit once common
   ecosystem crates are in the tree (`parking_lot`, `rustix`), which most real
   async workloads pull in transitively.

All are already interposed on Linux (futex / epoll / `clock_gettime`) or have a
same-category macOS sibling already interposed, so the routes exist.

This doc has three parts: (1) the interposition asks (the two MREs, the
symbol/route table, acceptance) - the core request; (2) **separate feedback** on
`cargo patina audit` UX, which misled during debugging; (3) **separate feedback**
distinguishing which e/g/h "non-goals" are architectural vs. just not-yet-built,
as roadmap notes. Parts 2-3 are not blocking anything - they're to make the tool
and its docs clearer.

## MRE A - stock std + Tokio (isolates the reactor)

```
cargo new --bin mre && cd mre
# Cargo.toml: tokio = { version = "1", features = ["full"] }
```

```rust
use std::sync::Mutex;
use std::time::Instant;

fn main() {
    let m = Mutex::new(0u64);
    let t = Instant::now();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        *m.lock().unwrap() += 1;
        tokio::fs::write("/tmp/mre_out", b"hi").await.unwrap();
        let _ = tokio::fs::read("/tmp/mre_out").await.unwrap();
    });
    println!("{} {:?}", *m.lock().unwrap(), t.elapsed());
}
```

```
cargo patina build ./Cargo.toml --bin mre --output ./mre.patina --release
cargo patina run ./mre.patina --seed 1
```

Refuses with (verified on this host):

```
  _kevent (wait-multiplex)
  _kqueue (wait-multiplex)
  _pow (unknown-import)
  _socketpair (shared-memory-ipc)
```

Note what is NOT here: `os_unfair_lock`, `openat`, `clock_gettime_nsec_np`. On
current std/macOS, `std::sync::Mutex` lowers to `pthread_mutex_*`,
`Instant::now()` calls the plain `clock_gettime(CLOCK_UPTIME_RAW, ...)` symbol,
and std `fs` uses `open` - all three already interposed by strong defs in
`patina_posix.c`. So a std-only guest's only real gap is the reactor.

## MRE B - add the two crates a real workload carries

Add to `Cargo.toml`: `parking_lot = "0.12"` and `rustix = { version = "1",
features = ["fs"] }`, and touch each so they are not dead-stripped:

```rust
let l = parking_lot::Mutex::new(0u64);
*l.lock() += 1;
let _ = rustix::fs::open("/tmp/mre_out", rustix::fs::OFlags::RDONLY,
                         rustix::fs::Mode::empty());
```

Now the refusal additionally lists:

```
  _os_unfair_lock_lock / _trylock / _unlock    (unmanaged-sync)  <- parking_lot_core
  _openat                                      (filesystem)      <- rustix libc backend
  _clock_gettime_nsec_np                       (time)            <- rustix time module
```

These are the same symbols any nontrivial async workload surfaces, because
`parking_lot` and `rustix` are near-ubiquitous transitive deps.

## What to interpose (all detected today; none interposed on macOS)

| Symbol(s) | Category | Origin | Route to (Linux analogue already interposed) |
|-----------|----------|--------|----------------------------------------------|
| `kqueue` / `kevent` / `kevent64` | `wait-multiplex` (a) | mio / Tokio reactor | scheduler-integrated readiness (the epoll path) |
| `os_unfair_lock_lock` / `_trylock` / `_unlock` | `unmanaged-sync` (a) | `parking_lot_core` macOS parker | `DetScheduler` (same as the interposed `pthread_mutex_*`) |
| `openat` (and likely `fstatat`/`unlinkat`/`renameat`) | `filesystem` (f) | `rustix` libc backend | deterministic FS (same as the interposed `open`/`stat`/`unlink`) |
| `clock_gettime_nsec_np` | `time` (b) | `rustix` time module | virtual clock (same as the interposed `clock_gettime`) |

Suggested order: `kqueue`/`kevent` first (unblocks the reactor itself, and every
Tokio guest), then `os_unfair_lock_*` (every `parking_lot` lock), then `openat`
family and `clock_gettime_nsec_np` (both small, self-contained, siblings already
wired).

## Two secondary items

- `_pow` (`unknown-import`): a pure libm function, no host effect. Recognize it as
  known-safe rather than requiring `--allow _pow` at every run. (Real workloads
  add a larger `unknown-import` set of pure libm / CoreFoundation / Security-
  framework symbols on the TLS-cert path; where those are pure or unreachable,
  allowlisting or a `known-safe` classification avoids papering over them with
  `--allow-unsupported-symbols all`.)
- `_socketpair` (`shared-memory-ipc`, class g): Tokio's IO-driver / signal
  self-pipe wakeup. If the reactor gets an internal scheduler wakeup, the guest
  may stop importing it; otherwise it needs a deterministic in-process pipe.

## Acceptance

For MRE A and B: `cargo patina run` passes the pre-run gate with **no**
`--allow-unsupported-symbols`; two runs at the same `--seed` are byte-identical;
record + flag-free replay converges. The fix is to interpose these symbols (route
them into the deterministic runtime), not to downgrade or default-allow them - the
gate's refusal is correct today.

---

## Separate feedback: `cargo patina audit` UX

This is a tooling-usability item, not part of the interposition asks above, but it
cost real debugging time and is worth fixing.

**Observation.** `patina audit <prebuilt-path>` silently audits whatever binary
you hand it. Running it on a **stock `cargo build`** output (not built through
`cargo patina build`) reports ~89 "unsupported" symbols, including `open`,
`clock_gettime`, `pthread_mutex_*`, `pthread_cond_*` - i.e. the whole libc
surface the shim *does* interpose. That is technically correct (a non-shim-linked
binary genuinely has those as unsatisfied imports), but it is deeply misleading:
it looks like the shim covers almost nothing, when in fact those symbols only
become satisfied once `cargo patina build` links the shim staticlib in. The
*true* residual (the 8 effect-surface symbols above) is only visible when
auditing the Patina-built artifact or building-on-the-fly from source.

**What's confusing:** the audit output is identical in shape whether the input was
shim-linked or not, so nothing signals which situation you're in. A newcomer
auditing their `target/release/foo` reasonably concludes "Patina interposes
nothing," which is the opposite of the truth.

**Requested improvements, in priority order:**

1. **Audit from source, like `cargo build`.** `audit ./Cargo.toml --package X
   --bin Y` (or a bare `.rs`) already resolves to `ArtifactRef::Build` and can
   build-on-the-fly with the shim linked before auditing - this path gives the
   correct residual. Make this the documented, encouraged form and show it first
   in `--help`, so `audit` mirrors a normal `cargo build <target>` invocation
   rather than defaulting people toward auditing a stale prebuilt path.
2. **Optionally accept a Patina-built binary** for the "I already built it" case -
   but detect whether the given prebuilt binary is actually shim-linked (e.g.
   presence of the shim control-plane symbols, or the yield-point marker the tool
   already scans for) and, when it is *not*, emit a clear warning:
   *"this binary was not built with `cargo patina build`; the audit reflects
   unsatisfied libc imports, not the post-interposition residual - re-run with a
   Cargo manifest or a Patina-built artifact."* Failing closed (refusing to audit
   a non-shim-linked binary unless `--force`/`--raw` is passed) would be even
   safer, but a loud warning is the minimum.

Net: today the tool's most convenient invocation (`audit ./target/.../bin`) is the
one most likely to mislead. Steering toward source/manifest audit - and warning
when handed a raw binary - closes that trap.

## Separate feedback: which non-goals are principle vs. not-yet-built

From reading `ESCAPE-CLASSES.md`, the e/g/h "non-goal" framing bundles together a
hard architectural limit with a couple of things that look buildable and would
meaningfully widen the supported surface. Flagging the distinction so it's a
deliberate roadmap call, not an implicit "never":

- **Class e (process: `fork`/`exec`/`posix_spawn`/`kill`/...)** - genuinely
  architectural. A second process runs off-scheduler with its own clock/RNG/FS
  and can't be deterministic in a single-process model. The deny-trap treatment
  (abort loud + reproducible) is the right call. **No ask here - leave as-is.**

- **Class g (`socketpair`/`pipe` specifically)** - *not* architectural. When both
  ends stay inside the guest (the common case: an async runtime's own IO-driver /
  signal self-pipe wakeup, which is exactly the `_socketpair` seen above), this is
  in-process and **could be modeled as a deterministic in-process pipe** wired to
  the scheduler's wakeup path - no cross-address-space escape involved. The truly
  cross-process members (`shm_open`, `mach_msg*`, `mach_port_*`, `mq_*`) should
  stay refused. **Suggested build-out:** a deterministic `pipe`/`socketpair` whose
  reads/writes are scheduler-visible, so async reactors stop needing this class at
  all. (This is the cleaner fix for the `_socketpair` item above than "hope it
  disappears when the reactor is interposed.")

- **Class h (signals/timers)** - mostly principled (real host timers / ambient
  signals would perturb the schedule), but there's a modeled seam already
  half-open: registration (`sigaction`/`signal`/`sigaltstack`) is allowlisted;
  only timer-*arming* and signal-*waiting* are refused. A **virtual-clock-driven
  timer** (fire at deterministic virtual-time N, driven by the same clock that
  already backs `nanosleep`/`clock_nanosleep`) is conceivable in-model and would
  let guests that arm timers (`timer_settime`, `setitimer`) run deterministically
  instead of being refused. **Suggested build-out (lower priority):** map the
  timer-arming family onto the virtual clock; keep real signal *delivery*/waiting
  refused.
