# syscall-conformance — the host-oracle conformance harness

The kernel is the oracle. Every `probes/<family>/<name>.rs` binary is a
self-checking scenario over a slice of the Linux syscall ABI; it issues its
calls through one of three **vehicles** and writes one typed JSON event per
observed call on stdout. The same binary runs natively (the host kernel
answers), under `cargo patina run` (patina answers), and under `cargo patina
replay`, and the event streams must agree except for the divergences declared
in `divergences.toml`. Design: `docs/arcs/syscall-conformance.md` §4.

```sh
testbeds/syscall-conformance/run.sh                 # every probe, every mode, every vehicle
testbeds/syscall-conformance/run.sh --fast          # native + patina, libc vehicle (check:fast)
testbeds/syscall-conformance/run.sh --mode patina --vehicle raw --probe fs/open_rw
testbeds/syscall-conformance/run.sh --selftest      # prove every gate can fail
testbeds/syscall-conformance/run.sh --bless         # re-record expected/ on THIS host
testbeds/syscall-conformance/run.sh --help
```

## Vehicles

| `--vehicle` | how the call is issued | what it exercises under patina |
|---|---|---|
| `libc` | the glibc symbol of the same name (`openat`, `fstatat`, …) | the C interposer layer (`crates/patina-native-shim/c/`) |
| `syscall` | glibc's `syscall(2)` with the `libc::SYS_*` number | the shim's `syscall` interposer |
| `raw` | an inline-asm `syscall` instruction (x86_64 Linux only) | the SUD dispatcher (`sud.rs`) |

A probe body is written once against `Probe` (`src/calls.rs`), which records
every call with the row's normalizations. Rows whose libc symbol the shim does
not interpose today (`getdents64`, `ppoll`) live in their own probes and link
that symbol only there (`Probe::register_libc`), so the pre-run audit refuses
just that probe rather than every binary.

## Modes and legs

| `--mode` | leg | what must hold |
|---|---|---|
| `native` | the plain binary with `--strict` | exits 0; normalized stream equals `expected/<probe>.<os>-<arch>.jsonl` exactly; host kernel ≥ the blessing kernel; a host lacking a row's number is `HOST-UNAVAILABLE` (counted, not failed) |
| `patina` | `cargo patina run … --seed 1 -- --vehicle V` | every field difference from the blessing is declared in `divergences.toml`, and every declaration still diverges (a stale one fails) |
| `replay` | `run --record` then `replay` | the two streams are byte-identical and the recorded one passes the patina diff |
| `leak` | the shim-linked binary directly under `strace` | zero host syscalls outside the loader prelude (the `validate-native-shim.sh` default-deny filter, trace set widened to `%process,%signal,%ipc`) |

Every leg is a `PASS`, a `FAIL` (with the differ's lines and the probe's
stderr), or a counted `SKIP`; the script exits 1 on any failure and prints
`CONFORMANCE_LEGS_RAN …` only after every leg passed. Off Linux, on an
unblessed platform, or without SUD for the raw vehicle it prints a counted
`SKIPPED`/`SKIP` line — never a silent green.

## Events, normalization, checks

```json
{"seq":3,"op":"openat","args":{"dirfd":"AT_FDCWD","flags":66,"mode":420,"path":"/tmp/syscall-conformance/fs-open_rw/data"},
 "ret":3,"errno":null,"fields":{},"norm":{"ret":"relative:fd"}}
```

`ret` is the kernel result (`-1` with `errno` named on failure), `fields` the
struct members the probe chose, and `norm` the typed per-field normalization
the differ applies before comparing (never regex over text):

| tag | meaning |
|---|---|
| `relative:<ns>` | an allocated number (descriptor, port): replaced by the label of the event that introduced it (`fd@57`), so identity relations survive and magnitudes do not; a `close` retires a descriptor number |
| `inode` | inode identity, same labeling (`ino@5`) |
| `identity` | pid/uid/gid, same labeling (`id@0`) |
| `monotonic` | a clock reading: `mono:first`, `mono:>=`, `mono:-` relative to the previous reading of the same op/field |
| `mask:0oNNN` | keep only these bits |

Semantic properties are `p.check(label, cond)` events (`op: check`, `ret`
1/0). Natively (`--strict`) a false check panics; under patina it is recorded
and the probe continues, so one wrong answer becomes one declared field
divergence rather than a lost stream. `p.require` marks the few preconditions
a scenario cannot continue without.

## Expectations and divergences

`expected/<probe>.<os>-<arch>.jsonl` starts with a header naming the oracle:

```json
{"header":{"schema":"patina.conformance/v1","probe":"fs/open_rw","os":"linux","arch":"x86_64",
 "kernel":"6.8.0-139-generic","glibc":"2.39","virtual_abi":"6.8"}}
```

`virtual_abi` is the kernel ABI level patina's virtual kernel claims
(`probes.toml [abi]`). Re-record with `--bless` on a host whose kernel is at
least what the other blessings name; the other two vehicles must then agree
natively (the runner checks). A platform with no expectation file is skipped
loudly (`UNBLESSED`); `linux-aarch64` needs a bless on an aarch64 host.

`divergences.toml` declares each host≠patina field with a reason:

```toml
[[divergence]]
probe  = "fs/open_rw"
op     = "openat"          # or "*"
field  = "errno"           # op | ret | errno | args.<k> | fields.<k>
seq    = 55                # optional; `seqs = [..]` for a set; `label = "…"` for check events
reason = "pending: F3 — a component through a regular file answers ENOENT, not ENOTDIR (…)"
```

`kind = "abort"` (with `seq`) declares a probe that dies inside patina at that
event — the recorded prefix is still compared; `kind = "probe"` declares a
probe that cannot be compared at all (an audit refusal, or a fatal whose
stdout is lost). Every kind is self-cleaning: a declaration the stream no
longer needs fails the leg as STALE, so the file is always exactly the current
gap. `vehicle = "…"` scopes a declaration to one vehicle.

## Selftests

`run.sh --selftest` proves each gate can fail, on synthetic streams through the
same differ the legs use (`conform selftest`): a planted divergence (native and
patina), a planted stale divergence, planted event-count drift in both
directions, a failed check, a probe that dies, planted stale probe-level and
abort-level declarations, the host gate's host-unavailable and too-old refusals,
plus the controls that must pass; and the strace leak gate against a planted
`openat("/etc/hostname")` (`probes/selftest/leak.rs`) under the leg's exact
`strace` invocation and filter.

## Adding a probe

1. Add `probes/<family>/<name>.rs` (see any existing one) and its `[[bin]]`
   (`name = "<family>-<name>"`) to `Cargo.toml`.
2. Add `[probe."<family>/<name>"]` to `probes.toml` with the kernel rows and
   libc symbols it covers (every row needs a `[since]` kernel).
3. `run.sh --bless --probe <family>/<name>`, then `run.sh --mode patina --probe …`
   and declare what it finds in `divergences.toml` with a `pending: <family>`
   reason and the responsible shim code.

Layout: `src/vehicle.rs` (vehicles, numbers, errno names), `src/observe.rs`
(events, recorder, normalization tags), `src/calls.rs` (the probe API),
`src/expect.rs` (normalizer, differ, host gate, selftest), `src/bin/conform.rs`
(the CLI `run.sh` drives; positional arguments only), `probes.toml`,
`divergences.toml`, `expected/`.
