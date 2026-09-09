# cap-std-dirfd — the `*at` / directory-descriptor resolution MRE

A minimal `std` + [`cap-std`](https://github.com/bytecodealliance/cap-std)
program. `cap-std` is the **capability-based** filesystem API: a program opens
one directory and receives a `Dir`, and every later operation is performed
*relative to that descriptor*. It resolves paths one component at a time itself
(so a `..` or a symlink can never escape the capability), which means it never
issues a path-only call — everything is `*at`:

| what the guest does | the syscall it becomes |
|---|---|
| `Dir::open_ambient_dir` | `open(path, O_RDONLY\|O_DIRECTORY\|O_PATH\|O_CLOEXEC)` — through **libc** |
| walking a component | `openat(dirfd, name, O_PATH\|O_DIRECTORY\|O_NOFOLLOW\|O_CLOEXEC)` |
| `Dir::open` / `create` / `write` | `openat(dirfd, name, …)` |
| `Dir::metadata` / `symlink_metadata` | `statx(dirfd, name, …)`, `statx(fd, "", AT_EMPTY_PATH)` |
| resolving a symlink component | `readlinkat(dirfd, name, …)` |
| stepping through `..` | `faccessat2(dirfd, ".", X_OK, AT_EACCESS)` |
| `create_dir` / `remove_file` / `remove_dir` | `mkdirat(dirfd, name, mode)`, `unlinkat`, `unlinkat(…, AT_REMOVEDIR)` |
| `rename` / `symlink` | `renameat(dirfd, …, dirfd, …)`, `symlinkat(target, dirfd, link)` |
| `entries` / `read_dir` | `fcntl(dirfd, F_GETFL)` → `openat(dirfd, ".")` → `getdents64` |
| probing the fast path | `openat2(…, RESOLVE_BENEATH)`, expected to `ENOSYS` |

Under `cap-primitives` those calls go through **rustix's default backend**, so on
x86_64 they are raw inline `syscall` instructions handled by syscall-user-dispatch
(SUD) — while the base descriptor is minted by the **C interposer**. One guest
therefore exercises both halves of the `*at` surface at once, and it can only work
because they share one directory-descriptor table in the runtime
(`patina_openat` / the resolver in `src/paths.rs`).

## Why it is the MRE

Before dirfd-relative resolution, every `*at` row modeled only `AT_FDCWD` and
refused a real descriptor with `ENOSYS`, and the libc `open` refused `O_PATH`
outright. A cap-std guest therefore died on its **first** call:

```
Dir::open_ambient_dir: Function not implemented (os error 38)
```

That is the RED state this testbed pins; a green `run-patina.sh` is the
end-to-end proof of the fix.

## Running

```sh
./run-patina.sh
```

This testbed is **SUD-only**, for the same reason `rustix-default` is: the raw
`*at` calls need the kernel's generic-entry syscall-user-dispatch (x86_64
≥ 5.11; arm64 does not have it yet). On a non-SUD kernel or a non-Linux host
`run-patina.sh` prints a **loud, counted** `cap-std-dirfd: SKIPPED 1 …` line and
exits 0 — never a silent pass. Where SUD is present it asserts: the binary
audits as `direct-syscall (SUD-managed)`, runs with the expected
`CAPSTD_RESULT`, is byte-identical across same-seed repeats **on stdout and the
captured stderr**, and records/replays byte-identically, then prints
`CAPSTD_LEGS_RAN branch=sud …`. The expected result line includes
`modes=enforced+created pinned=node`, so a regression in either of the two legs
above fails the run rather than passing quietly.

The mode leg covers both halves of the model: the bits are ENFORCED (`0o000` is
`PermissionDenied` and not `NotFound`, a directory with no `x` cannot be resolved
through, one with no `r` cannot be listed), and a CREATION mode is the caller's
own — a file created `0o400` reads back `0o400` and refuses a later write-open, a
directory created `0o500` refuses a new name inside it, an `open` of an EXISTING
file leaves that file's mode alone whatever third argument it carries, and the
ordinary `0o666`/`0o777` requests still land at `0o644`/`0o755` under the modeled
umask.

The legs are RED-proven by mutation rather than assumed: neutering the
owner-triad permission check fails the enforcement half (`a 0o000 file must not
be readable`), dropping the caller's mode on the driver side fails the creation
half (`a creation mode must be the caller's`), and dropping the bookkeeping that
moves an open description with its node through a rename fails the pinning leg
(`the descriptor must survive the rename: PermissionDenied`).

## What stays fail-closed

`openat2` is **not** modeled: its `RESOLVE_*` flags are a kernel-side sandbox the
deterministic filesystem does not implement. It is a named deny (one diagnostic
line on the captured stderr, then `ENOSYS`), which is exactly the answer
`cap-primitives` probes for before taking its component-wise `openat` fallback —
so the refusal is visible in the recorded stderr rather than silent.
