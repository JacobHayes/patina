# fifo-ipc — the named-pipe (FIFO) MRE

A minimal `std` program plus libc's `mkfifo`, `mkfifoat` and `mknod` — the three
spellings of the one special file an unprivileged program can create portably.

A FIFO is the only entry kind whose **name is filesystem state while its bytes
are not**. The name stats, lists, chmods, renames and unlinks like any other
entry; the bytes live in a pipe that the openers share and that vanishes with
the last descriptor, exactly as a kernel's does. Modeling one therefore means
modeling both halves and keeping them apart:

| what the guest does | what it becomes |
|---|---|
| `mkfifo` / `mkfifoat` / `mknod(S_IFIFO)` | `patina_mkfifo` → the recorded `fs_make_fifo` boundary operation |
| `stat` / `lstat` / `statx` / `fstat` | `S_IFIFO` plus the entry's permission bits |
| `read_dir` | `DT_FIFO` |
| `open(O_RDONLY)` | parks until a writer opens — woken through the scheduler |
| `open(O_WRONLY)` | parks until a reader opens |
| `open(O_RDONLY\|O_NONBLOCK)` | succeeds at once, with no writer |
| `open(O_WRONLY\|O_NONBLOCK)` | `ENXIO` when there is no reader |
| `open(O_RDWR)` | never waits (Linux's behavior) |
| `read` / `write` | the same in-process pipe channel an anonymous `pipe(2)` uses |
| `read` with no writer left | end-of-file |
| `write` with no reader left | `EPIPE`, an errno and never a signal |
| `fstat` on the descriptor | the entry's LIVE bits, read by inode — a `chmod` after the open shows through |
| `link` / `linkat` | a second NAME for the same inode, so the two names are one pipe |
| `unlink` | drops the name; a surviving link keeps the node, and open descriptors keep the pipe alive |

## Why it is the MRE

Before named pipes were modeled, `mkfifo` was not interposed at all. A guest
that called it could not be audited — the symbol was an unsupported-symbol
refusal in the `filesystem` escape class — and forcing it through with
`--allow-unsupported-symbols` only moved the failure: the call escaped to the
host, where it failed `ENOENT` on a path that exists only inside the in-memory
filesystem. Every leg below was unreachable.

That is the RED state this testbed pins; a green `run-patina.sh` is the
end-to-end proof.

## Running

```sh
./run-patina.sh
```

The script builds and stages under `CARGO_TARGET_DIR`, defaulting to
`../../target/testbeds/fifo-ipc` from this directory.

Unlike `rustix-default` and `cap-std-dirfd`, this testbed is **not** SUD-only:
the guest reaches every call through libc, so it runs on every platform the
native shim supports. The raw-syscall `mknodat` row (and the x86_64 legacy
`mknod` alias) has its own probe inside the SUD battery of
`scripts/validate-native-shim.sh`.

It asserts that the pre-run audit is **clean** — no allowance flag, and the
mkfifo/mknod family appears nowhere in it — that the guest prints the expected
`FIFO_RESULT`, that two same-seed runs are byte-identical **on stdout and the
captured stderr**, that a recorded run replays byte-identically, and that four
different seeds all reach the same result, then prints `FIFO_LEGS_RAN …`.

## What stays fail-closed

`mknod` models `S_IFIFO` and nothing else. A character or block device answers
`EPERM` — what the single non-root identity this runtime models would get on a
real kernel — and every other type is a loud named deny. No `mknod` reaches the
host.
