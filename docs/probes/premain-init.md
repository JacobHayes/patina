# Pre-main initialization probe — measured results

Throwaway experiment. No changes were made to the patina repo and no git/jj
state was touched.

Probe sources and drivers: `premain/` in this directory
(`run-linux.sh`, `run-macos.sh`, `shim.c`, `guest_obj.c`, `guest_ar.c`,
`shimdylib.c`, `shimdylib2.c`, `rustguest.rs`, `rustmain.rs`, `main*.c`).
Raw output: `premain/linux-raw.log`, `premain/macos-raw.log`.

Every initializer writes its own line with `write(2)` directly, so the printed
order is the execution order with no stdio buffering in the way. Line prefixes
(`00`, `01`, `02`, …) are labels chosen when the probe was written, *not*
observed ordering — read the actual sequence of lines.

## Verdicts

| Claim | Verdict |
|---|---|
| A — Linux: main-executable `.preinit_array` runs before every `.init_array` ctor, regardless of link order or contributor | **HOLDS** |
| A (constraint) — `.preinit_array` is honored only in the main executable | **HOLDS, and is stronger than stated**: GNU ld refuses to *produce* such a DSO at all |
| B — macOS: initializer order within the main executable follows object/archive link order | **HOLDS** |

The important result is not in either claim: **on macOS, the ordering rule that
does hold makes a static shim unable to run first in a rustc-driven link.** See
"Surprises that affect the arc design".

## Toolchains

Linux (tart VM `patina-linux-verify`, aarch64):

```
cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
rustc 1.97.1 (8bab26f4f 2026-07-14)
GNU ld (GNU Binutils for Ubuntu) 2.42
ldd (Ubuntu GLIBC 2.39-0ubuntu8.8) 2.39
aarch64 / Linux 7.0.0-28-generic (Ubuntu 24.04)
```

macOS (host, arm64):

```
Apple clang version 21.0.0 (clang-2100.1.1.101)
Target: arm64-apple-darwin25.5.0
rustc 1.97.1 (8bab26f4f 2026-07-14)
@(#)PROGRAM:ld PROJECT:ld-1267  BUILD 16:38:58 Jun  8 2026
dyld: /usr/lib/dyld, 2374000 bytes, dated Jun 24 22:29 (macOS 26.5.2, build 25F84)
```

## Claim A — Linux / ELF

### A1–A3: link order does not affect preinit precedence

`.preinit_array` entries came from two different translation units: `main.c`
(`PREINIT_EXE`) and the shim TU `shim.c` (`PREINIT_SHIM`). Constructors came
from an exe object, a C static archive, and a Rust staticlib.

```
===== A1: preinit in exe; shim object FIRST on the link line =====
01 PREINIT_EXE (.preinit_array, main executable)
01b PREINIT_SHIM (.preinit_array from the shim TU)
02 SHIM_CTOR (exe object)
03 GUEST_OBJ_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
05 RUST_GUEST_CTOR (rust staticlib)
99 MAIN

===== A2: preinit in exe; shim object LAST on the link line =====
01 PREINIT_EXE (.preinit_array, main executable)
01b PREINIT_SHIM (.preinit_array from the shim TU)
03 GUEST_OBJ_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
05 RUST_GUEST_CTOR (rust staticlib)
02 SHIM_CTOR (exe object)
99 MAIN

===== A3: preinit in exe; guest object first, main.o last among objects =====
01b PREINIT_SHIM (.preinit_array from the shim TU)
01 PREINIT_EXE (.preinit_array, main executable)
03 GUEST_OBJ_CTOR (exe object)
02 SHIM_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
05 RUST_GUEST_CTOR (rust staticlib)
99 MAIN
```

A2 moves the shim's constructor from first to last among the `.init_array`
entries, and A3 reorders the objects again — the `.init_array` block reshuffles
each time while both preinit entries stay ahead of all of it. Note in A3 that
the two preinit entries swapped relative to each other: **ordering *within*
`.preinit_array` follows link order**, exactly like `.init_array`. Preinit's
guarantee is about the boundary between the two arrays, not about who is first
inside preinit.

Section dumps confirm the two arrays are separate and that A1 vs A2 differ only
in `.init_array` contents:

```
 0x0000000000000020 (PREINIT_ARRAY)      0x1fd10
 0x0000000000000021 (PREINIT_ARRAYSZ)    16 (bytes)
 0x0000000000000019 (INIT_ARRAY)         0x1fd20
 0x000000000000001b (INIT_ARRAYSZ)       40 (bytes)

exe_first .init_array: 50090000 f00a0000 100b0000 8c0b0000 0c0c0000
exe_last  .init_array: 50090000 380a0000 b40a0000 340b0000 580c0000
```

### A4, A7: preinit also precedes shared-library constructors, including LD_PRELOAD

```
===== A4: exe preinit vs a SHARED LIBRARY constructor =====
01 PREINIT_EXE (.preinit_array, main executable)
01b PREINIT_SHIM (.preinit_array from the shim TU)
02 SHIM_CTOR (exe object)
...

===== A7: LD_PRELOAD ctor vs main-exe preinit_array =====
01 PREINIT_EXE (.preinit_array, main executable)
01b PREINIT_SHIM (.preinit_array from the shim TU)
?? PRELOAD_CTOR (LD_PRELOAD .so)
02 SHIM_CTOR (exe object)
03 GUEST_OBJ_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
05 RUST_GUEST_CTOR (rust staticlib)
99 MAIN
```

The observed glibc ordering is: **main-executable preinit → all shared-object
constructors (in dependency order, `LD_PRELOAD` included) → main-executable
`.init_array`**. A `LD_PRELOAD`ed library therefore cannot preempt a preinit
entry in the executable, but it *does* precede every executable constructor.

### A5, A5b, A0: the "main executable only" constraint

`.preinit_array` in a shared object is not merely ignored — with GNU ld 2.42 it
is a hard link error:

```
===== A0: can a shared object even CARRY a .preinit_array entry? =====
LINK REFUSED by the linker (GNU ld):
/usr/bin/ld: /tmp/ccxi3nQG.o: .preinit_array section is not allowed in DSO
/usr/bin/ld: failed to set dynamic section sizes: nonrepresentable section on output
collect2: error: ld returned 1 exit status
  but -fuse-ld=gold ACCEPTED it; dynamic tags:
 0x0000000000000019 (INIT_ARRAY)         0x1fd80
 0x000000000000001b (INIT_ARRAYSZ)       16 (bytes)
 0x0000000000000020 (PREINIT_ARRAY)      0x1fd90
 0x0000000000000021 (PREINIT_ARRAYSZ)    8 (bytes)
  [19] .preinit_array    PREINIT_ARRAY    000000000001fd90  0000fd90
```

`gold` will happily emit the DSO *with* a real `DT_PREINIT_ARRAY` tag. glibc
2.39 then ignores it at runtime, silently — the entry never fires, and nothing
warns:

```
===== A5b: if a DSO with .preinit_array could be built, does its entry fire? =====
00 SHIM_DYLIB_CTOR (shared library)
03 GUEST_OBJ_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
05 RUST_GUEST_CTOR (rust staticlib)
99 MAIN
```

(`PREINIT_DSO` is absent; only the DSO's ordinary constructor ran.)

### A6, A8, A9, A11: the delivery shapes patina would actually use

Shim as a **static archive** (`libshimar.a`, member pulled in by a symbol
reference) — the preinit entry survives archive extraction and still leads:

```
===== A8: shim delivered as a STATIC ARCHIVE =====
01b PREINIT_SHIM (.preinit_array from the shim TU)
03 GUEST_OBJ_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
02 SHIM_CTOR (exe object)
05 RUST_GUEST_CTOR (rust staticlib)
99 MAIN
```

A Rust crate can register a preinit entry directly
(`#[used] #[link_section = ".preinit_array"] static … : extern "C" fn(i32, *const *const u8, *const *const u8)`),
and it lands in a real `PREINIT_ARRAY`:

```
  [21] .preinit_array    PREINIT_ARRAY    000000000005e038  0004e038
  [22] .init_array       INIT_ARRAY       000000000005e048  0004e048
 0x0000000000000020 (PREINIT_ARRAY)      0x5e038
 0x0000000000000021 (PREINIT_ARRAYSZ)    16 (bytes)
```

rustc-driven links, dynamic and fully static:

```
===== A9: rustc-driven link, shim as -l static =====
01c PREINIT_RUST (.preinit_array registered from a Rust crate)
01b PREINIT_SHIM (.preinit_array from the shim TU)
06 GUEST_BIN_CTOR (rust binary crate's own ctor)
02 SHIM_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
99 MAIN

===== A10: rustc-driven link, shim as a shared object =====
01c PREINIT_RUST (.preinit_array registered from a Rust crate)
00 SHIM_DYLIB_CTOR (shared library)
06 GUEST_BIN_CTOR (rust binary crate's own ctor)
04 GUEST_AR_CTOR (static archive)
99 MAIN

===== A11: rustc-driven, fully static (crt-static) =====
  exe_rustmain_static: ELF 64-bit LSB executable, ARM aarch64, statically linked, for GNU/Linux 3.7.0
01c PREINIT_RUST (.preinit_array registered from a Rust crate)
01b PREINIT_SHIM (.preinit_array from the shim TU)
06 GUEST_BIN_CTOR (rust binary crate's own ctor)
02 SHIM_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
99 MAIN

===== A6: fully static C link (-static) =====
  exe_static: ELF 64-bit LSB executable, ARM aarch64, statically linked, for GNU/Linux 3.7.0
01b PREINIT_SHIM (.preinit_array from the shim TU)
02 SHIM_CTOR (exe object)
03 GUEST_OBJ_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
99 MAIN
```

Preinit leads in every one, including `crt-static`, where `__libc_start_main`
rather than `ld.so` drives initialization.

## Claim B — macOS / Mach-O

### B1–B3: order follows the link line, and flips with it

```
===== B1: shim object FIRST on the link line =====
02 SHIM_CTOR (exe object)
03 GUEST_OBJ_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
05 RUST_GUEST_CTOR (rust staticlib)
99 MAIN

===== B2: shim object LAST on the link line =====
03 GUEST_OBJ_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
05 RUST_GUEST_CTOR (rust staticlib)
02 SHIM_CTOR (exe object)
99 MAIN

===== B3: shim first, rust staticlib before the C archive, guest object last =====
02 SHIM_CTOR (exe object)
05 RUST_GUEST_CTOR (rust staticlib)
04 GUEST_AR_CTOR (static archive)
03 GUEST_OBJ_CTOR (exe object)
99 MAIN
```

The trace tracks the link line exactly in all three, across plain objects, a C
static archive, and a Rust staticlib. **Claim B holds**, and the Rust staticlib's
`__DATA,__mod_init_func` entry is an equal participant in that ordering.

### B4, B5, B8: a dylib's initializers run before all main-executable initializers

```
===== B4: shim in a dylib the exe links against =====
00 SHIM_DYLIB_CTOR (shared library)
03 GUEST_OBJ_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
05 RUST_GUEST_CTOR (rust staticlib)
99 MAIN
```

B5 repeats it with the dylib in a different position on the link line and the
result is unchanged. Among *multiple* dylibs, though, order is again link order:

```
===== B8: two dylibs =====
(link: -lshimdylib2 -lshimdylib)
00b SHIM_DYLIB2_CTOR (second shared library)
00 SHIM_DYLIB_CTOR (shared library)
03 GUEST_OBJ_CTOR ...

(link: -lshimdylib -lshimdylib2)
00 SHIM_DYLIB_CTOR (shared library)
00b SHIM_DYLIB2_CTOR (second shared library)
03 GUEST_OBJ_CTOR ...
```

### B6: the rustc-driven link — the result that matters

This is the shape patina's native family actually builds: a Rust binary crate
(with its own constructor) plus the shim as a native static library.

```
===== B6: rustc-driven link, shim as -l static =====
06 GUEST_BIN_CTOR (rust binary crate's own ctor)
02 SHIM_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
99 MAIN

===== B6b: same, but shim archive force-loaded (-Wl,-force_load via -C link-arg) =====
06 GUEST_BIN_CTOR (rust binary crate's own ctor)
04 GUEST_AR_CTOR (static archive)
02 SHIM_CTOR (exe object)
99 MAIN

===== B6c: shim as a DYLIB on a rustc-driven link =====
00 SHIM_DYLIB_CTOR (shared library)
06 GUEST_BIN_CTOR (rust binary crate's own ctor)
04 GUEST_AR_CTOR (static archive)
99 MAIN

===== B7: DYLD_INSERT_LIBRARIES against the plain rustc-driven exe =====
?? PRELOAD_CTOR (inserted dylib)
06 GUEST_BIN_CTOR (rust binary crate's own ctor)
02 SHIM_CTOR (exe object)
04 GUEST_AR_CTOR (static archive)
99 MAIN
```

rustc places the crate's own objects first and `-l static=` libraries after
them, so **the guest's constructor runs before the shim's** — and `-force_load`
made it *worse*, pushing the shim to last (rustc appends `-C link-arg` at the
end of the link line; there is no stable-channel hook to inject a link argument
ahead of the crate objects — `-Z pre-link-args` is nightly-only).

Only a dylib wins: linked as `-l dylib=` (B6c) or inserted with
`DYLD_INSERT_LIBRARIES` (B7).

## Surprises that affect the arc design

1. **macOS has no static-shim path to "first".** Claim B holds, and that is
   precisely the problem: order follows the link line, and in a rustc-driven
   link the guest's objects are always ahead of a `-l static=` shim. A prologue
   that must run before every guest constructor cannot be a static library on
   macOS. The two mechanisms that do work are a dylib the guest links against
   and `DYLD_INSERT_LIBRARIES` — both of which change the shim's packaging, and
   the latter is subject to SIP restrictions on protected binaries. The
   platforms are asymmetric: Linux gets an order-independent guarantee for free,
   macOS needs a packaging change.

2. **Preinit is not a lock on being first.** Ordering *among* `.preinit_array`
   entries is plain link order (A3). If a guest also registers a preinit entry
   — an ordinary Rust crate can, as A9/A11 show — it can run before patina's.
   The prologue design should treat "first among preinit entries" as something
   to detect and refuse, not something to assume.

3. **A `.preinit_array` in a DSO fails in two different ways.** GNU ld errors
   out loudly; gold produces a binary with a genuine `DT_PREINIT_ARRAY` that
   glibc then ignores in silence. Anything that builds or audits shared objects
   should check for the tag rather than trusting the linker to reject it.

4. **Two different Mach-O init sections are in play.** clang-linked executables
   here used `__TEXT,__init_offsets` (the newer 32-bit-offset form); the
   rustc-linked ones used `__DATA_CONST,__mod_init_func`. Any tooling that reads
   or rewrites the initializer list must handle both, and `otool -s __DATA
   __mod_init_func` silently prints nothing for the `__init_offsets` form.

5. **GNU ld's one-pass archive semantics constrain link-line rewriting.** An
   archive listed before the object that references it is simply not pulled in
   (an early revision of the probe failed this way with `undefined reference to
   guest_ar_anchor`). If the arc reorders the link line to place a shim early,
   it needs `--whole-archive`/`--start-group` or an explicit `-u` reference.

6. **`crt-static` does not change the picture on Linux.** Preinit leads under
   both `ld.so` and `__libc_start_main` (A6, A11), so a static-binary mode
   needs no separate mechanism.

## Not demonstrated

- x86_64 Linux was not tested; the Linux VM is aarch64. Nothing observed here is
  plausibly architecture-specific (glibc's `_dl_init` preinit handling is
  arch-independent), but it is untested.
- musl was not tested — only glibc 2.39.
- `DYLD_INSERT_LIBRARIES` was tested against an unsigned local binary only; SIP
  and hardened-runtime behavior for signed binaries was not probed.
- Only one macOS version (26.5.2 / dyld from build 25F84) and one Linux distro
  were measured.
