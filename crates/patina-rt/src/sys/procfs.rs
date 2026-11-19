//! Synthesised `/proc` and `/sys` files.
//!
//! An open of a listed path gets a read-only memfd holding the synthesised
//! contents, at the descriptor number a real open would have got. The
//! descriptor is marked so that `fstat`, `readlink /proc/self/fd/N` and `dup`
//! keep presenting it as the `/proc` file. Contents are a function of the run:
//! constants, the configured CPU count, the virtual clock, seeded bytes, the
//! runtime's own state, or the kernel's view of this process rewritten through
//! the same identity rules as `stat` (maps, mountinfo).

use super::*;
use crate::path::{self, fmt_dec, Global, Synth};
use crate::state::config;
use proto::layout::*;

// ---- per-descriptor marks ----

static MARKS: Global<[u8; FD_HIDDEN_MIN as usize]> = Global::new([0; FD_HIDDEN_MIN as usize]);

pub fn kind_of(fd: i64) -> Option<Synth> {
    if !(0..FD_HIDDEN_MIN as i64).contains(&fd) {
        return None;
    }
    Synth::from_u8(MARKS.get()[fd as usize])
}

/// A `/proc` directory descriptor duplicated in a `vfork` child (`dup`, `F_DUPFD`): the child
/// shares its parent's marks, so the copy would be unmarked, the kernel's `/proc`. Refused, as
/// opening one there is (`open`); recorded.
pub fn vfork_dir(fd: i64) -> bool {
    match kind_of(fd) {
        Some(k) if k.is_dir() && crate::state::in_vfork_child() => {
            path::refuse(k.path());
            true
        }
        _ => false,
    }
}

pub fn mark(fd: i64, k: Option<Synth>) {
    // a vfork child shares these marks with its parent: its descriptors are its own.
    if crate::state::in_vfork_child() {
        return;
    }
    if (0..FD_HIDDEN_MIN as i64).contains(&fd) {
        MARKS.get()[fd as usize] = k.map(|k| k as u8).unwrap_or(0);
    }
}

// ---- the guest's arguments and environment (for cmdline/environ) ----

/// Where the loader placed the argument and environment strings: [low, high, count] each,
/// the first string at the top, each below the one before (`loader::start`).
static STRS: Global<[[u64; 3]; 2]> = Global::new([[0; 3]; 2]);

/// Called by the loader: where the guest's argument and environment strings are.
pub fn note_strings(args: [u64; 3], env: [u64; 3]) {
    *STRS.get() = [args, env];
}

// ---- output buffer ----

const SCRATCH: u64 = 4 << 20;
static BUF: Global<u64> = Global::new(0);

fn scratch() -> u64 {
    let b = BUF.get();
    if *b == 0 {
        let a = crate::state::priv_alloc(SCRATCH, PAGE);
        let r = unsafe {
            sc6(
                nr::MMAP,
                a,
                SCRATCH,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                u64::MAX,
                0,
            )
        };
        if r as u64 != a {
            crate::sup::host_error(r, nr::MMAP, proto::ctl::HE_SYSCALL);
        }
        *b = a;
    }
    *b
}

pub(crate) struct W {
    p: *mut u8,
    pub n: usize,
    cap: usize,
}

impl W {
    pub fn new(b: &mut [u8]) -> W {
        W {
            p: b.as_mut_ptr(),
            n: 0,
            cap: b.len(),
        }
    }
    pub fn s(&mut self, b: &[u8]) -> &mut W {
        let k = b.len().min(self.cap - self.n);
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), self.p.add(self.n), k) };
        self.n += k;
        self
    }
    pub fn c(&mut self, ch: u8) -> &mut W {
        self.s(&[ch])
    }
    pub fn u(&mut self, v: u64) -> &mut W {
        let mut t = [0u8; 20];
        let n = fmt_dec(&mut t, v);
        self.s(&t[..n])
    }
    pub fn hex(&mut self, v: u64, width: usize) -> &mut W {
        let mut t = [b'0'; 16];
        let mut n = 0;
        let mut x = v;
        while x != 0 || n == 0 {
            t[15 - n] = b"0123456789abcdef"[(x & 15) as usize];
            x >>= 4;
            n += 1;
        }
        let n = n.max(width).min(16);
        let start = 16 - n;
        self.s(&t[start..])
    }
    pub fn bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.p, self.n) }
    }
}

fn read_real(path: &[u8], buf: &mut [u8]) -> usize {
    crate::loader::read_file(path, buf)
}

fn uname_field(field: usize) -> ([u8; 65], usize) {
    let mut u = [0u8; 390];
    unsafe { sc1(nr::UNAME, u.as_mut_ptr() as u64) };
    let mut out = [0u8; 65];
    out.copy_from_slice(&u[field * 65..field * 65 + 65]);
    let n = out.iter().position(|&c| c == 0).unwrap_or(65);
    (out, n)
}

fn cpus() -> u64 {
    config().cpu_count.max(1)
}

fn now_ns() -> u64 {
    ctl().vclock_ns.load(Relaxed)
}

/// Rewrite the device and inode of one mapping line (`/proc/self/maps` format).
fn maps_line(w: &mut W, line: &[u8]) -> bool {
    let mut f = line.splitn(6, |&c| c == b' ');
    let range = f.next().unwrap_or(b"");
    let perms = f.next().unwrap_or(b"");
    let off = f.next().unwrap_or(b"");
    let dev = f.next().unwrap_or(b"");
    let ino = f.next().unwrap_or(b"");
    let rest = f.next().unwrap_or(b"");
    let pathname = {
        let i = rest.iter().position(|&c| c != b' ').unwrap_or(rest.len());
        &rest[i..]
    };
    let dash = range.iter().position(|&c| c == b'-').unwrap_or(0);
    let start = hexv(&range[..dash]);
    if (RT_BASE..RT_REGION_END).contains(&start) {
        return false; // the runtime's own mappings
    }
    if pathname == b"[stack]"
        || pathname == b"[vdso]"
        || pathname == b"[vvar]"
        || pathname == b"[vvar_vclock]"
    {
        return false; // the kernel's start-up stack (the runtime's), the vDSO
    }
    let colon = dev.iter().position(|&c| c == b':').unwrap_or(0);
    let (ma, mi) = (
        hexv(&dev[..colon]),
        hexv(dev.get(colon + 1..).unwrap_or(b"")),
    );
    let real_ino = path::dec(ino);
    let (vdev, vino) = if ma == 0 && mi == 0 {
        (0, real_ino)
    } else {
        let id = super::fs::ident(path::makedev(ma, mi), real_ino);
        (id.dev, id.ino)
    };
    let l0 = w.n;
    w.s(range).c(b' ').s(perms).c(b' ').s(off).c(b' ');
    w.hex(path::dev_major(vdev), 2)
        .c(b':')
        .hex(path::dev_minor(vdev), 2)
        .c(b' ')
        .u(vino);
    if !pathname.is_empty() {
        while w.n - l0 < 73 {
            w.c(b' ');
        }
        w.s(pathname);
    }
    w.c(b'\n');
    true
}

pub(crate) fn hexv(s: &[u8]) -> u64 {
    let mut v = 0u64;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => break,
        };
        v = (v << 4) | d as u64;
    }
    v
}

fn maps(w: &mut W, smaps: bool) {
    let base = scratch() + SCRATCH / 2;
    let real = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, (SCRATCH / 2) as usize) };
    let n = read_real(b"/proc/self/maps\0", real);
    let mut emit = |line: &[u8]| {
        if maps_line(w, line) && smaps {
            let dash = line.iter().position(|&c| c == b'-').unwrap_or(0);
            let sp = line.iter().position(|&c| c == b' ').unwrap_or(0);
            let size = (hexv(&line[dash + 1..sp]) - hexv(&line[..dash])) / 1024;
            w.s(b"Size:           ")
                .u(size)
                .s(b" kB\nKernelPageSize:        4 kB\nMMUPageSize:           4 kB\n");
            for k in [
                "Rss",
                "Pss",
                "Pss_Dirty",
                "Shared_Clean",
                "Shared_Dirty",
                "Private_Clean",
                "Private_Dirty",
                "Referenced",
                "Anonymous",
                "KSM",
                "LazyFree",
                "AnonHugePages",
                "ShmemPmdMapped",
                "FilePmdMapped",
                "Shared_Hugetlb",
                "Private_Hugetlb",
                "Swap",
                "SwapPss",
                "Locked",
            ] {
                w.s(k.as_bytes()).s(b":");
                for _ in k.len()..15 {
                    w.c(b' ');
                }
                w.s(b"0 kB\n");
            }
            w.s(b"THPeligible:    0\nVmFlags: rd wr mr mw me\n");
        }
    };
    // With load-time plans: the original file's lines (`plans::Maps`).
    let mut fix = crate::plans::Maps::new();
    for line in real[..n].split(|&c| c == b'\n') {
        if !line.is_empty() {
            fix.feed(line, &mut emit);
        }
    }
    fix.flush(&mut emit);
}

/// mountinfo with virtual ids (index + 1, as `statx` reports) and device numbers.
fn mountinfo(w: &mut W, plain: bool) {
    let base = scratch() + SCRATCH / 2;
    let real = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, (SCRATCH / 2) as usize) };
    let n = read_real(b"/proc/self/mountinfo\0", real);
    let t = path::mounts();
    let idx = |id: u64| {
        t.m[..t.n]
            .iter()
            .position(|m| m.id == id)
            .map(|i| i as u64 + 1)
            .unwrap_or(0)
    };
    for line in real[..n].split(|&c| c == b'\n') {
        if line.is_empty() {
            continue;
        }
        let fields: [&[u8]; 6] = {
            let mut it = line.splitn(7, |&c| c == b' ');
            [
                it.next().unwrap_or(b""),
                it.next().unwrap_or(b""),
                it.next().unwrap_or(b""),
                it.next().unwrap_or(b""),
                it.next().unwrap_or(b""),
                it.next().unwrap_or(b""),
            ]
        };
        let sep = line
            .windows(3)
            .position(|x| x == b" - ")
            .map(|i| &line[i + 3..])
            .unwrap_or(b"");
        let mut tail = sep.splitn(3, |&c| c == b' ');
        let (fstype, mut source, mut sopts) = (
            tail.next().unwrap_or(b""),
            tail.next().unwrap_or(b""),
            tail.next().unwrap_or(b""),
        );
        // Filesystems the sandbox did not create (the host's disks, devtmpfs behind the device
        // binds) carry host facts in their source and super options: device names, RAM size.
        if !matches!(fstype, b"tmpfs" | b"proc" | b"devpts") {
            source = b"host";
            sopts = b"rw";
        }
        // The root column of a bind names a host path (or bwrap's randomly named temporary
        // file): show the mount point instead.
        let root = if fields[3] == b"/" || fields[4] == b"/" {
            &b"/"[..]
        } else {
            fields[4]
        };
        // Per-mount flags of a bind (relatime, noatime, nosuid...) are inherited from the
        // host's mount of the source: only read-only or read-write is the sandbox's choice.
        let mopts: &[u8] = if fields[5].split(|&c| c == b',').any(|o| o == b"ro") {
            b"ro"
        } else {
            b"rw"
        };
        if plain {
            // /proc/self/mounts: source point fstype options 0 0 (options as mount options)
            w.s(source)
                .c(b' ')
                .s(fields[4])
                .c(b' ')
                .s(fstype)
                .c(b' ')
                .s(mopts)
                .s(b" 0 0\n");
            continue;
        }
        let id = path::dec(fields[0]);
        let mm = fields[2];
        let colon = mm.iter().position(|&c| c == b':').unwrap_or(0);
        let dev = path::makedev(path::dec(&mm[..colon]), path::dec(&mm[colon + 1..]));
        // Every mount's device reads as its index, host filesystems included (as in `stat`).
        let vdev = match path::mount_index(dev) {
            Some(i) => path::makedev(0, VDEV_MOUNT_BASE + i as u64),
            None => 0,
        };
        w.u(idx(id)).c(b' ').u(idx(path::dec(fields[1]))).c(b' ');
        w.u(path::dev_major(vdev))
            .c(b':')
            .u(path::dev_minor(vdev))
            .c(b' ');
        w.s(root)
            .c(b' ')
            .s(fields[4])
            .c(b' ')
            .s(mopts)
            .s(b" - ")
            .s(fstype)
            .c(b' ')
            .s(source)
            .c(b' ');
        if fstype == b"tmpfs" {
            tmpfs_opts(w, sopts, fields[4]);
        } else {
            w.s(sopts);
        }
        w.c(b'\n');
    }
}

/// tmpfs super options without host RAM. The kernel prints `size=` and `nr_inodes=` when they
/// differ from the defaults computed from the RAM *at the time of reading*; when the VM's balloon
/// moves RAM after the mount, `size=16406100k,nr_inodes=...` appears on mounts that set neither
/// (seen under parallel load; Go and Rust std read mountinfo at start-up). Kept: `size=` of the
/// mounts the launcher sizes (`/work`, `/tmp`).
fn tmpfs_opts(w: &mut W, sopts: &[u8], point: &[u8]) {
    let sized = point == crate::state::config().work_path() || point == b"/tmp";
    let mut first = true;
    for o in sopts.split(|&c| c == b',') {
        // uid= and gid= name the launcher's own ids on the host (1000 on one machine, 1001
        // on another), not the sandbox's: left out, as `stat` shows the owner 1000.
        if o.starts_with(b"nr_inodes=")
            || (o.starts_with(b"size=") && !sized)
            || o.starts_with(b"uid=")
            || o.starts_with(b"gid=")
        {
            continue;
        }
        if !first {
            w.c(b',');
        }
        w.s(o);
        first = false;
    }
}

/// The strings of one block (`note_strings`), first to last, as they are now in memory.
fn strings(w: &mut W, [lo, hi, n]: [u64; 3]) {
    let byte = |a: u64| unsafe { *(a as *const u8) };
    let mut end = hi; // one past the NUL of the next string
    for _ in 0..n {
        if end <= lo {
            break;
        }
        let mut s = end - 1;
        while s > lo && byte(s - 1) != 0 {
            s -= 1;
        }
        w.s(unsafe { core::slice::from_raw_parts(s as *const u8, (end - 1 - s) as usize) })
            .c(0);
        end = s;
    }
}

fn comm(w: &mut W) {
    let mut c = [0u8; 17];
    unsafe { sc2(nr::PRCTL, 16, c.as_mut_ptr() as u64) }; // PR_GET_NAME
    let n = c.iter().position(|&x| x == 0).unwrap_or(16);
    w.s(&c[..n]);
}

fn uuid(w: &mut W, bytes: [u8; 16]) {
    let mut b = bytes;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    for (i, x) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            w.c(b'-');
        }
        w.hex(*x as u64, 2);
    }
    w.c(b'\n');
}

fn cpuinfo(w: &mut W) {
    let base = scratch() + SCRATCH / 2;
    let real = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, (SCRATCH / 2) as usize) };
    let n = read_real(b"/proc/cpuinfo\0", real);
    let first = real[..n]
        .windows(2)
        .position(|x| x == b"\n\n")
        .map(|i| i + 1)
        .unwrap_or(n);
    let block = &real[..first];
    for cpu in 0..cpus() {
        for line in block.split(|&c| c == b'\n') {
            if line.is_empty() {
                continue;
            }
            let key = line.split(|&c| c == b':').next().unwrap_or(b"");
            let key = &key[..key
                .iter()
                .rposition(|&c| c != b' ' && c != b'\t')
                .map(|i| i + 1)
                .unwrap_or(0)];
            match key {
                b"cpu MHz" | b"bogomips" | b"BogoMIPS" => continue, // frequency and calibration vary
                // arm64: the features the auxiliary vector hides are not listed either.
                b"Features" => {
                    let colon = line.iter().position(|&c| c == b':').unwrap_or(0);
                    w.s(&line[..colon + 1]);
                    for f in line[colon + 1..].split(|&c| c == b' ') {
                        if !f.is_empty() && !crate::arch::feature_hidden(f) {
                            w.c(b' ').s(f);
                        }
                    }
                    w.c(b'\n');
                }
                b"processor" | b"core id" | b"apicid" | b"initial apicid" => {
                    w.s(&line[..line.iter().position(|&c| c == b':').unwrap_or(0) + 1])
                        .c(b' ')
                        .u(cpu)
                        .c(b'\n');
                }
                b"siblings" | b"cpu cores" => {
                    w.s(&line[..line.iter().position(|&c| c == b':').unwrap_or(0) + 1])
                        .c(b' ')
                        .u(cpus())
                        .c(b'\n');
                }
                _ => {
                    w.s(line).c(b'\n');
                }
            }
        }
        w.c(b'\n');
    }
}

fn cpu_list(w: &mut W) {
    if cpus() == 1 {
        w.s(b"0\n");
    } else {
        w.s(b"0-").u(cpus() - 1).c(b'\n');
    }
}

const MEM_TOTAL_KB: u64 = 16 << 20;
const MEM_FREE_KB: u64 = 12 << 20;

/// The contents of a synthesised file.
fn content(k: Synth, w: &mut W) {
    let pid = crate::state::thread().pid as u64;
    let ppid = unsafe { sc0(nr::GETPPID) } as u64;
    let s = STRS.get();
    let uid = unsafe { sc0(nr::GETUID) } as u64;
    let gid = unsafe { sc0(nr::GETGID) } as u64;
    let cpu_ticks = crate::state::thread().cpu_ns() / 10_000_000;
    match k {
        Synth::Maps => maps(w, false),
        Synth::Smaps => maps(w, true),
        Synth::Stat => {
            w.u(pid).s(b" (");
            comm(w);
            w.s(b") R ")
                .u(ppid)
                .c(b' ')
                .u(pid)
                .c(b' ')
                .u(pid)
                .s(b" 0 -1 4194560 0 0 0 0 ")
                .u(cpu_ticks)
                .s(b" 0 0 0 20 0 1 0 0 0 0 18446744073709551615");
            for _ in 26..=52 {
                w.s(b" 0");
            }
            w.c(b'\n');
        }
        Synth::Status => {
            w.s(b"Name:\t");
            comm(w);
            w.s(b"\nUmask:\t0022\nState:\tR (running)\nTgid:\t")
                .u(pid)
                .s(b"\nNgid:\t0\nPid:\t")
                .u(pid)
                .s(b"\nPPid:\t")
                .u(ppid);
            w.s(b"\nTracerPid:\t0\nUid:\t")
                .u(uid)
                .c(b'\t')
                .u(uid)
                .c(b'\t')
                .u(uid)
                .c(b'\t')
                .u(uid);
            w.s(b"\nGid:\t")
                .u(gid)
                .c(b'\t')
                .u(gid)
                .c(b'\t')
                .u(gid)
                .c(b'\t')
                .u(gid);
            w.s(b"\nFDSize:\t64\nGroups:\t\nVmPeak:\t       0 kB\nVmSize:\t       0 kB\nVmRSS:\t       0 kB\nThreads:\t1\n");
            w.s(b"SigQ:\t0/0\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\nSigBlk:\t0000000000000000\n");
            w.s(b"SigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n");
            w.s(b"CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t0\nCpus_allowed_list:\t");
            cpu_list(w);
            w.s(b"voluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n");
        }
        Synth::Statm => {
            w.s(b"0 0 0 0 0 0 0\n");
        }
        Synth::Cgroup => {
            w.s(b"0::/\n");
        }
        Synth::Mountinfo => mountinfo(w, false),
        Synth::Mounts => mountinfo(w, true),
        Synth::Cmdline => strings(w, s[0]),
        Synth::Environ => strings(w, s[1]),
        Synth::Comm => {
            comm(w);
            w.c(b'\n');
        }
        Synth::Cpuinfo => cpuinfo(w),
        Synth::Meminfo => {
            w.s(b"MemTotal:       ")
                .u(MEM_TOTAL_KB)
                .s(b" kB\nMemFree:        ")
                .u(MEM_FREE_KB);
            w.s(b" kB\nMemAvailable:   ")
                .u(MEM_FREE_KB)
                .s(b" kB\nBuffers:               0 kB\nCached:                0 kB\n");
            w.s(b"SwapCached:            0 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\nShmem:                 0 kB\n");
            w.s(b"HugePages_Total:       0\nHugePages_Free:        0\nHugepagesize:       2048 kB\n");
        }
        Synth::SysStat => {
            w.s(b"cpu  0 0 0 0 0 0 0 0 0 0\n");
            for c in 0..cpus() {
                w.s(b"cpu").u(c).s(b" 0 0 0 0 0 0 0 0 0 0\n");
            }
            w.s(b"intr 0\nctxt 0\nbtime ")
                .u(REALTIME_EPOCH_S - VCLOCK_BOOT_NS / 1_000_000_000);
            w.s(b"\nprocesses 1\nprocs_running 1\nprocs_blocked 0\nsoftirq 0\n");
        }
        Synth::Uptime => {
            let t = now_ns() / 10_000_000;
            w.u(t / 100).c(b'.').u(t % 100 / 10).u(t % 10).s(b" 0.00\n");
        }
        Synth::Loadavg => {
            w.s(b"0.00 0.00 0.00 1/1 ").u(pid).c(b'\n');
        }
        Synth::Version => {
            let (r, rn) = uname_field(2);
            let (v, vn) = uname_field(3);
            w.s(b"Linux version ")
                .s(&r[..rn])
                .s(b" (patina) ")
                .s(&v[..vn])
                .c(b'\n');
        }
        Synth::Filesystems => {
            w.s(b"nodev\tsysfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tdevtmpfs\nnodev\tpipefs\nnodev\tdevpts\n\text4\n");
        }
        Synth::Osrelease => {
            let (r, rn) = uname_field(2);
            w.s(&r[..rn]).c(b'\n');
        }
        Synth::PidMax => {
            w.s(b"4194304\n");
        }
        Synth::NgroupsMax => {
            w.s(b"65536\n");
        }
        Synth::Somaxconn => {
            w.s(b"4096\n");
        }
        Synth::Uuid => {
            let mut b = [0u8; 16];
            proto::fill(
                config().seed,
                proto::Stream::Entropy,
                crate::state::thread().seq,
                &mut b,
            );
            uuid(w, b);
        }
        Synth::BootId => {
            let mut b = [0u8; 16];
            proto::fill(config().seed, proto::Stream::Entropy, u64::MAX, &mut b);
            uuid(w, b);
        }
        Synth::Overcommit => {
            w.s(b"0\n");
        }
        Synth::CpuOnline | Synth::CpuPossible | Synth::CpuPresent => cpu_list(w),
        Synth::ThpEnabled => {
            w.s(b"always [madvise] never\n");
        }
        Synth::ThpDefrag => {
            w.s(b"always defer defer+madvise [madvise] never\n");
        }
        Synth::ThpPmdSize => {
            w.s(b"2097152\n");
        }
        Synth::Task | Synth::ProcDir | Synth::SelfDir | Synth::FdDir => {}
        Synth::ThpShmem => {
            w.s(b"always within_size advise [never] deny force\n");
        }
    }
}

/// Open a synthesised file: a read-only memfd at the lowest free descriptor. A directory is a
/// real one (`/proc`, or `/proc/self/fd` for the descriptor list), marked: what it lists and
/// what `stat` says of it are the runtime's (`getdents`, `fake_stat`), and names relative to it
/// are policed as the paths they name (`path::dir_base`), so the kernel never walks from it.
pub fn open(k: Synth, cloexec: bool) -> i64 {
    const MFD_CLOEXEC: u64 = 1;
    use proto::abi::open::O_DIRECTORY;
    const O_CLOEXEC_: u64 = 0o2000000;
    if k.is_dir() {
        // A vfork child shares its parent's marks but not its descriptors: it cannot keep one.
        if crate::state::in_vfork_child() {
            path::refuse(k.path());
            return -e::EACCES;
        }
        // The real directory of the kind (`dir_kind` finds the kind again after exec); the
        // kernel lists or walks none of them (`getdents_fds` reads a fresh `/proc/self/fd`).
        let real: &core::ffi::CStr = match k {
            Synth::FdDir => c"/proc/self/fd",
            Synth::Task => c"/proc/self/task",
            Synth::SelfDir => c"/proc/self",
            _ => c"/proc",
        };
        let fd = unsafe {
            sc4(
                nr::OPENAT,
                (-100i64) as u64,
                real.as_ptr() as u64,
                O_DIRECTORY | if cloexec { O_CLOEXEC_ } else { 0 },
                0,
            )
        };
        if fd >= 0 {
            mark(fd, Some(k));
        }
        return fd;
    }
    let mut w = W {
        p: scratch() as *mut u8,
        n: 0,
        cap: (SCRATCH / 2) as usize,
    };
    content(k, &mut w);
    // The kind is in the name, so that an image started by execve finds the mark again.
    let mut name = *b"patina-proc:000\0";
    let kv = k as u8;
    name[12] = b'0' + kv / 100;
    name[13] = b'0' + (kv / 10) % 10;
    name[14] = b'0' + kv % 10;
    let fd = unsafe {
        sc2(
            nr::MEMFD_CREATE,
            name.as_ptr() as u64,
            if cloexec { MFD_CLOEXEC } else { 0 },
        )
    };
    if fd < 0 {
        return fd;
    }
    let data = w.bytes();
    let mut off = 0;
    while off < data.len() {
        let r = unsafe {
            sc3(
                nr::WRITE,
                fd as u64,
                data.as_ptr() as u64 + off as u64,
                (data.len() - off) as u64,
            )
        };
        if r <= 0 {
            crate::sup::host_error(r, nr::WRITE, proto::ctl::HE_SYSCALL);
        }
        off += r as usize;
    }
    // Reopen read-only through the descriptor link and put it at the same number.
    let mut lp = [0u8; 32];
    let mut l = 0;
    for &c in b"/proc/self/fd/" {
        lp[l] = c;
        l += 1;
    }
    l += fmt_dec(&mut lp[l..], fd as u64);
    lp[l] = 0;
    const O_CLOEXEC: u64 = 0o2000000;
    let ro = unsafe {
        sc4(
            nr::OPENAT,
            (-100i64) as u64,
            lp.as_ptr() as u64,
            if cloexec { O_CLOEXEC } else { 0 },
            0,
        )
    };
    if ro < 0 {
        crate::sup::host_error(ro, nr::OPENAT, proto::ctl::HE_SYSCALL);
    }
    unsafe {
        sc3(
            nr::DUP3,
            ro as u64,
            fd as u64,
            if cloexec { O_CLOEXEC } else { 0 },
        ); // dup3
        sc1(nr::CLOSE, ro as u64);
    }
    mark(fd, Some(k));
    fd
}

fn proc_dev() -> u64 {
    let t = path::mounts();
    match t.m[..t.n]
        .iter()
        .position(|m| m.class == path::MountClass::Proc)
    {
        Some(i) => path::makedev(0, VDEV_MOUNT_BASE + i as u64),
        None => 0,
    }
}

fn fake_ino(k: Synth) -> u64 {
    0x4000 + k as u64
}

fn fake_mode(k: Synth) -> u32 {
    match k {
        Synth::FdDir => 0o040500,
        k if k.is_dir() => 0o040555,
        Synth::Environ => 0o100400,
        _ => 0o100444,
    }
}

/// The run's live threads of this process, by the supervisor's slots (a thread that has
/// exited is gone, whether or not the kernel has reaped it yet), in ascending tid order.
fn threads(out: &mut [i32; proto::ctl::MAX_THREADS]) -> usize {
    let pid = crate::state::thread().pid;
    let c = ctl();
    let mut n = 0;
    for i in 0..proto::ctl::MAX_THREADS {
        let s = unsafe { &*c.slot(i) };
        if s.state.load(Acquire) == proto::ctl::SLOT_LIVE && s.pid.load(Relaxed) == pid {
            out[n] = s.tid.load(Relaxed);
            n += 1;
        }
    }
    out[..n].sort_unstable();
    n
}

/// Link count: a directory has 2 and one more for each directory in it.
fn fake_nlink(k: Synth) -> u32 {
    match k {
        Synth::Task => 2 + threads(&mut [0; proto::ctl::MAX_THREADS]) as u32,
        // `self` reads as a directory; this process's id is one more.
        Synth::ProcDir => 3,
        Synth::SelfDir => 2 + path::SELF_SYNTH.iter().filter(|(_, k)| k.is_dir()).count() as u32,
        Synth::FdDir => 2,
        _ => 1,
    }
}

/// `struct stat` of a synthesised file.
pub fn fake_stat(k: Synth, p: u64) -> i64 {
    let uid = unsafe { sc0(nr::GETUID) } as u32;
    let gid = unsafe { sc0(nr::GETGID) } as u32;
    let t = crate::vtime::epoch() / 1_000_000_000;
    let st = proto::abi::stat::Stat::new(
        proc_dev(),
        fake_ino(k),
        fake_nlink(k),
        fake_mode(k),
        uid,
        gid,
        1024,
        t,
    );
    crate::guest::put(p, st).err().unwrap_or(0)
}

/// `struct statx` of a synthesised file.
pub fn fake_statx(k: Synth, p: u64) -> i64 {
    let mut b = [0u8; 256];
    let put32 = |b: &mut [u8; 256], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    let put64 = |b: &mut [u8; 256], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    let uid = unsafe { sc0(nr::GETUID) } as u32;
    let gid = unsafe { sc0(nr::GETGID) } as u32;
    put32(&mut b, 0, 0x7ff | 0x1000); // basic stats, mount id
    put32(&mut b, 4, 1024);
    put32(&mut b, 16, fake_nlink(k));
    put32(&mut b, 20, uid);
    put32(&mut b, 24, gid);
    b[28..30].copy_from_slice(&(fake_mode(k) as u16).to_le_bytes());
    put64(&mut b, 32, fake_ino(k));
    let t = crate::vtime::epoch() / 1_000_000_000;
    for o in [64, 96, 112] {
        put64(&mut b, o, t);
    }
    let d = proc_dev();
    put32(&mut b, 136, path::dev_major(d) as u32);
    put32(&mut b, 140, path::dev_minor(d) as u32);
    let t = path::mounts();
    let idx = t.m[..t.n]
        .iter()
        .position(|m| m.class == path::MountClass::Proc)
        .map(|i| i as u64 + 1)
        .unwrap_or(0);
    put64(&mut b, 144, idx);
    crate::guest::write(p, &b).err().unwrap_or(0)
}

/// `struct statfs` of `/proc`: constants.
pub fn fake_statfs(p: u64) -> i64 {
    let mut w = [0u64; 15];
    w[0] = 0x9fa0; // PROC_SUPER_MAGIC
    w[1] = 4096;
    w[8] = 255;
    w[9] = 4096;
    w[10] = 0x26; // ST_NOSUID|ST_NODEV|ST_NOEXEC|ST_RELATIME... as proc reports
    crate::guest::put(p, w).err().unwrap_or(0)
}

// ---- directory listings ----

const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;

/// Entry `i` of a directory the runtime lists (`.`, `..`, then its names, in a fixed order):
/// its name (in `name`, the length returned), type and inode number.
fn entry(k: Synth, i: usize, tids: &[i32], name: &mut [u8; 24]) -> Option<(usize, u8, u64)> {
    let mut put = |s: &[u8]| {
        name[..s.len()].copy_from_slice(s);
        s.len()
    };
    let parent = match k {
        Synth::Task => Synth::SelfDir,
        _ => Synth::ProcDir,
    };
    match i {
        0 => return Some((put(b"."), DT_DIR, fake_ino(k))),
        1 => return Some((put(b".."), DT_DIR, fake_ino(parent))),
        _ => {}
    }
    let i = i - 2;
    let dtype = |k: Synth| if k.is_dir() { DT_DIR } else { DT_REG };
    match k {
        Synth::Task => tids
            .get(i)
            .map(|&t| (fmt_dec(name, t as u64), DT_DIR, 0x10000 + t as u64)),
        Synth::SelfDir => match path::SELF_SYNTH.get(i) {
            Some((n, s)) => Some((put(n), dtype(*s), fake_ino(*s))),
            None if i == path::SELF_SYNTH.len() => Some((put(b"exe"), DT_LNK, 0x40ff)),
            None => None,
        },
        Synth::ProcDir => {
            // The policy's files and directories one level under /proc, then this process.
            let mut top = path::SYNTH_PATHS.iter().filter_map(|(p, s)| {
                let n = p.strip_prefix(b"/proc/")?;
                (!n.contains(&b'/')).then_some((n, *s))
            });
            let n = top.clone().count();
            if let Some((p, s)) = top.nth(i) {
                Some((put(p), dtype(s), fake_ino(s)))
            } else if i == n {
                let pid = crate::state::thread().pid as u64;
                Some((fmt_dec(name, pid), DT_DIR, fake_ino(Synth::SelfDir)))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// getdents on a directory the runtime lists (all but the descriptor list): from the entry the
/// descriptor's offset names (the kernel's offset of the real directory, used as an index, so
/// it is shared by duplicates and forks and `lseek` rewinds it), as many as fit.
pub fn getdents_listed(k: Synth, fd: i64, buf: u64, len: u64, old: bool) -> i64 {
    let pos = unsafe { sc3(nr::LSEEK, fd as u64, 0, SEEK_CUR) };
    if pos < 0 {
        return pos;
    }
    let mut tids = [0i32; proto::ctl::MAX_THREADS];
    let nt = if k == Synth::Task {
        threads(&mut tids)
    } else {
        0
    };
    let cap = len.min(SCRATCH / 2) as usize;
    let out = unsafe { core::slice::from_raw_parts_mut(scratch() as *mut u8, cap) };
    let mut n = 0;
    let mut i = pos as usize;
    let mut name = [0u8; 24];
    while let Some((l, ty, ino)) = entry(k, i, &tids[..nt], &mut name) {
        // linux_dirent64: ino, off, reclen, type, name, NUL; linux_dirent: ino, off, reclen,
        // name, NUL, type; both padded to 8 bytes.
        let (at, reclen) = if old {
            (18, (18 + l + 2 + 7) & !7)
        } else {
            (19, (19 + l + 1 + 7) & !7)
        };
        if n + reclen > cap {
            break;
        }
        let r = &mut out[n..n + reclen];
        r.fill(0);
        r[0..8].copy_from_slice(&ino.to_le_bytes());
        r[8..16].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        r[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        r[at..at + l].copy_from_slice(&name[..l]);
        if old {
            r[reclen - 1] = ty;
        } else {
            r[18] = ty;
        }
        n += reclen;
        i += 1;
    }
    if n == 0 && entry(k, i, &tids[..nt], &mut name).is_some() {
        return -e::EINVAL; // the buffer holds not even one entry
    }
    if let Err(r) = crate::guest::write(buf, &out[..n]) {
        return r;
    }
    unsafe { sc3(nr::LSEEK, fd as u64, i as u64, SEEK_SET) };
    n as i64
}

/// getdents on `/proc/self/fd`: the kernel's list without the runtime's own descriptors
/// (`FD_HIDDEN_MIN` and above, last in the kernel's ascending order), read into the runtime's
/// memory first so the program never sees their numbers; inode numbers become virtual.
pub fn getdents_fds(fd: i64, buf: u64, len: u64, old: bool) -> i64 {
    // The calling process's descriptors (after a fork the inherited descriptor still names
    // the parent's): a fresh `/proc/self/fd`, at a runtime number, read from the descriptor's
    // position (the kernel's position in such a listing is the next descriptor number + 2).
    let fresh = crate::spin::open_hidden(b"/proc/self/fd\0", proto::abi::open::O_DIRECTORY);
    if fresh < 0 {
        return -e::EIO;
    }
    let pos = unsafe { sc3(nr::LSEEK, fd as u64, 0, 1) };
    let r = if pos < 0 {
        pos
    } else {
        unsafe { sc3(nr::LSEEK, fresh as u64, pos as u64, 0) };
        let r = fds_from(fresh as i64, buf, len, old);
        let end = unsafe { sc3(nr::LSEEK, fresh as u64, 0, 1) };
        if end >= 0 {
            unsafe { sc3(nr::LSEEK, fd as u64, end as u64, 0) };
        }
        r
    };
    unsafe { sc1(nr::CLOSE, fresh as u64) };
    r
}

fn fds_from(fd: i64, buf: u64, len: u64, old: bool) -> i64 {
    let cap = len.min(SCRATCH / 2);
    let w = scratch();
    let at = if old { 18 } else { 19 };
    loop {
        let r = unsafe {
            sc3(
                if old { nr::GETDENTS } else { nr::GETDENTS64 },
                fd as u64,
                w,
                cap,
            )
        };
        if r <= 0 {
            return r;
        }
        let b = unsafe { core::slice::from_raw_parts_mut(w as *mut u8, r as usize) };
        let (mut off, mut m) = (0usize, 0usize);
        while off < r as usize {
            let reclen = u16::from_le_bytes([b[off + 16], b[off + 17]]) as usize;
            if reclen == 0 {
                break;
            }
            let name = &b[off + at..off + reclen];
            let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
            let hidden = !name.is_empty()
                && name.iter().all(|c| c.is_ascii_digit())
                && path::dec(name) >= FD_HIDDEN_MIN as u64;
            if !hidden {
                b.copy_within(off..off + reclen, m);
                m += reclen;
            }
            off += reclen;
        }
        if m > 0 {
            rewrite_dents(w, m as i64, old);
            return match crate::guest::write(buf, &b[..m]) {
                Ok(()) => m as i64,
                Err(e) => e,
            };
        }
    }
}

/// Inode numbers of a `/proc` listing become virtual.
fn rewrite_dents(buf: u64, len: i64, old: bool) {
    let t = path::mounts();
    let Some(m) = t.m[..t.n]
        .iter()
        .find(|m| m.class == path::MountClass::Proc)
    else {
        return;
    };
    let mut off = 0i64;
    while off < len {
        let rec = buf + off as u64;
        let reclen = unsafe { *((rec + 16) as *const u16) } as i64;
        if reclen == 0 {
            break;
        }
        unsafe {
            let ino = *(rec as *const u64);
            *(rec as *mut u64) = crate::vino::of(m.dev, ino);
        }
        let _ = old; // d_ino is the first word in both record layouts
        off += reclen;
    }
}

/// The kind of an inherited descriptor of a directory under `/proc` (a new image finds its
/// marks again, `exec::rescan_marks`): by its real path (`open` opens `/proc`, `/proc/PID`,
/// `/proc/PID/fd`, `/proc/PID/task`). Every directory under `/proc` gets a kind, `/proc`'s if
/// no other, so none is ever a base the kernel walks from.
pub fn dir_kind(real: &[u8]) -> Option<Synth> {
    let r = match real.strip_prefix(b"/proc") {
        Some(r) if r.is_empty() || r[0] == b'/' => r,
        _ => return None,
    };
    let r = r.strip_prefix(b"/").unwrap_or(r);
    let n = r.iter().position(|&c| c == b'/').unwrap_or(r.len());
    if n == 0 || !r[..n].iter().all(|c| c.is_ascii_digit()) {
        return Some(Synth::ProcDir);
    }
    Some(match &r[n..] {
        b"" => Synth::SelfDir,
        b"/fd" => Synth::FdDir,
        b"/task" => Synth::Task,
        _ => Synth::ProcDir,
    })
}
