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

const MAX_STRS: usize = 4096;
struct Strs {
    args: [u64; MAX_STRS],
    nargs: usize,
    env: [u64; MAX_STRS],
    nenv: usize,
}
static STRS: Global<Strs> = Global::new(Strs {
    args: [0; MAX_STRS],
    nargs: 0,
    env: [0; MAX_STRS],
    nenv: 0,
});

/// Called by the loader: where the guest's argument and environment strings are.
pub fn note_strings(args: &[u64], env: &[u64]) {
    let s = STRS.get();
    s.nargs = args.len().min(MAX_STRS);
    s.args[..s.nargs].copy_from_slice(&args[..s.nargs]);
    s.nenv = env.len().min(MAX_STRS);
    s.env[..s.nenv].copy_from_slice(&env[..s.nenv]);
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

struct W {
    p: *mut u8,
    n: usize,
    cap: usize,
}

impl W {
    fn s(&mut self, b: &[u8]) -> &mut W {
        let k = b.len().min(self.cap - self.n);
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), self.p.add(self.n), k) };
        self.n += k;
        self
    }
    fn c(&mut self, ch: u8) -> &mut W {
        self.s(&[ch])
    }
    fn u(&mut self, v: u64) -> &mut W {
        let mut t = [0u8; 20];
        let n = fmt_dec(&mut t, v);
        self.s(&t[..n])
    }
    fn hex(&mut self, v: u64, width: usize) -> &mut W {
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
    fn bytes(&self) -> &[u8] {
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

fn hexv(s: &[u8]) -> u64 {
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
    for line in real[..n].split(|&c| c == b'\n') {
        if line.is_empty() {
            continue;
        }
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
    }
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

fn strings(w: &mut W, v: &[u64]) {
    for &p in v {
        if p != 0 {
            w.s(unsafe { crate::loader::cstr(p as *const u8) }).c(0);
        }
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
                b"cpu MHz" | b"bogomips" => continue, // frequency and calibration vary
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
        Synth::Cmdline => strings(w, &s.args[..s.nargs]),
        Synth::Environ => strings(w, &s.env[..s.nenv]),
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
        Synth::Task => {}
        Synth::ThpShmem => {
            w.s(b"always within_size advise [never] deny force\n");
        }
    }
}

/// Open a synthesised file: a read-only memfd at the lowest free descriptor.
pub fn open(k: Synth, cloexec: bool) -> i64 {
    const MFD_CLOEXEC: u64 = 1;
    const O_DIRECTORY: u64 = 0o200000;
    const O_CLOEXEC_: u64 = 0o2000000;
    if k == Synth::Task {
        // The thread list is sandbox history (tids in the PID namespace); only the inode
        // numbers that getdents and fstat show are rewritten.
        let fd = unsafe {
            sc4(
                nr::OPENAT,
                (-100i64) as u64,
                c"/proc/self/task".as_ptr() as u64,
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
    if k == Synth::Task {
        return 0o040555;
    }
    let perm = if k == Synth::Environ { 0o400 } else { 0o444 };
    0o100000 | perm
}

/// `struct stat` of a synthesised file.
pub fn fake_stat(k: Synth, p: u64) -> i64 {
    let mut st = [0u64; 18];
    st[0] = proc_dev();
    st[1] = fake_ino(k);
    st[2] = 1;
    let uid = unsafe { sc0(nr::GETUID) } as u64;
    let gid = unsafe { sc0(nr::GETGID) } as u64;
    st[3] = fake_mode(k) as u64 | (uid << 32);
    st[4] = gid;
    st[7] = 1024;
    let t = crate::vtime::epoch();
    for i in [9, 11, 13] {
        st[i] = t / 1_000_000_000;
    }
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
    put32(&mut b, 16, 1);
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

/// getdents on a `/proc` directory handed out by the policy: inode numbers become virtual.
pub fn rewrite_dents(buf: u64, len: i64, old: bool) {
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
