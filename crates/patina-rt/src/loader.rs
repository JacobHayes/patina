//! Loads the guest image: ELF segments at fixed bases, the interpreter, an
//! initial stack and auxv built here (no vDSO, seeded AT_RANDOM), the kernel's
//! vDSO and its data pages unmapped. Then jumps to the entry point.

use crate::raw::*;
use crate::state::*;
use proto::ctl::Setup;
use proto::layout::*;
use proto::{fill, Stream};

pub struct KernelStart {
    pub argc: usize,
    pub argv: *const *const u8,
    pub envp: *const *const u8,
    pub nenv: usize,
    pub auxv: *const [u64; 2],
}

impl KernelStart {
    pub fn parse(ksp: u64) -> KernelStart {
        unsafe {
            let sp = ksp as *const u64;
            let argc = *sp as usize;
            let argv = sp.add(1) as *const *const u8;
            let envp = argv.add(argc + 1);
            let mut nenv = 0;
            while !(*envp.add(nenv)).is_null() {
                nenv += 1;
            }
            let auxv = envp.add(nenv + 1) as *const [u64; 2];
            KernelStart {
                argc,
                argv,
                envp,
                nenv,
                auxv,
            }
        }
    }
    fn arg(&self, i: usize) -> &'static [u8] {
        unsafe { cstr(*self.argv.add(i)) }
    }
    pub fn aux(&self, t: u64) -> Option<u64> {
        unsafe {
            let mut p = self.auxv;
            while (*p)[0] != 0 {
                if (*p)[0] == t {
                    return Some((*p)[1]);
                }
                p = p.add(1);
            }
        }
        None
    }
}

pub unsafe fn cstr<'a>(p: *const u8) -> &'a [u8] {
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    core::slice::from_raw_parts(p, n)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ehdr {
    ident: [u8; 16],
    typ: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Phdr {
    typ: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
use proto::abi::ELF_MACHINE;

pub struct Image {
    pub base: u64,
    pub entry: u64,
    pub phdr: u64,
    pub phnum: u64,
    pub interp: [u8; 256],
    pub interp_len: usize,
}

fn fail(step: Setup, r: i64) -> ! {
    crate::fatal(step, r)
}

fn page_down(x: u64) -> u64 {
    x & !(PAGE - 1)
}
fn page_up(x: u64) -> u64 {
    (x + PAGE - 1) & !(PAGE - 1)
}

/// The `pr_type` property's word in the image's `NT_GNU_PROPERTY_TYPE_0` note, 0 if absent.
fn gnu_property(fd: u64, ph: &[Phdr], pr_type: u32) -> u32 {
    let Some(p) = ph.iter().find(|p| p.typ == PT_GNU_PROPERTY) else {
        return 0;
    };
    let mut b = [0u8; 256];
    let n = (p.filesz as usize).min(b.len());
    if unsafe { sc4(nr::PREAD64, fd, b.as_mut_ptr() as u64, n as u64, p.offset) } != n as i64 {
        return 0;
    }
    let u = |i: usize| {
        b.get(i..i + 4)
            .map_or(0, |w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
    };
    // namesz, descsz, type (NT_GNU_PROPERTY_TYPE_0), "GNU\0", then the properties: type,
    // size, data padded to 8.
    let (namesz, descsz) = (u(0) as usize, u(4) as usize);
    if u(8) != 5 || namesz != 4 || &b[12..16] != b"GNU\0" {
        return 0;
    }
    let end = (16 + descsz).min(n);
    let mut i = 16;
    while i + 8 <= end {
        let (t, sz) = (u(i), u(i + 4) as usize);
        if t == pr_type && sz >= 4 && i + 12 <= end {
            return u(i + 8);
        }
        i += 8 + ((sz + 7) & !7);
    }
    0
}

/// Map an ELF image. `path` must be NUL-terminated. `interp`: this is the interpreter.
pub fn load(path: &[u8], dyn_base: u64, interp: bool) -> Image {
    unsafe {
        let fd = sc4(
            nr::OPENAT,
            (-100i64) as u64,
            path.as_ptr() as u64,
            0o2000000,
            0,
        ); // O_RDONLY|O_CLOEXEC
        if fd < 0 {
            fail(Setup::OpenImage, fd);
        }
        let fd = fd as u64;
        let mut eh: Ehdr = core::mem::zeroed();
        let n = sc4(
            nr::PREAD64,
            fd,
            &mut eh as *mut Ehdr as u64,
            core::mem::size_of::<Ehdr>() as u64,
            0,
        );
        if n != core::mem::size_of::<Ehdr>() as i64
            || &eh.ident[..4] != b"\x7fELF"
            || eh.ident[4] != 2
            || eh.machine != ELF_MACHINE
        {
            fail(Setup::NotElf, 0);
        }
        if eh.typ != ET_EXEC && eh.typ != ET_DYN {
            fail(Setup::ElfType, 0);
        }
        let mut ph = [Phdr::default(); 64];
        let phnum = eh.phnum as usize;
        if phnum > 64 || eh.phentsize as usize != core::mem::size_of::<Phdr>() {
            fail(Setup::PhdrTable, 0);
        }
        let want = (phnum * core::mem::size_of::<Phdr>()) as i64;
        if sc4(
            nr::PREAD64,
            fd,
            ph.as_mut_ptr() as u64,
            want as u64,
            eh.phoff,
        ) != want
        {
            fail(Setup::PhdrRead, 0);
        }
        let base = if eh.typ == ET_DYN { dyn_base } else { 0 };
        let mut img = Image {
            base,
            entry: base + eh.entry,
            phdr: 0,
            phnum: phnum as u64,
            interp: [0; 256],
            interp_len: 0,
        };

        // The kernel adds protection bits (arm64: `PROT_BTI`) to the executable segments of the
        // image it maps itself: the interpreter, or a program without one. So does this loader;
        // the interpreter does it for the rest.
        let own = interp || !ph[..phnum].iter().any(|p| p.typ == PT_INTERP);
        let exec_extra = if own {
            crate::arch::insn::image_prot(|t| gnu_property(fd, &ph[..phnum], t))
        } else {
            0
        };

        // Span of all PT_LOAD segments, reserved first so gaps stay ours.
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        for p in &ph[..phnum] {
            if p.typ == PT_LOAD {
                lo = lo.min(page_down(p.vaddr));
                hi = hi.max(page_up(p.vaddr + p.memsz));
            }
        }
        if lo >= hi {
            fail(Setup::NoLoad, 0);
        }
        let (rlo, rhi) = (base + lo, base + hi);
        if rhi > RT_BASE && rlo < RT_REGION_END {
            fail(Setup::ImageInRuntime, 0);
        }
        let r = sc6(
            nr::MMAP,
            rlo,
            rhi - rlo,
            0,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE,
            u64::MAX,
            0,
        );
        if r as u64 != rlo {
            fail(Setup::ReserveImage, r);
        }
        for p in &ph[..phnum] {
            match p.typ {
                PT_INTERP => {
                    let n = (p.filesz as usize).min(255);
                    sc4(
                        nr::PREAD64,
                        fd,
                        img.interp.as_mut_ptr() as u64,
                        n as u64,
                        p.offset,
                    );
                    img.interp_len = img.interp[..n].iter().position(|&c| c == 0).unwrap_or(n);
                    img.interp[img.interp_len] = 0;
                }
                PT_PHDR => img.phdr = base + p.vaddr,
                PT_LOAD => {
                    let off_in_page = p.vaddr & (PAGE - 1);
                    let va = base + p.vaddr - off_in_page;
                    let prot = (if p.flags & 4 != 0 { PROT_READ } else { 0 })
                        | (if p.flags & 2 != 0 { PROT_WRITE } else { 0 })
                        | (if p.flags & 1 != 0 {
                            PROT_EXEC | exec_extra
                        } else {
                            0
                        });
                    let flen = p.filesz + off_in_page;
                    let fmap = page_up(flen);
                    let mend = page_up(p.vaddr + p.memsz) + base;
                    if p.filesz > 0 {
                        let r = sc6(
                            nr::MMAP,
                            va,
                            fmap,
                            prot | PROT_WRITE,
                            MAP_PRIVATE | MAP_FIXED,
                            fd,
                            p.offset - off_in_page,
                        );
                        if r as u64 != va {
                            fail(Setup::MapSegment, r);
                        }
                        if p.memsz > p.filesz {
                            // zero the tail of the last file page (.bss start)
                            core::ptr::write_bytes(
                                (va + flen) as *mut u8,
                                0,
                                (fmap - flen) as usize,
                            );
                        }
                        if prot & PROT_EXEC != 0 {
                            // instruction channels: patch rdrand/rdseed while the segment is still writable.
                            let file = crate::insn::scan::FileId {
                                fd,
                                off: p.offset - off_in_page,
                            };
                            crate::insn::scan::scan_exec(va, fmap, Some(file), true, prot);
                        }
                        if prot & PROT_WRITE == 0 {
                            sc3(nr::MPROTECT, va, fmap, prot);
                        }
                    }
                    let anon_start = va + if p.filesz > 0 { fmap } else { 0 };
                    if mend > anon_start {
                        let r = sc6(
                            nr::MMAP,
                            anon_start,
                            mend - anon_start,
                            prot,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                            u64::MAX,
                            0,
                        );
                        if r as u64 != anon_start {
                            fail(Setup::MapBss, r);
                        }
                    }
                    if img.phdr == 0 && eh.phoff >= p.offset && eh.phoff < p.offset + p.filesz {
                        img.phdr = base + p.vaddr + (eh.phoff - p.offset);
                    }
                }
                _ => {}
            }
        }
        // Sites the image declares in its `patina_sites` section (compiled SDKs).
        crate::sys::sdk::declare_image(fd, eh.shoff, eh.shnum, eh.shentsize, eh.shstrndx);
        sc1(nr::CLOSE, fd);
        if img.phdr == 0 {
            fail(Setup::PhdrNotLoaded, 0);
        }
        img
    }
}

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_BASE_PLATFORM: u64 = 24;
const AT_RANDOM: u64 = 25;
const AT_HWCAP2: u64 = 26;
const AT_RSEQ_FEATURE_SIZE: u64 = 27;
const AT_RSEQ_ALIGN: u64 = 28;
const AT_HWCAP3: u64 = 29;
const AT_HWCAP4: u64 = 30;
const AT_EXECFN: u64 = 31;
const AT_SYSINFO_EHDR: u64 = 33;
const AT_MINSIGSTKSZ: u64 = 51;

/// Copied from the kernel's auxv: host-stable facts.
const COPIED: [u64; 11] = [
    AT_PAGESZ,
    AT_UID,
    AT_EUID,
    AT_GID,
    AT_EGID,
    AT_HWCAP,
    AT_CLKTCK,
    AT_HWCAP2,
    AT_HWCAP3,
    AT_HWCAP4,
    AT_MINSIGSTKSZ,
];

struct StackBuilder {
    top: u64,
    sp: u64,
}

impl StackBuilder {
    fn push_bytes(&mut self, b: &[u8]) -> u64 {
        self.sp -= b.len() as u64;
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), self.sp as *mut u8, b.len()) };
        self.sp
    }
    fn push_cstr(&mut self, b: &[u8]) -> u64 {
        self.sp -= b.len() as u64 + 1;
        unsafe {
            core::ptr::copy_nonoverlapping(b.as_ptr(), self.sp as *mut u8, b.len());
            *((self.sp + b.len() as u64) as *mut u8) = 0;
        }
        self.sp
    }
}

const MAX_ARGS: usize = 4096;

/// Load the guest named on the command line and enter it.
pub fn start(k: &KernelStart) -> ! {
    // The kernel placed the vDSO and its data pages below its randomised mmap base, which
    // can fall anywhere in the terabytes under the guest stack's fixed address: remove them
    // before the fixed placements below, or one exec in some 10^5 finds them in the way.
    unmap_vdso();
    crate::arch::image_init(k.aux(AT_HWCAP2).unwrap_or(0));
    // argv: [rt, path, argv0, args...]
    if k.argc < 3 {
        crate::fatal(Setup::Usage, 0);
    }
    let p = proc();
    let path = k.arg(1);
    if path.len() >= p.guest_path.len() - 1 {
        crate::fatal(Setup::PathTooLong, 0);
    }
    p.guest_path[..path.len()].copy_from_slice(path);
    p.guest_path[path.len()] = 0;
    p.guest_path_len = path.len();

    crate::sys::fs::read_mounts();
    // The task name the kernel would have given the guest: the basename of the
    // path, at most 15 bytes (it is "rt" after the runtime's own exec).
    let base = path.rsplit(|&c| c == b'/').next().unwrap_or(path);
    let mut comm = [0u8; 16];
    let n = base.len().min(15);
    comm[..n].copy_from_slice(&base[..n]);
    unsafe { sc2(nr::PRCTL, 15, comm.as_ptr() as u64) }; // PR_SET_NAME

    let exe = load(&p.guest_path[..=path.len()], EXE_BASE, false);
    let mut entry = exe.entry;
    let mut ibase = 0;
    if exe.interp_len > 0 {
        let li = load(&exe.interp[..=exe.interp_len], INTERP_BASE, true);
        entry = li.entry;
        ibase = li.base;
    }

    // brk reservation: 64 GiB, inaccessible until brk grows.
    unsafe {
        let r = sc6(
            nr::MMAP,
            BRK_BASE,
            BRK_SIZE,
            0,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_NORESERVE,
            u64::MAX,
            0,
        );
        if r as u64 != BRK_BASE {
            crate::fatal(Setup::Brk, r);
        }
    }
    p.brk_cur = BRK_BASE;

    // Initial stack.
    let lo = STACK_TOP - STACK_SIZE;
    unsafe {
        let r = sc6(
            nr::MMAP,
            lo,
            STACK_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            u64::MAX,
            0,
        );
        if r as u64 != lo {
            crate::fatal(Setup::Stack, r);
        }
    }
    let mut sb = StackBuilder {
        top: STACK_TOP,
        sp: STACK_TOP - 16,
    };
    let mut rnd = [0u8; 16];
    fill(
        config().seed,
        Stream::Entropy,
        ctl().seq.load(core::sync::atomic::Ordering::Relaxed),
        &mut rnd,
    );
    let at_random = sb.push_bytes(&rnd);
    let execfn = sb.push_cstr(path);
    let platform = k
        .aux(AT_PLATFORM)
        .map(|v| sb.push_cstr(unsafe { cstr(v as *const u8) }));
    let base_platform = k
        .aux(AT_BASE_PLATFORM)
        .map(|v| sb.push_cstr(unsafe { cstr(v as *const u8) }));
    let nargs = k.argc - 2;
    if nargs > MAX_ARGS || k.nenv > MAX_ARGS {
        crate::fatal(Setup::TooManyArgs, 0);
    }
    let mut argp = [0u64; MAX_ARGS];
    for (i, a) in argp.iter_mut().enumerate().take(nargs) {
        *a = sb.push_cstr(k.arg(i + 2));
    }
    let mut envp = [0u64; MAX_ARGS];
    for (i, e) in envp.iter_mut().enumerate().take(k.nenv) {
        *e = sb.push_cstr(unsafe { cstr(*k.envp.add(i)) });
    }
    crate::sys::procfs::note_strings(&argp[..nargs], &envp[..k.nenv]);
    // auxv
    let mut aux = [[0u64; 2]; 32];
    let mut na = 0;
    let mut put = |t: u64, v: u64| {
        aux[na] = [t, v];
        na += 1;
    };
    put(AT_PHDR, exe.phdr);
    put(AT_PHENT, 56);
    put(AT_PHNUM, exe.phnum);
    put(AT_BASE, ibase);
    put(AT_FLAGS, 0);
    put(AT_ENTRY, exe.entry);
    put(AT_SECURE, 0);
    put(AT_RANDOM, at_random);
    put(AT_EXECFN, execfn);
    if let Some(v) = platform {
        put(AT_PLATFORM, v);
    }
    if let Some(v) = base_platform {
        put(AT_BASE_PLATFORM, v);
    }
    for t in COPIED {
        if let Some(v) = k.aux(t) {
            put(t, crate::arch::aux_value(t, v));
        }
    }
    // rseq is refused, so its feature fields are left out.
    let _ = (AT_RSEQ_FEATURE_SIZE, AT_RSEQ_ALIGN, AT_SYSINFO_EHDR);
    put(AT_NULL, 0);

    let words = 1 + nargs + 1 + k.nenv + 1 + 2 * na;
    sb.sp &= !15;
    if words % 2 == 1 {
        sb.sp -= 8;
    }
    sb.sp -= (words * 8) as u64;
    let start_sp = sb.sp;
    unsafe {
        let mut w = start_sp as *mut u64;
        let mut put_w = |v: u64| {
            *w = v;
            w = w.add(1);
        };
        put_w(nargs as u64);
        for a in &argp[..nargs] {
            put_w(*a);
        }
        put_w(0);
        for e in &envp[..k.nenv] {
            put_w(*e);
        }
        put_w(0);
        for a in &aux[..na] {
            put_w(a[0]);
            put_w(a[1]);
        }
    }
    let _ = sb.top;

    crate::compute::exit(crate::state::thread());
    // arm64: the entry is a jump, not a return with a counter read; the image's first segment
    // is not measured (`arch/aarch64/pmu.rs`).
    #[cfg(target_arch = "x86_64")]
    crate::pmu::exit(crate::state::thread(), entry, 0);
    crate::arch::enter_guest(start_sp, entry)
}

/// Remove the kernel's vDSO and its data pages, found by name in /proc/self/maps.
fn unmap_vdso() {
    let mut buf = [0u8; 16384];
    let n = read_file(b"/proc/self/maps\0", &mut buf);
    let text = &buf[..n];
    for line in text.split(|&c| c == b'\n') {
        let named = |s: &[u8]| line.windows(s.len()).any(|w| w == s);
        if named(b"[vdso]") || named(b"[vvar]") || named(b"[vvar_vclock]") {
            let dash = line.iter().position(|&c| c == b'-').unwrap_or(0);
            let sp = line.iter().position(|&c| c == b' ').unwrap_or(0);
            let (a, b) = (hex(&line[..dash]), hex(&line[dash + 1..sp]));
            if b > a {
                unsafe { sc2(nr::MUNMAP, a, b - a) };
            }
        }
    }
}

fn hex(s: &[u8]) -> u64 {
    let mut v = 0u64;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => break,
        };
        v = v * 16 + d as u64;
    }
    v
}

/// Read a whole (small) file with the runtime's own syscalls.
pub fn read_file(path: &[u8], buf: &mut [u8]) -> usize {
    unsafe {
        let fd = sc4(
            nr::OPENAT,
            (-100i64) as u64,
            path.as_ptr() as u64,
            0o2000000,
            0,
        );
        if fd < 0 {
            return 0;
        }
        let mut n = 0usize;
        while n < buf.len() {
            let r = sc3(
                nr::READ,
                fd as u64,
                buf.as_mut_ptr() as u64 + n as u64,
                (buf.len() - n) as u64,
            );
            if r <= 0 {
                break;
            }
            n += r as usize;
        }
        sc1(nr::CLOSE, fd as u64);
        n
    }
}
