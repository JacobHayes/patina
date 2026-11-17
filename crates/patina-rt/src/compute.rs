//! Compute points: scheduling points and virtual time inside code rebuilt with the compilers'
//! coverage hooks (`proto::compute`, `sdk/c/patina_compute.c`).
//!
//! The program's hooks decrement one word of its own memory, the cell (one page per address
//! space at `COMPUTE_CELL`, mapped at the first `COMPUTE_HELLO`), and make the SDK call
//! `COMPUTE_POINT` when it reaches 0. Nothing in the program calls runtime code.
//!
//! - `enter`, at every runtime entry beside `pmu::enter`: the events since the last `exit`
//!   are `handed - cell` (clamped to `0..=handed`, so a stray store into the cell moves only
//!   this process's own count); they are charged to virtual time at `compute_charge_ns` each.
//! - `exit`, the last thing before every return to program code beside `pmu::exit`: draws the
//!   next segment's gap (`proto::compute::gap`), cuts it short at the next deadline or the
//!   time limit and at `REFILL` (`proto::compute::arm`), writes it to the cell and remembers
//!   which of the three it was.
//! - `point`, the trap of `COMPUTE_POINT`: when the runtime's own count says the cell ran out,
//!   one `Preempt` record with that reason and a yield (the supervisor fires what is due);
//!   otherwise nothing (no record, no charge). So a timer, a timeout or the time limit falls
//!   due inside instrumented code at the exact event, with or without switches.
//!
//! Only the thread holding the turn runs, so the one cell of a process is never contended: a
//! thread's events are read and charged at its own next entry, before any other thread of the
//! process runs, and the next thread to return to program code writes its own gap. A spin
//! probe (`spin.rs`) arrives at a host-chosen instruction and touches none of this; the spin
//! point it may find is a state the same in every run, and an entry and exit like a trap.
//!
//! With counter preemption on (`Config::pmu`) the cell holds `NO_LIMIT` and nothing is
//! counted or charged here: counters own scheduling and time for the whole run.

use crate::arch::Frame;
use crate::state::{config, ctl, proc, ThreadState};
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use proto::compute::{NO_LIMIT, PREEMPT_NR, REASON_DEADLINE};
use proto::layout::{COMPUTE_CELL, PAGE};

/// No hello yet in this image: every function here is one test of `mode`.
pub const OFF: u64 = 0;
/// Counting, charging and switching.
pub const ON: u64 = 1;
/// Counter preemption owns the run: the cell holds `NO_LIMIT`.
pub const COUNTERS: u64 = 2;

/// Per-process (per address space) state, in `Proc`. Shared with a vfork child, as the cell is.
pub struct Compute {
    pub mode: u64,
    /// Event kinds the image's hook copies named.
    pub kinds: u64,
    /// The value last written to the cell, and that less the events charged since; the
    /// segment's drawn gap (0: switches off); why the cell will run out (`proto::compute`
    /// `REASON_*`).
    pub armed: i64,
    pub handed: i64,
    pub draw: u64,
    pub cut: u64,
    /// Events charged in this process.
    pub events: u64,
}

impl Compute {
    pub const fn new() -> Compute {
        Compute {
            mode: OFF,
            kinds: 0,
            armed: 0,
            handed: 0,
            draw: 0,
            cut: 0,
            events: 0,
        }
    }
}

/// A hello in this image: `COMPUTE_POINT` is a compute point (otherwise an unknown SDK call).
#[inline]
pub fn active() -> bool {
    proc().compute.mode != OFF
}

fn bump(a: &AtomicU64, n: u64) {
    a.store(a.load(Relaxed) + n, Relaxed);
}

/// The program unmapped, protected or mapped over the cell: the run ends `unsupported`.
fn cell_lost(errno: i64, mapping: bool) -> ! {
    crate::sup::host_error(errno, mapping as u64, proto::ctl::HE_COMPUTE_CELL)
}

fn read_cell() -> i64 {
    match crate::guest::get::<i64>(COMPUTE_CELL) {
        Ok(v) => v,
        Err(e) => cell_lost(e, false),
    }
}

fn write_cell(v: i64) {
    if let Err(e) = crate::guest::put(COMPUTE_CELL, v) {
        cell_lost(e, false)
    }
}

/// A runtime entry: charge the events of the segment that ended.
#[inline]
pub fn enter(ts: &mut ThreadState) {
    if proc().compute.mode != ON {
        return;
    }
    enter_slow(ts);
}

#[inline(never)]
fn enter_slow(ts: &mut ThreadState) {
    let p = &mut proc().compute;
    let cell = read_cell();
    let used = p.handed.saturating_sub(cell).clamp(0, p.handed) as u64;
    if used == 0 {
        return;
    }
    p.handed -= used as i64;
    // At most `REFILL` events per entry, whatever the program wrote into its cell.
    p.events += used;
    ts.compute_events += used;
    let c = ctl();
    bump(&c.compute.events, used);
    let t = (c.vclock_ns.load(Relaxed)).saturating_add(used * c.config.compute_charge_ns);
    c.vclock_ns.store(t, Relaxed);
}

/// A return to program code: arm the next segment.
#[inline]
pub fn exit(ts: &mut ThreadState) {
    if proc().compute.mode != ON {
        return;
    }
    exit_slow(ts);
}

#[inline(never)]
fn exit_slow(ts: &mut ThreadState) {
    ts.compute_segs += 1;
    let c = ctl();
    let cfg = &c.config;
    let key = proto::compute::key(c.seq.load(Relaxed), ts.slot, ts.compute_segs);
    let draw = proto::compute::gap(cfg.seed, cfg.compute_gap, key);
    // The first event at or after the next deadline, or past the time limit, is a point.
    let due = c.next_deadline_ns.load(Relaxed).min(
        proto::layout::VCLOCK_BOOT_NS
            .saturating_add(cfg.vtime_limit_ns)
            .saturating_add(1),
    );
    let (n, cut) = proto::compute::arm(draw, c.vclock_ns.load(Relaxed), due, cfg.compute_charge_ns);
    let p = &mut proc().compute;
    p.armed = n as i64;
    p.handed = n as i64;
    p.draw = draw.unwrap_or(0);
    p.cut = cut;
    write_cell(n as i64);
}

/// `COMPUTE_HELLO`: map the cell (first hook copy of this image), note the image and its kinds
/// in the run's image table (`proto::ctl::ComputeTab`, keyed by the guest path; the first
/// hello of an address space is a start), and answer the cell's address.
/// `COMPUTE_HELLO` from the system call instruction at `pc`, in the image whose hook copy
/// asked.
pub fn hello(arg: u64, pc: u64) -> i64 {
    let version = arg & 0xff;
    let kinds = arg >> 8;
    if version != proto::sdk::COMPUTE_VERSION || kinds & !proto::sdk::COMPUTE_KINDS != 0 {
        return -crate::raw::e::EINVAL;
    }
    let p = &mut proc().compute;
    let start = p.mode == OFF;
    if start {
        use crate::raw::*;
        let r = unsafe {
            sc6(
                nr::MMAP,
                COMPUTE_CELL,
                PAGE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                u64::MAX,
                0,
            )
        };
        if r as u64 != COMPUTE_CELL {
            cell_lost(r.min(0), true);
        }
        if config().pmu & proto::ctl::PMU_ON != 0 {
            p.mode = COUNTERS;
            write_cell(NO_LIMIT);
        } else {
            // `exit` writes the first gap on the way out of this trap.
            p.mode = ON;
            p.handed = 0;
        }
    }
    p.kinds |= kinds;
    let mut path = [0u8; 4096];
    let n = image_at(pc, &mut path);
    let image = match n {
        Some(n) => &path[..n],
        None => proc().guest_path(),
    };
    unsafe { proto::ctl::ComputeTab::at(crate::state::ctl_base()) }.note(image, kinds, start);
    let c = ctl();
    bump(&c.compute.hellos, 1);
    c.compute
        .kinds
        .store(c.compute.kinds.load(Relaxed) | kinds, Relaxed);
    COMPUTE_CELL as i64
}

/// The path of the file mapped at `pc`, read from the kernel's map into `out`; None (the
/// program is named) for the program itself, anonymous memory, or a map that cannot be read.
fn image_at(pc: u64, out: &mut [u8; 4096]) -> Option<usize> {
    use crate::raw::*;
    let fd = unsafe {
        sc4(
            nr::OPENAT,
            (-100i64) as u64,
            c"/proc/self/maps".as_ptr() as u64,
            0o2000000,
            0,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 8192];
    let (mut have, mut hit) = (0usize, None);
    'read: loop {
        let r = unsafe {
            sc3(
                nr::READ,
                fd as u64,
                buf.as_mut_ptr() as u64 + have as u64,
                (buf.len() - have) as u64,
            )
        };
        if r <= 0 {
            break;
        }
        have += r as usize;
        let mut used = 0;
        while let Some(nl) = buf[used..have].iter().position(|&c| c == b'\n') {
            let line = &buf[used..used + nl];
            used += nl + 1;
            if let Some((dev, ino, path)) = maps_hit(line, pc) {
                if ino != 0 && path.first() == Some(&b'/') && path.len() <= out.len() {
                    out[..path.len()].copy_from_slice(path);
                    hit = Some((dev, ino, path.len()));
                }
                break 'read;
            }
        }
        if used == 0 && have == buf.len() {
            break; // a line longer than the buffer
        }
        buf.copy_within(used..have, 0);
        have -= used;
    }
    unsafe { sc1(nr::CLOSE, fd as u64) };
    let (dev, ino, n) = hit?;
    let me = crate::sys::fs::fstatat_raw(-100, proc().guest_path.as_ptr() as u64, 0);
    (!me.is_some_and(|st| st.dev() == dev && st.ino() == ino)).then_some(n)
}

/// `(device, inode, path)` of a `/proc/self/maps` line when its range holds `pc`.
fn maps_hit(line: &[u8], pc: u64) -> Option<(u64, u64, &[u8])> {
    let mut f = line.splitn(6, |&c| c == b' ');
    let (range, _perms, _off, dev, ino) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
    let rest = f.next().unwrap_or(b"");
    let hex = |s: &[u8]| {
        s.iter()
            .map_while(|&c| (c as char).to_digit(16))
            .fold(0u64, |v, d| v << 4 | d as u64)
    };
    let dash = range.iter().position(|&c| c == b'-')?;
    if !(hex(&range[..dash])..hex(&range[dash + 1..])).contains(&pc) {
        return None;
    }
    let colon = dev.iter().position(|&c| c == b':')?;
    let ino = ino
        .iter()
        .map_while(|&c| (c as char).to_digit(10))
        .fold(0u64, |v, d| v * 10 + d as u64);
    let path = &rest[rest.iter().position(|&c| c != b' ').unwrap_or(rest.len())..];
    Some((
        crate::path::makedev(hex(&dev[..colon]), hex(&dev[colon + 1..])),
        ino,
        path,
    ))
}

/// The trap of `COMPUTE_POINT` (after `enter`), with the program's registers in `frame`.
/// Returns to the trap entry, which leaves through the normal trap exit.
pub fn point(ts: &mut ThreadState, frame: &Frame) {
    let p = &mut proc().compute;
    let c = ctl();
    let reason = match p.mode {
        // The cell ran out by the runtime's own count (a stray store that zeroed it counts the
        // same): consult the supervisor, for the reason `exit` armed it with.
        ON if p.handed == 0 => p.cut,
        // Counters own the run; a program that wrote the cell gets `NO_LIMIT` back.
        COUNTERS => return write_cell(NO_LIMIT),
        // The cell has events left (a call by hand), or no stop is due: nothing happens.
        // `exit` rewrites the cell on the way out.
        _ => return,
    };
    ts.seq = c.seq.load(Relaxed) + 1;
    c.seq.store(ts.seq, Relaxed);
    if reason == REASON_DEADLINE {
        bump(&c.compute.deadline_stops, 1);
    } else {
        bump(&c.compute.switches, 1);
    }
    let words = frame.regs_for_record();
    let bytes =
        unsafe { core::slice::from_raw_parts(words.as_ptr() as *const u8, words.len() * 8) };
    let rec = proto::Rec {
        seq: ts.seq,
        vclock_ns: c.vclock_ns.load(Relaxed),
        slot: ts.slot as u16,
        kind: proto::RecKind::Preempt as u8,
        class: 0,
        nr: PREEMPT_NR,
        args: [frame.pc(), p.armed as u64, reason, p.events, p.draw, 0],
        ret: 0,
        out_hash: proto::rec::hash_bytes(0, bytes),
        in_hash: 0,
    };
    crate::log::append(&rec);
    crate::sup::call_sup(proto::ctl::Op::Yield, [0; 6]);
}
