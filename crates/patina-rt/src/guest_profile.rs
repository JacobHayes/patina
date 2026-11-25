//! Deterministic CPU profiling (`--profile-cpu`): captures guest PC + bounded frame-pointer
//! stack samples at deterministic compute-point intervals and records executable image load
//! mappings into the `FD_CPU_PROFILE` sidecar (never touching `boundary.log`).

use crate::arch::Frame;
use crate::raw::*;
use crate::state::{config, ctl, ThreadState};
use core::sync::atomic::Ordering::Relaxed;
use proto::layout::FD_CPU_PROFILE;
use proto::guest_profile::{encode_image, encode_sample, MAX_FRAMES, MAX_RECORD_BYTES};

#[inline]
pub fn enabled() -> bool {
    config().profile_cpu_interval != 0
}

fn write_record(buf: &[u8]) {
    let mut off = 0usize;
    while off < buf.len() {
        let r = unsafe {
            sc3(
                nr::WRITE,
                FD_CPU_PROFILE as u64,
                buf.as_ptr().add(off) as u64,
                (buf.len() - off) as u64,
            )
        };
        if r <= 0 {
            break;
        }
        off += r as usize;
    }
}

/// Record an executable ELF mapping so the host symbolizer can resolve guest PCs.
pub fn record_image(start: u64, end: u64, bias: u64, file_off: u64, path: &[u8]) {
    if !enabled() || path.is_empty() || end <= start {
        return;
    }
    let pid = crate::state::thread().pid as u32;
    let mut buf = [0u8; MAX_RECORD_BYTES];
    let n = encode_image(&mut buf, pid, start, end, bias, file_off, path);
    write_record(&buf[..n]);
}

/// Capture one deterministic CPU sample at `pc` (already translated through `plans::shown`)
/// with a bounded frame-pointer stack walk, strictly excluding any PC in `patina-rt`.
pub fn record_sample(ts: &ThreadState, frame: &Frame, pc: u64, weight: u64) {
    if !enabled() {
        return;
    }
    let mut frames = [0u64; MAX_FRAMES];
    let mut nf = 0usize;

    if pc != 0 && !crate::fault::in_runtime(pc) {
        frames[nf] = pc;
        nf += 1;
    }

    let mut fp = frame.fp();
    let sp = frame.sp();
    while nf < MAX_FRAMES {
        if fp == 0 || fp & 7 != 0 || fp < sp || crate::fault::in_runtime(fp) {
            break;
        }
        let Ok(pair) = crate::guest::get::<[u64; 2]>(fp) else {
            break;
        };
        let next_fp = pair[0];
        let ret = pair[1];
        if ret == 0 {
            break;
        }
        let shown = crate::plans::shown(ret);
        if shown != 0 && !crate::fault::in_runtime(shown) {
            frames[nf] = shown;
            nf += 1;
        }
        // Strictly monotonic walk bounded by 1 MiB per frame avoids loops or corrupt stacks.
        if next_fp <= fp || next_fp - fp > (1 << 20) {
            break;
        }
        fp = next_fp;
    }

    let vclock_ns = ctl().vclock_ns.load(Relaxed);
    let seq = ctl().seq.load(Relaxed);
    let mut buf = [0u8; MAX_RECORD_BYTES];
    let n = encode_sample(
        &mut buf,
        vclock_ns,
        seq,
        weight,
        ts.pid as u32,
        ts.tid as u32,
        ts.slot as u16,
        &frames[..nf],
    );
    write_record(&buf[..n]);
}
