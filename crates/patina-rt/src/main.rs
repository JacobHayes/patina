//! In-guest runtime. Invoked as `rt <path> <argv0> [args...]` by
//! `execveat(3004, "", ..., AT_EMPTY_PATH)`; loads the guest itself and
//! handles every syscall the guest makes through the SIGSYS trap.
#![no_std]
#![no_main]

mod arch;
mod compute;
mod entry;
mod exec;
mod fault;
mod guest;
mod inject;
mod insn;
mod loader;
mod log;
mod oplog;
mod path;
#[cfg(target_arch = "x86_64")]
mod pmu;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/pmu.rs"]
mod pmu;
mod pmu_open;
mod raw;
mod resolve;
mod spin;
mod state;
mod sup;
mod swap;
mod sys;
mod trap;
mod vino;
mod vtime;

/// An internal failure at `step`: tell the supervisor (run ends as `infra`) and say why on
/// stderr. `r` is the failed call's return value (its negated errno), or 0 when the step
/// failed a check rather than a call.
pub fn fatal(step: proto::ctl::Setup, r: i64) -> ! {
    let errno = if r < 0 && r > -4096 { -r } else { 0 };
    raw::write_all(2, b"patina-rt: ");
    raw::write_all(2, step.name().as_bytes());
    if errno != 0 {
        let mut d = [0u8; 20];
        let mut i = d.len();
        let mut v = errno as u64;
        while v > 0 || i == d.len() {
            i -= 1;
            d[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        raw::write_all(2, b" (errno ");
        raw::write_all(2, &d[i..]);
        raw::write_all(2, b")");
    }
    raw::write_all(2, b"\n");
    if state::ctl_mapped()
        && state::ctl().check()
        && state::thread().magic == state::TS_MAGIC
        && state::thread().slot != u32::MAX
    {
        sup::host_error(errno, step as u64, proto::ctl::HE_LOADER);
    }
    unsafe {
        raw::sc1(proto::nr::EXIT_GROUP, 127);
    }
    sup::hang()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    fatal(proto::ctl::Setup::Panic, 0)
}
