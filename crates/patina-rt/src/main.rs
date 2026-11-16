//! In-guest runtime. Invoked as `rt <path> <argv0> [args...]` by
//! `execveat(3004, "", ..., AT_EMPTY_PATH)`; loads the guest itself and
//! handles every syscall the guest makes through the SIGSYS trap.
#![no_std]
#![no_main]

mod cmem;
mod entry;
mod exec;
mod fault;
mod inject;
mod insn;
mod loader;
mod log;
mod oplog;
mod path;
mod pmu;
mod raw;
mod resolve;
mod sigframe;
mod spin;
mod state;
mod sup;
mod sys;
mod trap;
mod vino;
mod vtime;

/// An internal failure: tell the supervisor (run ends as `infra`) and say why on stderr.
pub fn fatal(msg: &[u8]) -> ! {
    raw::write_all(2, b"patina-rt: ");
    raw::write_all(2, msg);
    raw::write_all(2, b"\n");
    if state::ctl().check()
        && state::thread().magic == state::TS_MAGIC
        && state::thread().slot != u32::MAX
    {
        sup::host_error(0, 0, proto::ctl::HE_LOADER);
    }
    unsafe {
        raw::sc1(raw::nr::EXIT_GROUP, 127);
    }
    sup::hang()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    fatal(b"runtime panic")
}
