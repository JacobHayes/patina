//! `patina ctl WORDS...`: a control call (`proto::sdk::OP_CONTROL`) from inside a run, for
//! scripts. The words are the call's (`proto::node`, the grammar); the runtime parses them
//! against the run's nodes and answers 0 or an errno, which is said here with its reason.

use proto::sdk::{OP_CONTROL, OP_HELLO, SYSCALL, TEXT_MAX};
use std::process::ExitCode;

fn call(op: u64, words: &[u8]) -> i64 {
    let r = unsafe { libc::syscall(SYSCALL as libc::c_long, op, words.as_ptr(), words.len()) };
    if r < 0 {
        -(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO) as i64)
    } else {
        r as i64
    }
}

pub fn main(words: &[String]) -> ExitCode {
    let text = words.join(" ");
    if call(OP_HELLO, &[]) < 0 {
        eprintln!("patina ctl: not inside a Patina run");
        return ExitCode::from(2);
    }
    if text.is_empty() || text.len() > TEXT_MAX {
        eprintln!("patina ctl: expected words (patina ctl --help)");
        return ExitCode::from(2);
    }
    let r = call(OP_CONTROL, text.as_bytes());
    if r == 0 {
        return ExitCode::SUCCESS;
    }
    let why = match (-r) as i32 {
        libc::EPERM => "only the driver's node may act on the network",
        libc::ENOENT => "no node of that name",
        libc::EOPNOTSUPP => "not available yet",
        libc::EINVAL => "not a control call (patina ctl --help)",
        _ => "refused",
    };
    eprintln!(
        "patina ctl: {text}: {why} ({})",
        std::io::Error::from_raw_os_error((-r) as i32)
    );
    ExitCode::from(2)
}
