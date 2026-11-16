//! Sockets: `AF_INET`/`AF_INET6` stream sockets go to the wire (`inet`); `AF_UNIX` is
//! served by `unixsock`. Netlink and packet sockets are refused; other families end the run.

use super::*;

const EADDRINUSE: i64 = 98;
const ECONNREFUSED: i64 = 111;
const EOPNOTSUPP: i64 = 95;

pub fn handle(call: &mut dyn Call) -> Action {
    match call.nr() {
        41 => {
            if let Some(a) = super::inet::socket_call(call) {
                return a;
            }
        }
        // socketpair(AF_INET/AF_INET6): the kernel answers EOPNOTSUPP.
        53 if matches!(call.arg(0), 2 | 10) => return Action::Return(-EOPNOTSUPP),
        53 => {}
        _ => {
            let fd = call.arg(0) as i32 as i64;
            if let Some(i) = super::inet::wire_idx(fd) {
                return super::inet::handle(call, i);
            }
            // The wire's own abstract names are not reachable from guest AF_UNIX sockets.
            match call.nr() {
                49 if super::inet::reserved_unix_name(call.arg(1), call.arg(2)) => {
                    return Action::Return(-EADDRINUSE)
                }
                42 if super::inet::reserved_unix_name(call.arg(1), call.arg(2)) => {
                    return Action::Return(-ECONNREFUSED)
                }
                44 if super::inet::reserved_unix_name(call.arg(4), call.arg(5)) => {
                    return Action::Return(-ECONNREFUSED)
                }
                _ => {}
            }
        }
    }
    super::unixsock::handle(call)
}
