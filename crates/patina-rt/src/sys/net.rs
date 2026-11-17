//! Sockets: `AF_INET`/`AF_INET6` stream sockets go to the wire (`inet`); `AF_UNIX` is
//! served by `unixsock`. Netlink and packet sockets are refused; other families end the run.

use super::*;

const EADDRINUSE: i64 = 98;
const ECONNREFUSED: i64 = 111;
const EOPNOTSUPP: i64 = 95;

pub fn handle(call: &mut dyn Call) -> Action {
    match call.nr() {
        nr::SOCKET => {
            if let Some(a) = super::inet::socket_call(call) {
                return a;
            }
        }
        // socketpair(AF_INET/AF_INET6): the kernel answers EOPNOTSUPP.
        nr::SOCKETPAIR if matches!(call.arg(0), 2 | 10) => return Action::Return(-EOPNOTSUPP),
        nr::SOCKETPAIR => {}
        _ => {
            let fd = call.arg(0) as i32 as i64;
            if let Some(i) = super::inet::wire_idx(fd) {
                return super::inet::handle(call, i);
            }
            // The wire's own abstract names are not reachable from guest AF_UNIX sockets.
            let (name, refused) = match call.nr() {
                nr::BIND => (Some((call.arg(1), call.arg(2))), -EADDRINUSE),
                nr::CONNECT => (Some((call.arg(1), call.arg(2))), -ECONNREFUSED),
                nr::SENDTO => (Some((call.arg(4), call.arg(5))), -ECONNREFUSED),
                _ => (None, 0),
            };
            if let Some((addr, len)) = name {
                match super::inet::reserved_unix_name(addr, len) {
                    Ok(false) => {}
                    Ok(true) => return Action::Return(refused),
                    Err(e) => return Action::Return(e),
                }
            }
        }
    }
    super::unixsock::handle(call)
}
