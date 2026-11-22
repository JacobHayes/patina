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
            if crate::state::with_machines() {
                return machine_names(call);
            }
        }
    }
    super::unixsock::handle(call)
}

/// An `AF_UNIX` call in a run with machines: its abstract names under the machine's prefix
/// (`unixname`).
fn machine_names(call: &mut dyn Call) -> Action {
    use super::unixname::{name_in, passcred_autobind, Msgs, Name, Out, MMSG_MAX};
    let fd = call.arg(0);
    if !super::unixsock::is_socket(fd) {
        return super::unixsock::handle(call);
    }
    let fail = |e: i64| Action::Return(e);
    let mut name = Name::new();
    let mut out = Out::new();
    let mut msgs = Msgs::new();
    let mut copied = false;
    let mut gives = false;
    let nr = call.nr();
    if matches!(nr, nr::CONNECT | nr::SENDTO | nr::SENDMSG | nr::SENDMMSG) {
        passcred_autobind(fd, nr != nr::CONNECT);
    }
    match nr {
        nr::BIND | nr::CONNECT => match name_in(call.arg(1), call.arg(2), &mut name) {
            Ok(true) => {
                call.set_arg(1, name.sa.as_ptr() as u64);
                call.set_arg(2, name.len as u64);
            }
            Ok(false) => {}
            Err(e) => return fail(e),
        },
        nr::SENDTO => match name_in(call.arg(4), call.arg(5), &mut name) {
            Ok(true) => {
                call.set_arg(4, name.sa.as_ptr() as u64);
                call.set_arg(5, name.len as u64);
            }
            Ok(false) => {}
            Err(e) => return fail(e),
        },
        nr::ACCEPT | nr::ACCEPT4 | nr::GETSOCKNAME | nr::GETPEERNAME => {
            match Out::take(call, 1, &mut out) {
                Ok(g) => gives = g,
                Err(e) => return fail(e),
            }
        }
        nr::RECVFROM => match Out::take(call, 4, &mut out) {
            Ok(g) => gives = g,
            Err(e) => return fail(e),
        },
        nr::SENDMSG | nr::RECVMSG | nr::SENDMMSG | nr::RECVMMSG => {
            let one = matches!(nr, nr::SENDMSG | nr::RECVMSG);
            let recv = matches!(nr, nr::RECVMSG | nr::RECVMMSG);
            let n = if one {
                1
            } else {
                let n = (call.arg(2) as usize).min(MMSG_MAX);
                call.set_arg(2, n as u64);
                n
            };
            match msgs.take(call.arg(1), n, if one { 56 } else { 64 }, recv) {
                Ok(true) => {
                    call.set_arg(1, msgs.ptr());
                    copied = true;
                }
                Ok(false) => {}
                Err(e) => return fail(e),
            }
        }
        _ => {}
    }
    let a = super::unixsock::handle(call);
    let ok = match a {
        Action::Return(r) => r >= 0,
        _ => false,
    };
    // Messages the call handled: `sendmsg` and `recvmsg` one, the `mmsg` calls their count.
    if copied {
        let count = match (nr, &a) {
            (nr::SENDMSG | nr::RECVMSG, Action::Return(r)) if *r >= 0 => 1,
            (nr::SENDMMSG | nr::RECVMMSG, Action::Return(r)) if *r > 0 => *r as usize,
            _ => 0,
        };
        if let Err(e) = msgs.done(count) {
            return fail(e);
        }
    }
    if gives && ok {
        if let Err(e) = out.give() {
            return fail(e);
        }
    }
    a
}
