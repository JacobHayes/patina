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
            if let Some(a) = abstract_with_nodes(call, name) {
                return a;
            }
        }
    }
    super::unixsock::handle(call)
}

/// In a run with nodes, abstract `AF_UNIX` names (and autobind, which makes one) are refused:
/// they live in the kernel's one network namespace, which every node shares, so one node could
/// reach another's. Path names are in each node's own view. Per-node abstract names come later.
fn abstract_with_nodes(call: &mut dyn Call, name: Option<(u64, u64)>) -> Option<Action> {
    let tab = unsafe { proto::node::NodeTab::at(crate::state::ctl_base()) };
    if tab.count() == 0 {
        return None;
    }
    // `sendmmsg`: every message's name (at most `UIO_MAXIOV` of them are sent).
    let (first, count, stride) = match call.nr() {
        nr::SENDMSG => (call.arg(1), 1, 0),
        nr::SENDMMSG => (call.arg(1), call.arg(2).min(1024), 64),
        _ => (0, 1, 0),
    };
    let autobind = call.nr() == nr::BIND;
    for i in 0..count {
        let n = match call.nr() {
            nr::SENDMSG | nr::SENDMMSG => msg_name(first + i * stride),
            _ => name,
        };
        let Some((addr, len)) = n else { continue };
        if addr == 0 || len < 2 {
            continue;
        }
        let mut sa = [0u8; 3];
        let n = (len as usize).min(3);
        if let Err(e) = crate::guest::read(addr, &mut sa[..n]) {
            return Some(Action::Return(e));
        }
        if u16::from_ne_bytes([sa[0], sa[1]]) != 1 {
            continue;
        }
        if (len == 2 && autobind) || (len >= 3 && sa[2] == 0) {
            super::inet::refuse(b"unix:abstract-with-nodes");
            return Some(Action::Return(-EOPNOTSUPP));
        }
    }
    None
}

/// The name of a `msghdr` (of the first message of a `sendmmsg`): its address and length.
fn msg_name(msg: u64) -> Option<(u64, u64)> {
    let mut h = [0u8; 12];
    crate::guest::read(msg, &mut h).ok()?;
    let addr = u64::from_ne_bytes(h[..8].try_into().unwrap());
    let len = u32::from_ne_bytes(h[8..12].try_into().unwrap()) as u64;
    Some((addr, len))
}
