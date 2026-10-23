//! A process's `net` directory, `/proc/<pid>/net` (fs/proc/proc_net.c),
//! with the socket tables of its network namespace (the machine's one,
//! which every process of the model shares): `tcp` and `tcp6`
//! (net/ipv4/tcp_ipv4.c, net/ipv6/tcp_ipv6.c), `udp` and `udp6`
//! (net/ipv4/udp.c, net/ipv6/udp.c) and `unix` (net/unix/af_unix.c).
//!
//! A table is its header line, as the kernel writes it (`tcp` and `udp`
//! padded by `seq_setwidth`/`seq_pad`), and a row per socket of its kind in
//! the namespace. The model writes no rows: a read of a table while the
//! guest holds a socket the table would list stops the run by name, so a
//! table never leaves out a socket that is there.

use super::Node;
use crate::thread::net::abi::{AF_INET, AF_INET6, AF_UNIX, SOCK_DGRAM, SOCK_STREAM};

/// A socket table of the `net` directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum NetFile {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
    Unix,
}

/// The tables and their names, in the directory's order: by name length,
/// then bytes (`proc_match`).
pub(super) const NET: [(NetFile, &str); 5] = [
    (NetFile::Tcp, "tcp"),
    (NetFile::Udp, "udp"),
    (NetFile::Tcp6, "tcp6"),
    (NetFile::Udp6, "udp6"),
    (NetFile::Unix, "unix"),
];

/// `TMPSZ - 1`, the width `tcp4_seq_show` pads each line to.
const TCP_WIDTH: usize = 149;
/// The width `udp4_seq_show` pads each line to.
const UDP_WIDTH: usize = 127;

pub(super) fn name(file: NetFile) -> &'static str {
    NET.iter()
        .find(|(each, _)| *each == file)
        .map_or("", |(_, name)| name)
}

/// `/proc/<pid>/net/<table>`'s inode: the namespace's entries, the same
/// under every process's directory (as the host's `/proc` numbered them).
pub(super) fn ino(file: NetFile) -> u64 {
    match file {
        NetFile::Tcp => 4_026_532_051,
        NetFile::Udp => 4_026_532_052,
        NetFile::Tcp6 => 4_026_533_186,
        NetFile::Udp6 => 4_026_533_185,
        NetFile::Unix => 4_026_532_057,
    }
}

/// The table's header line, as its `seq_show` writes it.
pub(super) fn header(file: NetFile) -> Vec<u8> {
    let (line, width) = match file {
        NetFile::Tcp => (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  \
             timeout inode",
            TCP_WIDTH,
        ),
        NetFile::Udp => (
            "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  \
             timeout inode ref pointer drops",
            UDP_WIDTH,
        ),
        NetFile::Tcp6 => (
            "  sl  local_address                         remote_address                        \
             st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
            0,
        ),
        NetFile::Udp6 => (
            "  sl  local_address                         remote_address                        \
             st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops",
            0,
        ),
        NetFile::Unix => ("Num       RefCount Protocol Flags    Type St Inode Path", 0),
    };
    format!("{line:<width$}\n").into_bytes()
}

/// The sockets a table lists: its family, and its type where the family
/// has more than one table.
fn lists(file: NetFile) -> (i32, Option<i32>) {
    match file {
        NetFile::Tcp => (AF_INET, Some(SOCK_STREAM)),
        NetFile::Udp => (AF_INET, Some(SOCK_DGRAM)),
        NetFile::Tcp6 => (AF_INET6, Some(SOCK_STREAM)),
        NetFile::Udp6 => (AF_INET6, Some(SOCK_DGRAM)),
        NetFile::Unix => (AF_UNIX, None),
    }
}

/// A table's text now: its header, with no socket of its kind held (the
/// guest's are the namespace's only sockets); a socket it would list stops
/// the run.
pub(super) fn text(pid: i32, file: NetFile) -> Vec<u8> {
    let (family, ty) = lists(file);
    if crate::thread::net::holds_socket(family, ty) {
        crate::trap_fatal(&format!(
            "{} is read while the guest holds a socket it lists; a table's socket rows are not \
             modeled; failing closed",
            Node::NetFile(pid, file).path()
        ));
    }
    header(file)
}
