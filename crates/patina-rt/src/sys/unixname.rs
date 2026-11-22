//! Per-machine abstract `AF_UNIX` names. Abstract names live in the kernel's network namespace,
//! which every machine of a run shares (`proto::machine`), so in a run with machines each name a guest
//! gives is stored as `\0patina-n<K>-<name>` for its machine `K`, and every name the kernel gives
//! back has its own machine's prefix taken off. A machine's names are its own: one machine cannot bind,
//! connect to or send to another's (the prefix is under the reserved `patina-` names, which a
//! guest cannot name itself). An autobind (`bind` with the family only, or a connect, or a
//! datagram socket's send, on an unbound socket with `SO_PASSCRED`, which the kernel would
//! autobind at random) gets
//! the runtime's counter name under the same prefix.
//!
//! The kernel is given the prefixed name: an argument is replaced (`Call::set_arg`) by a
//! runtime buffer; message headers (`sendmsg`, `recvmsg` and the `mmsg` calls) are copied to
//! runtime memory with their names replaced (`Msgs`). A `sendmmsg` or `recvmmsg` call on an
//! `AF_UNIX` socket handles at most `MMSG_MAX` messages (both may return fewer than asked).
//! A prefixed name is `PREFIX_MAX` bytes longer: an abstract name that no longer fits a
//! `sockaddr_un` is `EINVAL`, as an over-long address is. Without machines nothing here runs.

use super::*;
use crate::guest;

const AF_UNIX: u16 = 1;
const SOL_SOCKET: u64 = 1;
const SO_PASSCRED: u64 = 16;
const SO_TYPE: u64 = 3;
const SOCK_DGRAM: i32 = 2;
/// `sizeof(struct sockaddr_un)`.
const SUN_LEN: usize = 110;
/// Messages of an `AF_UNIX` `sendmmsg`/`recvmmsg` call in a run with machines.
pub const MMSG_MAX: usize = 16;
/// The longest prefix: `patina-n14-`.
const PREFIX_MAX: usize = 11;

/// A name in runtime memory, as the kernel takes or gives it.
#[derive(Clone, Copy)]
pub struct Name {
    pub sa: [u8; SUN_LEN + 2],
    pub len: u32,
}

impl Name {
    pub const fn new() -> Name {
        Name {
            sa: [0; SUN_LEN + 2],
            len: (SUN_LEN) as u32,
        }
    }
}

/// This machine's prefix (without the leading NUL): `patina-n<K>-`.
fn prefix(out: &mut [u8; PREFIX_MAX]) -> usize {
    let p = b"patina-n";
    out[..p.len()].copy_from_slice(p);
    let mut n = p.len();
    n += crate::path::fmt_dec(&mut out[n..], crate::state::machine() as u64);
    out[n] = b'-';
    n + 1
}

/// The guest's name at `addr` (`len` bytes) as the kernel is to see it, in `out`: `Ok(true)`
/// when it is abstract and was prefixed, `Ok(false)` to pass the guest's as it is.
pub fn name_in(addr: u64, len: u64, out: &mut Name) -> Result<bool, i64> {
    if addr == 0 || len < 3 || len > SUN_LEN as u64 {
        return Ok(false);
    }
    let n = len as usize;
    guest::read(addr, &mut out.sa[..n])?;
    if u16::from_ne_bytes([out.sa[0], out.sa[1]]) != AF_UNIX || out.sa[2] != 0 {
        return Ok(false);
    }
    let mut p = [0u8; PREFIX_MAX];
    let k = prefix(&mut p);
    if n + k > SUN_LEN {
        return Err(-e::EINVAL);
    }
    out.sa.copy_within(3..n, 3 + k);
    out.sa[3..3 + k].copy_from_slice(&p[..k]);
    out.len = (n + k) as u32;
    Ok(true)
}

/// The autobind name `\0<prefix><five hex digits>` of counter value `v`.
pub fn autobind_name(v: u64, out: &mut Name) {
    out.sa = [0; SUN_LEN + 2];
    out.sa[..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
    let mut p = [0u8; PREFIX_MAX];
    let k = prefix(&mut p);
    out.sa[3..3 + k].copy_from_slice(&p[..k]);
    for i in 0..5 {
        let d = ((v >> (4 * (4 - i))) & 0xf) as u8;
        out.sa[3 + k + i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
    }
    out.len = (3 + k + 5) as u32;
}

/// The name the kernel gave (`n` bytes of `sa`) as the guest is to see it: its own machine's
/// prefix taken off. Returns the guest's length.
fn strip(sa: &mut [u8; SUN_LEN + 2], n: usize) -> usize {
    let n = n.min(SUN_LEN);
    let mut p = [0u8; PREFIX_MAX];
    let k = prefix(&mut p);
    if n >= 3 + k && sa[2] == 0 && sa[3..3 + k] == p[..k] {
        sa.copy_within(3 + k..n, 3);
        return n - k;
    }
    n
}

/// Give the guest a name the kernel wrote to `name` (its length at `name.len`): at most
/// `cap` bytes of it to `addr`, and its whole length to `lenp` (as the kernel does when the
/// guest's buffer is short).
fn give(name: &mut Name, addr: u64, cap: u32, lenp: u64) -> Result<(), i64> {
    let n = strip(&mut name.sa, name.len as usize);
    let k = n.min(cap as usize);
    guest::write(addr, &name.sa[..k])?;
    guest::put::<u32>(lenp, n as u32)
}

/// A connect (`send` false), or a datagram socket's send, from an unbound socket with
/// `SO_PASSCRED` set: bind it to a counter name first, as the kernel would to a random one.
pub fn passcred_autobind(fd: u64, send: bool) {
    let opt = |o: u64| {
        let mut v: i32 = 0;
        let mut l: u32 = 4;
        let r = unsafe {
            sc6(
                nr::GETSOCKOPT,
                fd,
                SOL_SOCKET,
                o,
                &mut v as *mut i32 as u64,
                &mut l as *mut u32 as u64,
                0,
            )
        };
        if r == 0 {
            v
        } else {
            0
        }
    };
    if opt(SO_PASSCRED) == 0 || (send && opt(SO_TYPE) != SOCK_DGRAM) {
        return;
    }
    let mut me = Name::new();
    let r = unsafe {
        sc3(
            nr::GETSOCKNAME,
            fd,
            me.sa.as_mut_ptr() as u64,
            &mut me.len as *mut u32 as u64,
        )
    };
    if r == 0 && me.len == 2 {
        let _ = super::unixsock::autobind(fd as i64);
    }
}

/// Output names: a call that writes an address and its length (`accept`, `getsockname`,
/// `getpeername`, `recvfrom`) gets runtime buffers in place of the guest's.
pub struct Out {
    addr: u64,
    lenp: u64,
    cap: u32,
    pub name: Name,
}

impl Out {
    /// Arguments `ai` and `ai + 1` of `call` (the address and its length's address), if the
    /// guest asked for the name.
    pub fn take(call: &mut dyn Call, ai: usize, out: &mut Out) -> Result<bool, i64> {
        let (addr, lenp) = (call.arg(ai), call.arg(ai + 1));
        if addr == 0 || lenp == 0 {
            return Ok(false);
        }
        let cap = guest::get::<i32>(lenp)?;
        if cap < 0 {
            return Err(-e::EINVAL);
        }
        out.addr = addr;
        out.lenp = lenp;
        out.cap = cap as u32;
        out.name = Name::new();
        call.set_arg(ai, out.name.sa.as_mut_ptr() as u64);
        call.set_arg(ai + 1, &mut out.name.len as *mut u32 as u64);
        Ok(true)
    }

    pub const fn new() -> Out {
        Out {
            addr: 0,
            lenp: 0,
            cap: 0,
            name: Name::new(),
        }
    }

    /// After a call that succeeded: the name to the guest.
    pub fn give(&mut self) -> Result<(), i64> {
        give(&mut self.name, self.addr, self.cap, self.lenp)
    }
}

/// The message headers of a `sendmsg`, `recvmsg`, `sendmmsg` or `recvmmsg` call, copied into
/// runtime memory with their names in runtime buffers: the guest's headers are only read (a
/// header may be read-only, or shared with another thread), and what the kernel writes into a
/// header (a received name's length, `msg_controllen`, `msg_flags`, an `mmsghdr`'s `msg_len`)
/// is copied to the guest's after the call.
pub struct Msgs {
    pub h: [[u64; 8]; MMSG_MAX],
    names: [Name; MMSG_MAX],
    /// The guest's name buffer and its size, per message (0: none).
    addr: [u64; MMSG_MAX],
    cap: [u32; MMSG_MAX],
    guest: u64,
    n: usize,
    stride: u64,
    recv: bool,
}

impl Msgs {
    pub const fn new() -> Msgs {
        Msgs {
            h: [[0; 8]; MMSG_MAX],
            names: [Name::new(); MMSG_MAX],
            addr: [0; MMSG_MAX],
            cap: [0; MMSG_MAX],
            guest: 0,
            n: 0,
            stride: 0,
            recv: false,
        }
    }

    /// `n` headers at `guest`, `stride` bytes apart (56: a `msghdr`, 64: an `mmsghdr`), of
    /// messages to send or to receive. `Ok(true)` when a name was put in a runtime buffer:
    /// the call is then to be given `ptr()`.
    pub fn take(&mut self, guest: u64, n: usize, stride: u64, recv: bool) -> Result<bool, i64> {
        let n = n.min(MMSG_MAX);
        let (mut any, len) = (false, stride as usize);
        (self.guest, self.n, self.stride, self.recv) = (guest, n, stride, recv);
        for i in 0..n {
            let mut b = [0u8; 64];
            guest::read(guest + i as u64 * stride, &mut b[..len])?;
            for (w, c) in self.h[i].iter_mut().zip(b.as_chunks::<8>().0) {
                *w = u64::from_ne_bytes(*c);
            }
            let (addr, alen) = (self.h[i][0], self.h[i][1] as u32);
            self.addr[i] = 0;
            if recv {
                if addr != 0 {
                    self.names[i] = Name::new();
                    self.h[i][0] = self.names[i].sa.as_ptr() as u64;
                    self.h[i][1] = SUN_LEN as u64;
                    (self.addr[i], self.cap[i]) = (addr, alen);
                    any = true;
                }
            } else if name_in(addr, alen as u64, &mut self.names[i])? {
                self.h[i][0] = self.names[i].sa.as_ptr() as u64;
                self.h[i][1] = self.names[i].len as u64;
                any = true;
            }
        }
        Ok(any)
    }

    /// The copied headers, for the call.
    pub fn ptr(&self) -> u64 {
        if self.stride == 56 {
            // A lone `msghdr`: its seven words.
            self.h[0].as_ptr() as u64
        } else {
            self.h.as_ptr() as u64
        }
    }

    /// After the call handled `count` messages: what the kernel wrote, to the guest's headers.
    pub fn done(&mut self, count: usize) -> Result<(), i64> {
        for i in 0..count.min(self.n) {
            let g = self.guest + i as u64 * self.stride;
            if self.recv {
                let mut n = self.h[i][1] as u32;
                if self.addr[i] != 0 {
                    n = strip(&mut self.names[i].sa, n as usize) as u32;
                    let k = (n as usize).min(self.cap[i] as usize);
                    guest::write(self.addr[i], &self.names[i].sa[..k])?;
                    guest::put::<u32>(g + 8, n)?;
                }
                guest::put::<u64>(g + 40, self.h[i][5])?;
                guest::put::<u32>(g + 48, self.h[i][6] as u32)?;
            }
            if self.stride == 64 {
                guest::put::<u32>(g + 56, self.h[i][7] as u32)?;
            }
        }
        Ok(())
    }
}
