//! Network-interface ioctl and netlink rows.

use super::*;

impl Probe {
    // ---- interfaces --------------------------------------------------------

    /// An `SIOCGIF*` request on `fd` naming interface `name` (or, for
    /// `SIOCGIFNAME`, index `index`), decoded as `field`.
    pub fn ifreq(
        &self,
        fd: i32,
        request: u64,
        request_name: &str,
        name: &str,
        index: i32,
        field: IfField,
    ) -> (i64, IfAnswer) {
        let mut ifr = [0u8; IFREQ];
        let bytes = name.as_bytes();
        ifr[..bytes.len().min(IFNAMSIZ)].copy_from_slice(&bytes[..bytes.len().min(IFNAMSIZ)]);
        if field == IfField::Name {
            ifr[IFNAMSIZ..IFNAMSIZ + 4].copy_from_slice(&index.to_ne_bytes());
        }
        let result = self.call(
            Syscall::N_ioctl,
            [fd as i64, request as i64, ifr.as_mut_ptr() as i64, 0, 0, 0],
        );
        let union = &ifr[IFNAMSIZ..];
        let int = i32::from_ne_bytes(union[..4].try_into().unwrap());
        let mut answer = IfAnswer::default();
        let builder = self
            .fd_arg(self.event(Syscall::N_ioctl, result), "fd", fd)
            .arg("request", request_name)
            .arg("number", request);
        let builder = if field == IfField::Name {
            builder.arg("ifindex", index)
        } else {
            builder.arg("ifname", name)
        };
        let builder = if result < 0 {
            builder
        } else {
            match field {
                IfField::Index => {
                    answer.index = int;
                    builder.field("ifindex", int)
                }
                IfField::Flags(mask) => {
                    answer.flags = u16::from_ne_bytes([union[0], union[1]]);
                    builder.field("flags", answer.flags & mask)
                }
                IfField::Addr => {
                    let family = u16::from_ne_bytes([union[0], union[1]]);
                    let ip = Ipv4Addr::new(union[4], union[5], union[6], union[7]);
                    answer.addr = Some(ip);
                    builder
                        .field("family", family_name(i32::from(family)))
                        .field("addr", ip.to_string())
                }
                IfField::Mtu => {
                    answer.mtu = int;
                    builder
                }
                IfField::Name => {
                    let end = ifr[..IFNAMSIZ]
                        .iter()
                        .position(|b| *b == 0)
                        .unwrap_or(IFNAMSIZ);
                    answer.name = String::from_utf8_lossy(&ifr[..end]).into_owned();
                    builder.field("ifname", answer.name.clone())
                }
                IfField::HwAddr => {
                    answer.hw_family = u16::from_ne_bytes([union[0], union[1]]);
                    answer.hw_bytes.copy_from_slice(&union[2..8]);
                    builder.field("hw_family", answer.hw_family).field(
                        "hw_addr",
                        answer
                            .hw_bytes
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(":"),
                    )
                }
            }
        };
        builder.emit();
        (result, answer)
    }

    /// `SIOCGIFCONF` into room for `slots` entries: the interfaces with an
    /// IPv4 address, `(name, address)`. Only the entry the scenario asks
    /// about is recorded (`lo`); how many others the host has is its own
    /// business.
    pub fn ifconf(&self, fd: i32, slots: usize, find: &str) -> (i64, Vec<(String, Ipv4Addr)>) {
        let mut buf = vec![0u8; slots * IFREQ];
        #[repr(C)]
        struct Ifconf {
            len: i32,
            buf: *mut u8,
        }
        let mut conf = Ifconf {
            len: buf.len() as i32,
            buf: buf.as_mut_ptr(),
        };
        let result = self.call(
            Syscall::N_ioctl,
            [
                fd as i64,
                SIOCGIFCONF as i64,
                &mut conf as *mut _ as i64,
                0,
                0,
                0,
            ],
        );
        let mut entries = Vec::new();
        if result >= 0 {
            for entry in buf[..(conf.len.max(0) as usize).min(buf.len())]
                .as_chunks::<IFREQ>()
                .0
            {
                let end = entry[..IFNAMSIZ]
                    .iter()
                    .position(|b| *b == 0)
                    .unwrap_or(IFNAMSIZ);
                let name = String::from_utf8_lossy(&entry[..end]).into_owned();
                let union = &entry[IFNAMSIZ..];
                entries.push((name, Ipv4Addr::new(union[4], union[5], union[6], union[7])));
            }
        }
        let found = entries.iter().find(|(name, _)| name == find);
        let builder = self
            .fd_arg(self.event(Syscall::N_ioctl, result), "fd", fd)
            .arg("request", "SIOCGIFCONF")
            .arg("number", SIOCGIFCONF)
            .arg("slots", slots)
            .arg("find", find);
        let builder = if result >= 0 {
            builder
                .field("whole_entries", (conf.len as usize).is_multiple_of(IFREQ))
                .field(
                    "found",
                    found.map_or(Value::Null, |(_, ip)| Value::from(ip.to_string())),
                )
        } else {
            builder
        };
        builder.emit();
        (result, entries)
    }

    /// `if_nametoindex(3)`: glibc's wrapper under the libc vehicle; otherwise
    /// the calls glibc makes (a datagram socket, `SIOCGIFINDEX`, close), not
    /// recorded one by one. Recorded as the index, or `-1` with the errno
    /// where glibc answers 0 and sets it.
    pub fn if_nametoindex(&self, name: &str) -> i64 {
        let result = match self.vehicle {
            Vehicle::Libc => {
                let c = cstr(name);
                // SAFETY: a NUL-terminated name.
                let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
                if index == 0 {
                    neg(crate::vehicle::errno())
                } else {
                    i64::from(index)
                }
            }
            _ => {
                let fd = self.call(
                    Syscall::N_socket,
                    [
                        libc::AF_INET as i64,
                        (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as i64,
                        0,
                        0,
                        0,
                        0,
                    ],
                );
                if fd < 0 {
                    fd
                } else {
                    let mut ifr = [0u8; IFREQ];
                    let bytes = name.as_bytes();
                    let take = bytes.len().min(IFNAMSIZ - 1);
                    ifr[..take].copy_from_slice(&bytes[..take]);
                    let result = self.call(
                        Syscall::N_ioctl,
                        [fd, SIOCGIFINDEX as i64, ifr.as_mut_ptr() as i64, 0, 0, 0],
                    );
                    self.call(Syscall::N_close, [fd, 0, 0, 0, 0, 0]);
                    if result < 0 {
                        result
                    } else {
                        i64::from(i32::from_ne_bytes(
                            ifr[IFNAMSIZ..IFNAMSIZ + 4].try_into().unwrap(),
                        ))
                    }
                }
            }
        };
        self.rec
            .event("if_nametoindex", result)
            .arg("ifname", name)
            .emit();
        result
    }

    // ---- netlink -----------------------------------------------------------

    /// Send one netlink request (`sendto` to the kernel, port 0): a header of
    /// `kind`, `flags` and `seq` followed by `body`.
    pub fn nl_request(&self, fd: i32, kind: u16, flags: u16, seq: u32, body: &[u8]) -> i64 {
        let len = nl::HEADER + body.len();
        let mut message = Vec::with_capacity(len);
        message.extend_from_slice(&(len as u32).to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&flags.to_ne_bytes());
        message.extend_from_slice(&seq.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(body);
        let (raw, alen) = SockAddr::Netlink { pid: 0, groups: 0 }.encode();
        let result = self.call(
            Syscall::N_sendto,
            [
                fd as i64,
                message.as_ptr() as i64,
                len as i64,
                0,
                &raw as *const _ as i64,
                i64::from(alen),
            ],
        );
        self.fd_arg(self.event(Syscall::N_sendto, result), "fd", fd)
            .arg("len", len)
            .arg("nlmsg_type", kind)
            .arg("nlmsg_flags", flags)
            .arg("nlmsg_seq", seq)
            .arg("addr_family", "AF_NETLINK")
            .arg("addr_nl_pid", 0)
            .emit();
        result
    }

    /// Every netlink message queued for `fd` up to and including the one
    /// that ends the answer to a request (`NLMSG_DONE`, `NLMSG_ERROR`, or a
    /// single message without `NLM_F_MULTI`), read with `MSG_DONTWAIT` and
    /// not recorded (how the kernel splits a dump across reads is its
    /// business). `Err` names what went wrong: a read error, a queue that ran
    /// dry first, or more than `max_reads` reads.
    pub fn nl_answer(&self, fd: i32, max_reads: usize) -> Result<Vec<NlMsg>, String> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        for _ in 0..max_reads {
            let n = self.call(
                Syscall::N_recvfrom,
                [
                    fd as i64,
                    buf.as_mut_ptr() as i64,
                    buf.len() as i64,
                    libc::MSG_DONTWAIT as i64,
                    0,
                    0,
                ],
            );
            if n < 0 {
                return Err(format!(
                    "recvfrom answered {}",
                    crate::vehicle::errno_name((-n) as i32)
                ));
            }
            let mut at = 0;
            let n = n as usize;
            while at + nl::HEADER <= n {
                let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
                if len < nl::HEADER || at + len > n {
                    return Err(format!("a malformed netlink header (len {len})"));
                }
                let message = NlMsg {
                    kind: u16::from_ne_bytes([buf[at + 4], buf[at + 5]]),
                    flags: u16::from_ne_bytes([buf[at + 6], buf[at + 7]]),
                    seq: u32::from_ne_bytes(buf[at + 8..at + 12].try_into().unwrap()),
                    pid: u32::from_ne_bytes(buf[at + 12..at + 16].try_into().unwrap()),
                    payload: buf[at + nl::HEADER..at + len].to_vec(),
                };
                let last = matches!(message.kind, nl::NLMSG_DONE | nl::NLMSG_ERROR)
                    || message.flags & nl::NLM_F_MULTI == 0;
                out.push(message);
                if last {
                    return Ok(out);
                }
                at += len.div_ceil(4) * 4;
            }
        }
        Err(format!("no end of the answer within {max_reads} reads"))
    }
}
