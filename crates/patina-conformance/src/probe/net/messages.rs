//! Socket message and multi-message rows.

use super::*;

impl Probe {
    // ---- messages ----------------------------------------------------------

    /// `sendmsg` of `segments` (one iovec each) to `to`, with `control`.
    pub fn sendmsg(
        &self,
        fd: i32,
        segments: &[&[u8]],
        to: Option<&SockAddr>,
        control: &Control,
        flags: i32,
    ) -> i64 {
        let mut iov = write_vector(segments);
        let encoded = to.map(SockAddr::encode);
        let mut cbuf = control_bytes(control);
        // SAFETY: an all-zero msghdr is a valid value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        if let Some((raw, len)) = &encoded {
            msg.msg_name = raw as *const _ as *mut libc::c_void;
            msg.msg_namelen = *len;
        }
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len() as _;
        if !cbuf.is_empty() {
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = match control {
                Control::ShortHeader => cmsg_space(4),
                Control::Rights(fds) => cmsg_space(fds.len() * 4),
                Control::Creds { .. } => cmsg_space(12),
                Control::Protocol(messages) => messages
                    .iter()
                    .map(|(_, _, data)| cmsg_space(data.len()))
                    .sum(),
                Control::None => 0,
            } as _;
        }
        let result = self.call(
            Syscall::N_sendmsg,
            [fd as i64, &msg as *const _ as i64, flags as i64, 0, 0, 0],
        );
        let lens: Vec<Value> = segments.iter().map(|s| Value::from(s.len())).collect();
        let builder = self
            .fd_arg(self.event(Syscall::N_sendmsg, result), "fd", fd)
            .arg("iov", Value::Array(lens))
            .arg("flags", flags);
        let builder = match to {
            Some(to) => to.record(builder, false, "name"),
            None => builder.arg("name", Value::Null),
        };
        let builder = match control {
            Control::None => builder.arg("control", "none"),
            Control::ShortHeader => builder.arg("control", "short-header"),
            Control::Rights(fds) => {
                let mut builder = builder.arg("control", format!("rights x{}", fds.len()));
                match shared(fds) {
                    Some(fd) => builder = self.fd_arg(builder, "right_each", *fd),
                    None => {
                        for (index, fd) in fds.iter().enumerate() {
                            builder = self.fd_arg(builder, &format!("right{index}"), *fd);
                        }
                    }
                }
                builder
            }
            Control::Protocol(messages) => {
                let described: Vec<Value> = messages
                    .iter()
                    .map(|(level, kind, data)| Value::from(cmsg_text(*level, *kind, data)))
                    .collect();
                builder.arg("control", Value::Array(described))
            }
            Control::Creds { pid, uid, gid } => builder
                .arg("control", "credentials")
                .arg("cred_pid", *pid)
                .norm("args.cred_pid", Norm::Identity(Id::Process))
                .arg("cred_uid", *uid)
                .norm("args.cred_uid", Norm::Identity(Id::User))
                .arg("cred_gid", *gid)
                .norm("args.cred_gid", Norm::Identity(Id::Group)),
        };
        builder.emit();
        result
    }

    /// `sendmsg` with a message header the kernel cannot read (`msg` is the
    /// address 1): `EFAULT` before anything else. glibc's wrapper passes the
    /// pointer straight through, so every vehicle issues the same call.
    pub fn sendmsg_bad_header(&self, fd: i32) -> i64 {
        let result = self.call(Syscall::N_sendmsg, [fd as i64, 1, 0, 0, 0, 0]);
        self.fd_arg(self.event(Syscall::N_sendmsg, result), "fd", fd)
            .arg("msg", "bad pointer")
            .emit();
        result
    }

    /// `sendmsg` with `iovlen` zero-length segments (the count alone is
    /// judged: `UIO_MAXIOV` bounds it).
    pub fn sendmsg_iovlen(&self, fd: i32, iovlen: usize) -> i64 {
        let mut iov = vec![
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            };
            iovlen.max(1)
        ];
        // SAFETY: an all-zero msghdr is a valid value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iovlen as _;
        let result = self.call(
            Syscall::N_sendmsg,
            [fd as i64, &msg as *const _ as i64, 0, 0, 0, 0],
        );
        self.fd_arg(self.event(Syscall::N_sendmsg, result), "fd", fd)
            .arg("iovlen", iovlen)
            .emit();
        result
    }

    /// `recvmsg` into `spec`'s segments, name and control buffers. Received
    /// descriptors are recorded as `fd` labels, credentials as identities.
    pub fn recvmsg(&self, fd: i32, spec: RecvSpec<'_>) -> Received {
        let (buffers, mut iov) = read_vector(spec.segments);
        // SAFETY: an all-zero sockaddr_storage / msghdr is a valid value.
        let mut raw: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut cbuf = vec![0u64; spec.control.div_ceil(8)];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        if let Some(cap) = spec.name {
            msg.msg_name = &mut raw as *mut _ as *mut libc::c_void;
            msg.msg_namelen = cap as u32;
        }
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len() as _;
        if spec.control > 0 {
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = spec.control as _;
        }
        let result = self.call(
            Syscall::N_recvmsg,
            [
                fd as i64,
                &mut msg as *mut _ as i64,
                spec.flags as i64,
                0,
                0,
                0,
            ],
        );
        let mut received = Received {
            result,
            ..Received::default()
        };
        if result >= 0 {
            let mut left = result as usize;
            for buf in &buffers {
                let take = left.min(buf.len());
                received.segments.push(buf[..take].to_vec());
                left -= take;
            }
            received.msg_flags = msg.msg_flags;
            received.namelen = msg.msg_namelen;
            if spec.name.is_some() {
                received.name = Some(SockAddr::decode(
                    &raw,
                    msg.msg_namelen.min(spec.name.unwrap_or(0) as u32),
                ));
            }
            received.controllen = msg.msg_controllen as usize;
            // SAFETY: the kernel filled `msg_controllen` bytes of cmsgs.
            unsafe {
                let mut header = libc::CMSG_FIRSTHDR(&msg);
                while !header.is_null() {
                    let data = libc::CMSG_DATA(header);
                    let len = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    match ((*header).cmsg_level, (*header).cmsg_type) {
                        (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                            for index in 0..len / 4 {
                                let mut fd = [0u8; 4];
                                std::ptr::copy_nonoverlapping(
                                    data.add(index * 4),
                                    fd.as_mut_ptr(),
                                    4,
                                );
                                received.rights.push(i32::from_ne_bytes(fd));
                            }
                        }
                        (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) if len >= 12 => {
                            let mut creds = [0u8; 12];
                            std::ptr::copy_nonoverlapping(data, creds.as_mut_ptr(), 12);
                            received.creds = Some((
                                i32::from_ne_bytes(creds[0..4].try_into().unwrap()),
                                u32::from_ne_bytes(creds[4..8].try_into().unwrap()),
                                u32::from_ne_bytes(creds[8..12].try_into().unwrap()),
                            ));
                        }
                        (level, kind) => {
                            let mut bytes = vec![0u8; len];
                            std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), len);
                            received.protocol.push((level, kind, bytes));
                        }
                    }
                    header = libc::CMSG_NXTHDR(&msg, header);
                }
            }
        }
        let lens: Vec<Value> = spec.segments.iter().map(|len| Value::from(*len)).collect();
        let builder = self
            .fd_arg(self.event(Syscall::N_recvmsg, result), "fd", fd)
            .arg("iov", Value::Array(lens))
            .arg("name_cap", spec.name.map_or(Value::Null, Value::from))
            .arg("control_cap", spec.control)
            .arg("flags", spec.flags);
        let mut builder = if result >= 0 {
            let data: Vec<Value> = received
                .segments
                .iter()
                .map(|segment| Value::from(printable(segment)))
                .collect();
            builder
                .field("segments", Value::Array(data))
                .field("msg_flags", received.msg_flags)
                .field("controllen", received.controllen)
        } else {
            builder
        };
        if let Some(name) = &received.name {
            builder = name
                .record(builder, true, "name")
                .field("namelen", received.namelen);
        }
        if result >= 0 && spec.control > 0 {
            builder = builder.field("rights", received.rights.len());
            for (index, right) in received.rights.iter().enumerate() {
                builder = builder
                    .field(&format!("right{index}"), *right)
                    .norm(&format!("fields.right{index}"), Norm::Relative("fd"));
            }
        }
        if !received.protocol.is_empty() {
            let described: Vec<Value> = received
                .protocol
                .iter()
                .map(|(level, kind, data)| Value::from(cmsg_text(*level, *kind, data)))
                .collect();
            builder = builder.field("cmsgs", Value::Array(described));
        }
        if let Some((pid, uid, gid)) = received.creds {
            builder = builder
                .field("cred_pid", pid)
                .norm("fields.cred_pid", Norm::Identity(Id::Process))
                .field("cred_uid", uid)
                .norm("fields.cred_uid", Norm::Identity(Id::User))
                .field("cred_gid", gid)
                .norm("fields.cred_gid", Norm::Identity(Id::Group));
        }
        builder.emit();
        received
    }

    /// `sendmmsg` of `messages` (one iovec each). The recorded `sent` array is
    /// every message's `msg_len` the kernel filled (sent messages only).
    pub fn sendmmsg(&self, fd: i32, messages: &[Outgoing<'_>], flags: i32) -> (i64, Vec<u32>) {
        let names: Vec<Option<(libc::sockaddr_storage, u32)>> = messages
            .iter()
            .map(|message| message.to.as_ref().map(SockAddr::encode))
            .collect();
        let data: Vec<&[u8]> = messages.iter().map(|message| message.data).collect();
        let mut iov = write_vector(&data);
        let mut headers: Vec<libc::mmsghdr> = (0..messages.len())
            .map(|index| {
                // SAFETY: an all-zero mmsghdr is a valid value.
                let mut header: libc::mmsghdr = unsafe { std::mem::zeroed() };
                header.msg_hdr.msg_iov = &mut iov[index];
                header.msg_hdr.msg_iovlen = 1;
                if let Some((raw, len)) = &names[index] {
                    header.msg_hdr.msg_name = raw as *const _ as *mut libc::c_void;
                    header.msg_hdr.msg_namelen = *len;
                }
                header
            })
            .collect();
        let pointer = if headers.is_empty() {
            0
        } else {
            headers.as_mut_ptr() as i64
        };
        let result = self.call(
            Syscall::N_sendmmsg,
            [
                fd as i64,
                pointer,
                messages.len() as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let sent: Vec<u32> = headers
            .iter()
            .take(result.max(0) as usize)
            .map(|header| header.msg_len)
            .collect();
        let lens: Vec<Value> = messages.iter().map(|m| Value::from(m.data.len())).collect();
        let mut builder = self
            .fd_arg(self.event(Syscall::N_sendmmsg, result), "fd", fd)
            .arg("vlen", messages.len())
            .arg("lens", list_or_shared(lens))
            .arg("flags", flags);
        let destinations: Vec<Option<&SockAddr>> =
            messages.iter().map(|message| message.to.as_ref()).collect();
        match shared(&destinations) {
            Some(Some(to)) => builder = to.record(builder, false, "to_each"),
            _ => {
                for (index, to) in destinations.iter().enumerate() {
                    if let Some(to) = to {
                        builder = to.record(builder, false, &format!("to{index}"));
                    }
                }
            }
        }
        let builder = if result >= 0 {
            builder.field(
                "sent",
                list_or_shared(sent.iter().map(|len| Value::from(*len)).collect()),
            )
        } else {
            builder
        };
        builder.emit();
        (result, sent)
    }

    /// `recvmmsg` into one buffer of each capacity in `caps`, with source
    /// names; `timeout` is `(sec, nsec)` (`None` passes NULL).
    pub fn recvmmsg(
        &self,
        fd: i32,
        caps: &[usize],
        flags: i32,
        timeout: Option<(i64, i64)>,
    ) -> (i64, Vec<Incoming>) {
        let (buffers, mut iov) = read_vector(caps);
        // SAFETY: all-zero sockaddr_storage values are valid.
        let mut names: Vec<libc::sockaddr_storage> = (0..caps.len())
            .map(|_| unsafe { std::mem::zeroed() })
            .collect();
        let mut headers: Vec<libc::mmsghdr> = (0..caps.len())
            .map(|index| {
                // SAFETY: an all-zero mmsghdr is a valid value.
                let mut header: libc::mmsghdr = unsafe { std::mem::zeroed() };
                header.msg_hdr.msg_iov = &mut iov[index];
                header.msg_hdr.msg_iovlen = 1;
                header.msg_hdr.msg_name = &mut names[index] as *mut _ as *mut libc::c_void;
                header.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
                header
            })
            .collect();
        let mut ts = timeout.map(|(tv_sec, tv_nsec)| libc::timespec { tv_sec, tv_nsec });
        let result = self.call(
            Syscall::N_recvmmsg,
            [
                fd as i64,
                headers.as_mut_ptr() as i64,
                caps.len() as i64,
                flags as i64,
                ts.as_mut().map_or(0, |ts| ts as *mut libc::timespec as i64),
                0,
            ],
        );
        let incoming: Vec<Incoming> = headers
            .iter()
            .enumerate()
            .take(result.max(0) as usize)
            .map(|(index, header)| Incoming {
                data: buffers[index][..(header.msg_len as usize).min(caps[index])].to_vec(),
                len: header.msg_len,
                flags: header.msg_hdr.msg_flags,
                from: Some(SockAddr::decode(&names[index], header.msg_hdr.msg_namelen)),
            })
            .collect();
        let caps_value: Vec<Value> = caps.iter().map(|cap| Value::from(*cap)).collect();
        let mut builder = self
            .fd_arg(self.event(Syscall::N_recvmmsg, result), "fd", fd)
            .arg("vlen", caps.len())
            .arg("caps", Value::Array(caps_value))
            .arg("flags", flags)
            .arg(
                "timeout",
                timeout.map_or(Value::Null, |(s, ns)| Value::from(format!("{s}s{ns}ns"))),
            );
        for (index, message) in incoming.iter().enumerate() {
            builder = builder
                .field(&format!("data{index}"), printable(&message.data))
                .field(&format!("len{index}"), message.len)
                .field(&format!("flags{index}"), message.flags);
            if let Some(from) = &message.from {
                builder = from.record(builder, true, &format!("src{index}"));
            }
        }
        builder.emit();
        (result, incoming)
    }
}
