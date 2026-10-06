//! Key lifecycle and key-management syscall operations.

use super::*;

/// The calling thread's id, whose process keyring the key calls use.
fn caller_tid() -> c_int {
    crate::thread::deterministic_thread_id()
}

/// A new thread `child` of `parent` shares its creator's process keyring
/// (`copy_creds`).
pub(in crate::sud) fn keyring_spawned(parent: c_int, child: c_int) {
    KEYS.lock().unwrap().spawned(parent, child);
}

/// Thread `tid` exited, with its reference to its process keyring.
pub(in crate::sud) fn keyring_exited(tid: c_int) {
    KEYS.lock().unwrap().exited(tid);
}

/// `add_key(type, description, payload, plen, ringid)`.
pub(in crate::sud) fn add_key(credential: &Credential, a: &[u64; 6]) -> Answer {
    let now = now_seconds();
    answer(add_key_at(credential, caller_tid(), a, now))
}

fn add_key_at(credential: &Credential, tid: c_int, a: &[u64; 6], now: u64) -> Result<i64, Stop> {
    let plen = a[3];
    if plen > MAX_PAYLOAD {
        return Err(errno::EINVAL.into());
    }
    let type_name = type_from_user(a[0])?;
    let mut description = None;
    if a[1] != 0 {
        let text = guest_strndup(a[1], KEY_MAX_DESC_SIZE)?;
        if text.first() == Some(&b'.') && type_name.starts_with(b"keyring") {
            return Err(errno::EPERM.into());
        }
        description = Some(text).filter(|text| !text.is_empty());
    }
    let data = if plen != 0 {
        crate::uaccess::read_bytes(a[2] as usize, plen as usize).map_err(|_| errno::EFAULT)?
    } else {
        Vec::new()
    };
    let mut keys = KEYS.lock().unwrap();
    keys.collect(now)?;
    let (ring, _) = keys.lookup(credential, tid, a[4] as i32, true, Some(NEED_WRITE))?;
    let keyring_type = match key_type(&type_name) {
        KeyType::User => false,
        KeyType::Keyring => true,
        KeyType::Unmodeled => return Err(unmodeled_type(&type_name)),
        KeyType::Unknown => return Err(errno::ENODEV.into()),
    };
    if !matches!(keys.keys[&ring].payload, Payload::Keyring(_)) {
        return Err(errno::ENOTDIR.into());
    }
    // The type's `preparse`: a `user` key holds 1 to 32767 bytes, a keyring
    // none; both need a description.
    let preparsed = if keyring_type {
        plen == 0
    } else {
        (1..=MAX_USER_PAYLOAD).contains(&data.len())
    };
    let Some(description) = description.filter(|_| preparsed) else {
        return Err(errno::EINVAL.into());
    };
    if keyring_type {
        return Err(unmodeled("a keyring inside a keyring"));
    }
    keys.create_or_update(credential, ring, description, data)
}

/// `request_key(type, description, callout_info, dest_keyringid)`: the
/// strings, the destination (made on demand), the type (`ENOKEY` for one no
/// module registers), then a search of the calling thread's process
/// keyring, then the session (including its persistent subtree); a
/// miss without callout information is `ENOKEY`.
pub(in crate::sud) fn request_key(credential: &Credential, a: &[u64; 6]) -> Answer {
    let now = now_seconds();
    answer(request_key_at(credential, caller_tid(), a, now))
}

fn request_key_at(
    credential: &Credential,
    tid: c_int,
    a: &[u64; 6],
    now: u64,
) -> Result<i64, Stop> {
    let type_name = type_from_user(a[0])?;
    let description = guest_strndup(a[1], KEY_MAX_DESC_SIZE)?;
    let callout = if a[2] != 0 {
        Some(guest_strndup(a[2], PAGE_SIZE)?)
    } else {
        None
    };
    let mut keys = KEYS.lock().unwrap();
    keys.collect(now)?;
    let destination = match a[3] as i32 {
        0 => None,
        id => Some(keys.lookup(credential, tid, id, true, Some(NEED_WRITE))?.0),
    };
    match key_type(&type_name) {
        KeyType::User => {}
        KeyType::Keyring => return Err(unmodeled("request_key of a keyring")),
        KeyType::Unmodeled => return Err(unmodeled_type(&type_name)),
        KeyType::Unknown => return Err(errno::ENOKEY.into()),
    }
    let rings: Vec<_> = keys
        .holders
        .get(&tid)
        .copied()
        .into_iter()
        .chain([FIRST_SERIAL])
        .collect();
    let mut error = errno::EACCES;
    for ring in rings {
        match keys.search(credential, ring, &description, true) {
            Ok(serial) => {
                if let Some(dest) = destination {
                    if !permitted(&keys.keys[&serial], credential, true, NEED_LINK) {
                        return Err(errno::EACCES.into());
                    }
                    keys.link(serial, dest)?;
                }
                return Ok(i64::from(serial));
            }
            Err(Stop::Refuse(code)) => {
                if code == errno::ENOKEY || error != errno::ENOKEY {
                    error = code;
                }
            }
            Err(end) => return Err(end),
        }
    }
    if error == errno::ENOKEY && callout.is_some() {
        return Err(unmodeled(
            "request_key's upcall to /sbin/request-key (it would run outside the simulation)",
        ));
    }
    Err(error.into())
}

/// `keyctl(option, arg2, arg3, arg4, arg5)`, the operation an `int`.
pub(in crate::sud) fn keyctl(credential: &Credential, a: &[u64; 6]) -> Answer {
    let now = now_seconds();
    answer(keyctl_at(credential, caller_tid(), a, now))
}

pub(super) fn keyctl_at(
    credential: &Credential,
    tid: c_int,
    a: &[u64; 6],
    now: u64,
) -> Result<i64, Stop> {
    let option = a[0] as i32;
    let id = a[1] as i32;
    match option {
        KEYCTL_GET_PERSISTENT => {
            let uid = a[1] as u32;
            if uid != u32::MAX && uid != credential.uid {
                return Err(if credential.capable(Capability::Setuid) {
                    Stop::End(Unmodeled::Granted(Capability::Setuid))
                } else {
                    errno::EPERM.into()
                });
            }
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            let (ring, _) = keys.lookup(credential, tid, a[2] as i32, true, Some(NEED_WRITE))?;
            keys.persistent(credential, ring, now)
        }
        KEYCTL_LINK => {
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            let (ring, _) = keys.lookup(credential, tid, a[2] as i32, true, Some(NEED_WRITE))?;
            let (serial, _) = keys.lookup(credential, tid, id, true, Some(NEED_LINK))?;
            keys.link(serial, ring)?;
            Ok(0)
        }
        KEYCTL_SEARCH => {
            let kind = type_from_user(a[2])?;
            let description = guest_strndup(a[3], KEY_MAX_DESC_SIZE)?;
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            let (ring, possessed) = keys.lookup(credential, tid, id, false, Some(NEED_SEARCH))?;
            if a[4] as i32 != 0 {
                return Err(unmodeled("KEYCTL_SEARCH with a destination"));
            }
            match key_type(&kind) {
                KeyType::User => {}
                KeyType::Unknown => return Err(errno::ENOKEY.into()),
                _ => return Err(unmodeled("KEYCTL_SEARCH for a type other than user")),
            }
            keys.search(credential, ring, &description, possessed)
                .map(i64::from)
        }
        KEYCTL_INVALIDATE => {
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            let (serial, _) = match keys.lookup(credential, tid, id, false, Some(NEED_SEARCH)) {
                Err(Stop::Refuse(_)) if credential.capable(Capability::SysAdmin) => {
                    return Err(Stop::End(Unmodeled::Granted(Capability::SysAdmin)));
                }
                found => found?,
            };
            keys.invalidate(serial).map(|()| 0)
        }
        KEYCTL_GET_KEYRING_ID => {
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            keys.lookup(credential, tid, id, a[2] as i32 != 0, Some(NEED_SEARCH))
                .map(|(serial, _)| i64::from(serial))
        }
        KEYCTL_UPDATE => {
            let plen = a[3] as usize;
            if plen > PAGE_SIZE {
                return Err(errno::EINVAL.into());
            }
            let data = if plen != 0 {
                crate::uaccess::read_bytes(a[2] as usize, plen).map_err(|_| errno::EFAULT)?
            } else {
                Vec::new()
            };
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            let (serial, _) = keys.lookup(credential, tid, id, false, Some(NEED_WRITE))?;
            if !matches!(keys.keys[&serial].payload, Payload::User(_)) {
                return Err(errno::EOPNOTSUPP.into());
            }
            if data.is_empty() {
                return Err(errno::EINVAL.into());
            }
            keys.update(serial, data).map(|()| 0)
        }
        KEYCTL_REVOKE => {
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            // Write permission, or failing that, setattr.
            let (serial, _) = match keys.lookup(credential, tid, id, false, Some(NEED_WRITE)) {
                Err(Stop::Refuse(errno::EACCES)) => {
                    keys.lookup(credential, tid, id, false, Some(NEED_SETATTR))?
                }
                found => found?,
            };
            let key = keys.keys.get_mut(&serial).unwrap();
            if matches!(key.payload, Payload::Keyring(_)) {
                return Err(unmodeled("revoking a keyring"));
            }
            key.payload = Payload::User(Vec::new());
            key.revoked_at = Some(now);
            Ok(0)
        }
        KEYCTL_CHOWN => chown(credential, tid, id, a[2] as u32, a[3] as u32, now),
        KEYCTL_DESCRIBE => {
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            let (serial, _) = keys.lookup(credential, tid, id, false, Some(NEED_VIEW))?;
            let key = &keys.keys[&serial];
            let mut text = format!(
                "{};{};{};{:08x};",
                key.type_name(),
                key.uid as i32,
                if key.gid == u32::MAX {
                    65534
                } else {
                    key.gid as i32
                },
                key.perm
            )
            .into_bytes();
            text.extend_from_slice(&key.description);
            text.push(0);
            let (buffer, length) = (a[2] as usize, a[3] as u32 as usize);
            if buffer != 0
                && length >= text.len()
                && crate::uaccess::write_bytes(buffer, &text).is_err()
            {
                return Err(errno::EFAULT.into());
            }
            Ok(text.len() as i64)
        }
        KEYCTL_READ => read(credential, tid, id, a[2] as usize, a[3] as usize, now),
        KEYCTL_CAPABILITIES => capabilities(a[1] as usize, a[2] as usize),
        _ => match KEYCTL_NAMES.get(option as usize) {
            Some(name) => Err(unmodeled(*name)),
            None => Err(errno::EOPNOTSUPP.into()),
        },
    }
}

/// `keyctl_chown_key`: -1 for both ids changes nothing, before the key is
/// looked up (made on demand); handing it to another user, or to a group
/// the caller is not in, needs `CAP_SYS_ADMIN` (`EACCES`).
pub(super) fn chown(
    credential: &Credential,
    tid: c_int,
    id: i32,
    uid: u32,
    gid: u32,
    now: u64,
) -> Result<i64, Stop> {
    const UNCHANGED: u32 = u32::MAX;
    if uid == UNCHANGED && gid == UNCHANGED {
        return Ok(0);
    }
    let mut keys = KEYS.lock().unwrap();
    keys.collect(now)?;
    let (serial, _) = keys.lookup(credential, tid, id, true, Some(NEED_SETATTR))?;
    let key = keys.keys.get_mut(&serial).unwrap();
    let in_group = gid == credential.gid || credential.groups.contains(&gid);
    let privileged =
        (uid != UNCHANGED && uid != key.uid) || (gid != UNCHANGED && gid != key.gid && !in_group);
    if privileged {
        return Err(if credential.capable(Capability::SysAdmin) {
            Stop::End(Unmodeled::Granted(Capability::SysAdmin))
        } else {
            errno::EACCES.into()
        });
    }
    if gid != UNCHANGED {
        key.gid = gid;
    }
    Ok(0)
}

/// `keyctl_read_key`: any failure to find the key is `ENOKEY`; a key the
/// calling thread neither may read nor possesses is `EACCES`; a revoked key
/// reads `EKEYREVOKED`. The answer is the data's length, copied only when
/// it fits; a keyring's data is its links' serials, and a buffer of up to a
/// page must hold whole ones (`EINVAL`).
pub(super) fn read(
    credential: &Credential,
    tid: c_int,
    id: i32,
    buffer: usize,
    length: usize,
    now: u64,
) -> Result<i64, Stop> {
    let mut keys = KEYS.lock().unwrap();
    keys.collect(now)?;
    let (serial, possessed) = keys
        .lookup(credential, tid, id, false, None)
        .map_err(|stop| match stop {
            Stop::Refuse(_) => Stop::Refuse(errno::ENOKEY),
            end => end,
        })?;
    let key = &keys.keys[&serial];
    if !possessed && !permitted(key, credential, false, NEED_READ) {
        return Err(errno::EACCES.into());
    }
    if key.revoked_at.is_some() {
        return Err(errno::EKEYREVOKED.into());
    }
    let copying = buffer != 0 && length != 0;
    let data: Vec<u8> = match &key.payload {
        Payload::User(data) => data.clone(),
        Payload::Keyring(_) if copying && length <= PAGE_SIZE && !length.is_multiple_of(4) => {
            return Err(errno::EINVAL.into());
        }
        Payload::Keyring(links) if copying && length >= 4 * links.len() && links.len() > 1 => {
            return Err(unmodeled(
                "reading a keyring of more than one key (its order is its associative array's)",
            ));
        }
        Payload::Keyring(links) => links
            .iter()
            .flat_map(|serial| serial.to_ne_bytes())
            .collect(),
    };
    if copying && length >= data.len() && crate::uaccess::write_bytes(buffer, &data).is_err() {
        return Err(errno::EFAULT.into());
    }
    Ok(data.len() as i64)
}

/// `keyctl_capabilities`: [`CAPABILITIES`], as much as fits, the rest of
/// the room cleared (`EFAULT` where a byte cannot be written); the answer
/// is its size.
pub(super) fn capabilities(buffer: usize, length: usize) -> Result<i64, Stop> {
    let copied = length.min(CAPABILITIES.len());
    if crate::uaccess::write_bytes(buffer, &CAPABILITIES[..copied]).is_err() {
        return Err(errno::EFAULT.into());
    }
    // `clear_user` of the rest, a page at a time.
    let Some(end) = buffer.checked_add(length) else {
        return Err(errno::EFAULT.into());
    };
    let mut at = buffer + copied;
    while at < end {
        let chunk = (PAGE_SIZE - at % PAGE_SIZE).min(end - at);
        if crate::uaccess::write_bytes(at, &[0; PAGE_SIZE][..chunk]).is_err() {
            return Err(errno::EFAULT.into());
        }
        at += chunk;
    }
    Ok(CAPABILITIES.len() as i64)
}
