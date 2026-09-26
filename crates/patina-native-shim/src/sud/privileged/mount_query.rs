//! Reading the mount table by unique mount id (fs/namespace.c `statmount`,
//! `listmount`), over the virtual machine's mounts ([`crate::volume::MOUNTS`]).
//! Any caller may read a mount reachable from its root; `CAP_SYS_ADMIN` only
//! reaches past it, and every mount of the virtual machine is reachable (the
//! caller's root is the namespace's, `chroot` being refused), so neither row
//! ever consults the credential.
//!
//! Where Ubuntu's 6.8.0-139 differs from the v6.8 tag, the model follows the
//! pinned build (seen live): a string area starts with an empty string (6.14's
//! "reserve an empty string for unset offsets"), and `listmount` refuses more
//! than a million ids (`EOVERFLOW`, 6.11's) and collects the ids before
//! copying them out, so an unknown parent is `ENOENT` whatever the array, and
//! a fault is `EFAULT` with no count of the ids copied (the copy may land the
//! ids before the faulting page, as `copy_to_user` may). Ubuntu moved this
//! ABI within the 6.8.0 series, so the pin is effectively 6.8.0-139's build:
//! a host kernel update that changes these answers is a pin question.
//!
//! One known difference: the namespace's root mount is its own parent. The
//! kernel's has a hidden parent (the initial rootfs), which `statmount`
//! refuses without `CAP_SYS_ADMIN` (`EPERM`) and `listmount` never lists; a
//! caller walking parents stops at the root either way.

use super::{Answer, refuse};
use crate::identity::Credential;
use crate::uaccess;
use crate::volume::{MOUNTS, Mount};
use linux_raw_sys::errno;

/// `struct mnt_id_req` as 6.8 knows it (`MNT_ID_REQ_SIZE_VER0`).
const REQUEST_SIZE: usize = 24;
/// `LSMT_ROOT`: `listmount` below the caller's root.
const LSMT_ROOT: u64 = u64::MAX;
/// The fixed part of `struct statmount`; its strings follow it.
const STATMOUNT_SIZE: usize = 512;
/// The `statmount` mask bits 6.8 answers; any other is ignored.
const STATMOUNT_SB_BASIC: u64 = 0x1;
const STATMOUNT_MNT_BASIC: u64 = 0x2;
const STATMOUNT_PROPAGATE_FROM: u64 = 0x4;
const STATMOUNT_MNT_ROOT: u64 = 0x8;
const STATMOUNT_MNT_POINT: u64 = 0x10;
const STATMOUNT_FS_TYPE: u64 = 0x20;
/// `MS_PRIVATE`: no mount of the virtual machine propagates (no init system
/// made any shared).
const MS_PRIVATE: u64 = 1 << 18;
/// The most ids one `listmount` collects (6.11's bound, which the pinned
/// build carries).
const LISTMOUNT_MAX: u64 = 1_000_000;

/// `copy_mnt_id_req`: the size (`EFAULT`), past a page `E2BIG`, short of
/// the first version `EINVAL`; then `copy_struct_from_user` (a tail past
/// the known structure unreadable `EFAULT`, nonzero `E2BIG`; the structure
/// unreadable `EFAULT`); a nonzero spare word `EINVAL` (6.17 makes it
/// `mnt_ns_fd`). The mount id and the parameter.
fn copy_request(address: u64) -> Result<(u64, u64), u32> {
    let address = address as usize;
    let size = uaccess::read::<u32>(address).map_err(|_| errno::EFAULT)? as usize;
    if size > crate::PAGE_SIZE {
        return Err(errno::E2BIG);
    }
    if size < REQUEST_SIZE {
        return Err(errno::EINVAL);
    }
    let tail = uaccess::read_bytes(address + REQUEST_SIZE, size - REQUEST_SIZE)
        .map_err(|_| errno::EFAULT)?;
    if tail.iter().any(|byte| *byte != 0) {
        return Err(errno::E2BIG);
    }
    let request = uaccess::read::<[u64; 3]>(address).map_err(|_| errno::EFAULT)?;
    if request[0] >> 32 != 0 {
        return Err(errno::EINVAL);
    }
    Ok((request[1], request[2]))
}

/// The mount with unique id `id` (`lookup_mnt_in_ns`).
fn find(id: u64) -> Option<&'static Mount> {
    MOUNTS.iter().find(|mount| mount.unique == id)
}

/// Whether `mount` is `under` or below it (`is_path_reachable` from its
/// root): its mount point is `under`'s, or inside it.
fn below(mount: &Mount, under: &Mount) -> bool {
    let within = under.point.trim_end_matches('/');
    mount.point == under.point
        || mount
            .point
            .strip_prefix(within)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// `statmount(req, buf, bufsize, flags)`: an unknown flag (`flags` is an
/// `unsigned int`) `EINVAL`; the request ([`copy_request`]); the buffer's
/// range (`access_ok`, `EFAULT`); the mount (`ENOENT`); then the requested
/// parts: the superblock's and the mount's basics, the propagation source,
/// and the strings (the mount's root, where it is mounted, its filesystem
/// type), a string without room `EOVERFLOW`; the strings are copied out,
/// then as much of the fixed part as the buffer holds (`EFAULT`). `size`
/// counts the bytes written.
pub(in crate::sud) fn statmount(_: &Credential, a: &[u64; 6]) -> Answer {
    if a[3] as u32 != 0 {
        return refuse(errno::EINVAL);
    }
    let (id, mask) = match copy_request(a[0]) {
        Ok(request) => request,
        Err(code) => return refuse(code),
    };
    let (buf, bufsize) = (a[1] as usize, a[2] as usize);
    if !uaccess::access_ok(buf, bufsize) {
        return refuse(errno::EFAULT);
    }
    let Some(mount) = find(id) else {
        return refuse(errno::ENOENT);
    };
    let mut fixed = [0u8; STATMOUNT_SIZE];
    let mut put = |offset: usize, bytes: &[u8]| {
        fixed[offset..offset + bytes.len()].copy_from_slice(bytes);
    };
    let mut answered = 0u64;
    if mask & STATMOUNT_SB_BASIC != 0 {
        answered |= STATMOUNT_SB_BASIC;
        let (major, minor) = mount.device();
        put(16, &major.to_ne_bytes());
        put(20, &minor.to_ne_bytes());
        put(24, &mount.magic().to_ne_bytes());
        // `sb_flags` (32): the volume and devtmpfs are read-write, neither
        // synchronous nor lazy.
    }
    if mask & STATMOUNT_MNT_BASIC != 0 {
        answered |= STATMOUNT_MNT_BASIC;
        let parent = mount.parent();
        put(40, &mount.unique.to_ne_bytes());
        put(48, &parent.unique.to_ne_bytes());
        put(56, &mount.id.to_ne_bytes());
        put(60, &parent.id.to_ne_bytes());
        put(64, &mount.attr.to_ne_bytes());
        put(72, &MS_PRIVATE.to_ne_bytes());
        // No peer group (80) or master (88): nothing is shared or a slave.
    }
    if mask & STATMOUNT_PROPAGATE_FROM != 0 {
        // Zero (96): only a slave mount propagates from somewhere.
        answered |= STATMOUNT_PROPAGATE_FROM;
    }
    let mut strings: Vec<u8> = Vec::new();
    for (bit, offset, text) in [
        (STATMOUNT_FS_TYPE, 36, mount.fs_type()),
        (STATMOUNT_MNT_ROOT, 104, mount.root),
        (STATMOUNT_MNT_POINT, 108, mount.point),
    ] {
        if mask & bit == 0 {
            continue;
        }
        if strings.is_empty() {
            strings.push(0);
        }
        let start = strings.len() as u32;
        strings.extend_from_slice(text.as_bytes());
        if STATMOUNT_SIZE + strings.len() >= bufsize {
            return refuse(errno::EOVERFLOW);
        }
        strings.push(0);
        put(offset, &start.to_ne_bytes());
        answered |= bit;
    }
    let copied = bufsize.min(STATMOUNT_SIZE);
    put(0, &((copied + strings.len()) as u32).to_ne_bytes());
    put(8, &answered.to_ne_bytes());
    let out = uaccess::write_bytes(buf + STATMOUNT_SIZE, &strings)
        .and_then(|()| uaccess::write_bytes(buf, &fixed[..copied]));
    match out {
        Ok(()) => Ok(0),
        Err(_) => refuse(errno::EFAULT),
    }
}

/// `listmount(req, mnt_ids, nr_mnt_ids, flags)`: an unknown flag (`flags`
/// is an `unsigned int`) `EINVAL`; more than a million ids `EOVERFLOW`;
/// the array's range (`access_ok`, `EFAULT`); the request
/// ([`copy_request`]); the mount below which to list (`LSMT_ROOT`: the
/// caller's root), `ENOENT` for none; then, in unique id order from past
/// the request's last id (0: from the first; `u64::MAX` wraps to it), each
/// mount reachable from there but that mount itself, up to `nr_mnt_ids`;
/// copied out whole (`EFAULT`). The answer is how many.
pub(in crate::sud) fn listmount(_: &Credential, a: &[u64; 6]) -> Answer {
    if a[3] as u32 != 0 {
        return refuse(errno::EINVAL);
    }
    let (ids, room) = (a[1] as usize, a[2]);
    if room > LISTMOUNT_MAX {
        return refuse(errno::EOVERFLOW);
    }
    if !uaccess::access_ok(ids, room as usize * size_of::<u64>()) {
        return refuse(errno::EFAULT);
    }
    let (parent, last) = match copy_request(a[0]) {
        Ok(request) => request,
        Err(code) => return refuse(code),
    };
    let under = if parent == LSMT_ROOT {
        &MOUNTS[0]
    } else {
        match find(parent) {
            Some(mount) => mount,
            None => return refuse(errno::ENOENT),
        }
    };
    let from = last.wrapping_add(1);
    let listed: Vec<u64> = MOUNTS
        .iter()
        .filter(|mount| last == 0 || mount.unique >= from)
        .filter(|mount| mount.unique != parent && below(mount, under))
        .map(|mount| mount.unique)
        .take(room as usize)
        .collect();
    if listed.is_empty() {
        return Ok(0);
    }
    match uaccess::write_slice(ids, &listed) {
        Ok(()) => Ok(listed.len() as i64),
        Err(_) => refuse(errno::EFAULT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::credential;
    use crate::volume::ROOT_MOUNT;

    fn request(size: u32, spare: u32, id: u64, param: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&size.to_ne_bytes());
        bytes[4..8].copy_from_slice(&spare.to_ne_bytes());
        bytes[8..16].copy_from_slice(&id.to_ne_bytes());
        bytes[16..24].copy_from_slice(&param.to_ne_bytes());
        bytes
    }

    fn statmount_of(req: &[u8], buf: &mut [u8], len: usize) -> i64 {
        let args = [
            req.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            len as u64,
            0,
            0,
            0,
        ];
        statmount(credential(), &args).unwrap()
    }

    fn listmount_of(req: &[u8], ids: &mut [u64]) -> i64 {
        let args = [
            req.as_ptr() as u64,
            ids.as_mut_ptr() as u64,
            ids.len() as u64,
            0,
            0,
            0,
        ];
        listmount(credential(), &args).unwrap()
    }

    fn u32_at(buf: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap())
    }

    fn u64_at(buf: &[u8], offset: usize) -> u64 {
        u64::from_ne_bytes(buf[offset..offset + 8].try_into().unwrap())
    }

    fn string_at(buf: &[u8], offset: u32) -> &str {
        let rest = &buf[STATMOUNT_SIZE + offset as usize..];
        std::ffi::CStr::from_bytes_until_nul(rest)
            .unwrap()
            .to_str()
            .unwrap()
    }

    /// Every part of every mount, and the size the pinned build counts: the
    /// strings after a leading empty one (the root's own `"/"` read 515
    /// bytes live on 6.8.0-139 for the mount point alone).
    #[test]
    fn statmount_describes_each_mount() {
        let all = STATMOUNT_SB_BASIC
            | STATMOUNT_MNT_BASIC
            | STATMOUNT_PROPAGATE_FROM
            | STATMOUNT_MNT_ROOT
            | STATMOUNT_MNT_POINT
            | STATMOUNT_FS_TYPE;
        for mount in &MOUNTS {
            let mut buf = vec![0xffu8; 1024];
            let len = buf.len();
            // An unknown mask bit is ignored.
            let req = request(24, 0, mount.unique, all | 1 << 40);
            assert_eq!(statmount_of(&req, &mut buf, len), 0);
            assert_eq!(u64_at(&buf, 8), all);
            assert_eq!(u64_at(&buf, 40), mount.unique);
            assert_eq!(u64_at(&buf, 48), ROOT_MOUNT.unique);
            assert_eq!(u32_at(&buf, 56), mount.id);
            assert_eq!(u32_at(&buf, 60), ROOT_MOUNT.id);
            assert_eq!(u64_at(&buf, 72), MS_PRIVATE);
            assert_eq!((u32_at(&buf, 16), u32_at(&buf, 20)), mount.device());
            assert_eq!(u64_at(&buf, 24), mount.magic());
            assert_eq!(string_at(&buf, u32_at(&buf, 36)), mount.fs_type());
            assert_eq!(string_at(&buf, u32_at(&buf, 104)), mount.root);
            assert_eq!(string_at(&buf, u32_at(&buf, 108)), mount.point);
            let strings = 1 + [mount.fs_type(), mount.root, mount.point]
                .iter()
                .map(|text| text.len() + 1)
                .sum::<usize>();
            assert_eq!(u32_at(&buf, 0) as usize, STATMOUNT_SIZE + strings);
            // The spare words stay zero, past the strings nothing is written.
            assert!(buf[112..STATMOUNT_SIZE].iter().all(|byte| *byte == 0));
            assert!(
                buf[STATMOUNT_SIZE + strings..]
                    .iter()
                    .all(|byte| *byte == 0xff)
            );
        }
    }

    #[test]
    fn statmount_room_and_order() {
        let root = ROOT_MOUNT.unique;
        let mut buf = vec![0x55u8; 1024];
        // "/" alone needs 512 + "\0/\0": room for 515, not 514.
        let point = request(24, 0, root, STATMOUNT_MNT_POINT);
        assert_eq!(
            statmount_of(&point, &mut buf, 514),
            -i64::from(errno::EOVERFLOW)
        );
        assert_eq!(statmount_of(&point, &mut buf, 515), 0);
        assert_eq!(u32_at(&buf, 0), 515);
        // A short buffer takes what fits of the fixed part, and says so.
        let basic = request(24, 0, root, STATMOUNT_MNT_BASIC);
        buf.fill(0x55);
        assert_eq!(statmount_of(&basic, &mut buf, 100), 0);
        assert_eq!(u32_at(&buf, 0), 100);
        assert!(buf[100..].iter().all(|byte| *byte == 0x55));
        // No room and nothing to write is no copy at all.
        let args = [basic.as_ptr() as u64, 0, 0, 0, 0, 0];
        assert_eq!(statmount(credential(), &args), Ok(0));
        // The buffer's range is judged before the mount is looked up.
        let absent = request(24, 0, u64::MAX - 1, 0);
        let huge = [
            absent.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            u64::MAX,
            0,
            0,
            0,
        ];
        assert_eq!(
            statmount(credential(), &huge),
            Ok(-i64::from(errno::EFAULT))
        );
        assert_eq!(
            statmount_of(&absent, &mut buf, 1024),
            -i64::from(errno::ENOENT)
        );
        // `LSMT_ROOT` names no mount here.
        let lsmt = request(24, 0, LSMT_ROOT, 0);
        assert_eq!(
            statmount_of(&lsmt, &mut buf, 1024),
            -i64::from(errno::ENOENT)
        );
        // `flags` is an `unsigned int`.
        let high = [
            basic.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            1024,
            1 << 32,
            0,
            0,
        ];
        assert_eq!(statmount(credential(), &high), Ok(0));
        let flag = [
            basic.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            1024,
            1,
            0,
            0,
        ];
        assert_eq!(
            statmount(credential(), &flag),
            Ok(-i64::from(errno::EINVAL))
        );
    }

    #[test]
    fn a_request_is_read_as_copy_mnt_id_req_reads_it() {
        let root = ROOT_MOUNT.unique;
        let mut buf = vec![0u8; 1024];
        let e = |code: u32| -i64::from(code);
        assert_eq!(
            statmount_of(&request(8192, 0, root, 0), &mut buf, 1024),
            e(errno::E2BIG)
        );
        assert_eq!(
            statmount_of(&request(16, 0, root, 0), &mut buf, 1024),
            e(errno::EINVAL)
        );
        assert_eq!(
            statmount_of(&request(24, 1, root, 0), &mut buf, 1024),
            e(errno::EINVAL)
        );
        let mut tail = request(32, 0, root, 0);
        assert_eq!(statmount_of(&tail, &mut buf, 1024), 0);
        tail[30] = 1;
        assert_eq!(statmount_of(&tail, &mut buf, 1024), e(errno::E2BIG));
        // The tail is judged before the spare word.
        let mut both = request(32, 1, root, 0);
        both[30] = 1;
        assert_eq!(statmount_of(&both, &mut buf, 1024), e(errno::E2BIG));
        let null = [0, buf.as_mut_ptr() as u64, 1024, 0, 0, 0];
        assert_eq!(statmount(credential(), &null), Ok(e(errno::EFAULT)));
    }

    #[test]
    fn listmount_lists_what_is_reachable() {
        let [root, device] = MOUNTS;
        let mut ids = [0u64; 8];
        let below_root = request(24, 0, LSMT_ROOT, 0);
        assert_eq!(listmount_of(&below_root, &mut ids), 2);
        assert_eq!(ids[..2], [root.unique, device.unique]);
        // Below a mount: not the mount itself.
        assert_eq!(listmount_of(&request(24, 0, root.unique, 0), &mut ids), 1);
        assert_eq!(ids[0], device.unique);
        assert_eq!(listmount_of(&request(24, 0, device.unique, 0), &mut ids), 0);
        // Past a last id; `u64::MAX` wraps to the start.
        assert_eq!(
            listmount_of(&request(24, 0, LSMT_ROOT, root.unique), &mut ids),
            1
        );
        assert_eq!(ids[0], device.unique);
        assert_eq!(
            listmount_of(&request(24, 0, LSMT_ROOT, u64::MAX), &mut ids),
            2
        );
        assert_eq!(listmount_of(&request(24, 0, LSMT_ROOT, 5), &mut ids), 2);
        // Room for one.
        assert_eq!(listmount_of(&below_root, &mut ids[..1]), 1);
        assert_eq!(listmount_of(&below_root, &mut ids[..0]), 0);
        let e = |code: u32| Ok(-i64::from(code));
        let absent = request(24, 0, u64::MAX - 1, 0);
        assert_eq!(listmount_of(&absent, &mut ids), -i64::from(errno::ENOENT));
        // The count's bound, then the array's range, then the request.
        let args = |req: u64, ids: u64, room: u64, flags: u64| [req, ids, room, flags, 0, 0];
        let r = below_root.as_ptr() as u64;
        let at = ids.as_mut_ptr() as u64;
        assert_eq!(
            listmount(credential(), &args(0, 0, 1_000_001, 0)),
            e(errno::EOVERFLOW)
        );
        assert_eq!(listmount(credential(), &args(r, at, 1_000_000, 0)), Ok(2));
        assert_eq!(
            listmount(credential(), &args(0, 0, 1_000_001, 1)),
            e(errno::EINVAL)
        );
        assert_eq!(
            listmount(credential(), &args(0, u64::MAX, 8, 0)),
            e(errno::EFAULT)
        );
        assert_eq!(
            listmount(credential(), &args(0, at, 8, 0)),
            e(errno::EFAULT)
        );
        // The parent is looked up before anything is copied out.
        let a = absent.as_ptr() as u64;
        assert_eq!(listmount(credential(), &args(a, 0, 8, 0)), e(errno::ENOENT));
        assert_eq!(listmount(credential(), &args(r, 0, 8, 0)), e(errno::EFAULT));
        assert_eq!(listmount(credential(), &args(r, at, 8, 1 << 32)), Ok(2));
    }
}
