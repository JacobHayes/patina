//! `proto::abi` against the C library's definitions for this target (the libc crate, written
//! from each architecture's kernel and glibc headers): the values and layouts that differ by
//! architecture. Runs natively on each architecture CI checks (`check`, `check-arm64`).

use proto::abi;
use std::mem::{offset_of, size_of};

#[test]
fn flags_are_the_targets() {
    assert_eq!(abi::open::O_DIRECTORY, libc::O_DIRECTORY as u64);
    assert_eq!(abi::open::O_NOFOLLOW, libc::O_NOFOLLOW as u64);
    assert_eq!(abi::open::O_DIRECT, libc::O_DIRECT as u64);
    #[cfg(target_arch = "x86_64")]
    assert_eq!(abi::MAP_32BIT, Some(libc::MAP_32BIT as u64));
    #[cfg(not(target_arch = "x86_64"))]
    assert_eq!(abi::MAP_32BIT, None);
    assert_eq!(abi::MINSIGSTKSZ, libc::MINSIGSTKSZ as u64);
    #[cfg(target_arch = "x86_64")]
    assert_eq!(abi::ELF_MACHINE, libc::EM_X86_64);
    #[cfg(target_arch = "aarch64")]
    assert_eq!(abi::ELF_MACHINE, libc::EM_AARCH64);
}

#[test]
fn epoll_event_layout() {
    assert_eq!(abi::epoll::SIZE as usize, size_of::<libc::epoll_event>());
    assert_eq!(
        abi::epoll::DATA as usize,
        offset_of!(libc::epoll_event, u64)
    );
    assert_eq!(offset_of!(libc::epoll_event, events), 0);
    assert_eq!(abi::epoll::PACKED, size_of::<libc::epoll_event>() == 12);
}

#[test]
fn stat_layout() {
    assert_eq!(abi::stat::SIZE as usize, size_of::<libc::stat>());
    let s = abi::stat::Stat::new(1, 2, 3, 0o100644, 1000, 1001, 4096, 77);
    let mut c: libc::stat = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            &s as *const _ as *const u8,
            &mut c as *mut _ as *mut u8,
            size_of::<libc::stat>(),
        );
    }
    assert_eq!((c.st_dev, c.st_ino, c.st_nlink as u64), (1, 2, 3));
    assert_eq!((c.st_mode, c.st_uid, c.st_gid), (0o100644, 1000, 1001));
    assert_eq!(c.st_blksize as u64, 4096);
    assert_eq!((c.st_atime, c.st_mtime, c.st_ctime), (77, 77, 77));
    c.st_size = 5;
    c.st_rdev = 6;
    let mut back = abi::stat::Stat::zeroed();
    unsafe {
        std::ptr::copy_nonoverlapping(
            &c as *const _ as *const u8,
            back.as_mut_ptr() as *mut u8,
            size_of::<libc::stat>(),
        );
        abi::stat::set_owner(back.as_mut_ptr() as *mut u8, 7, 8);
    }
    assert_eq!(
        (back.size(), back.rdev(), back.mode(), back.nlink()),
        (5, 6, 0o100644, 3)
    );
    assert_eq!((back.uid(), back.gid()), (7, 8));
}
