use std::arch::asm;
unsafe fn sc(nr: i64, a0: i64, a1: i64, a2: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", inlateout("rax") nr => r, in("rdi") a0, in("rsi") a1,
        in("rdx") a2, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: u16,
    addr: u32,
    zero: [u8; 8],
}
#[repr(C)]
struct Iovec {
    base: *mut u8,
    len: usize,
}
#[repr(C)]
struct Msghdr {
    name: *mut u8,
    namelen: u32,
    _pad0: u32,
    iov: *mut Iovec,
    iovlen: u64,
    control: *mut u8,
    controllen: u64,
    flags: i32,
    _pad1: u32,
}
fn main() {
    let sock = unsafe { sc(41, 2, 2, 0) }; // socket(AF_INET, SOCK_DGRAM, 0)
    assert!(sock >= 0, "socket {sock}");
    let mut sa = SockaddrIn {
        family: 2,
        port: 34569u16.to_be(),
        addr: 0x7f000001u32.to_be(),
        zero: [0; 8],
    };
    let b = unsafe {
        sc(
            49,
            sock,
            &mut sa as *mut SockaddrIn as i64,
            core::mem::size_of::<SockaddrIn>() as i64,
        )
    };
    assert_eq!(b, 0, "bind {b}");
    // A TWO-iovec datagram: a fragmenting implementation would send two
    // datagrams; the correct (interposer-mirroring) row refuses with ENOSYS.
    let a = *b"frag-";
    let c = *b"ment";
    let (mut abuf, mut cbuf) = (a, c);
    let mut iov = [
        Iovec {
            base: abuf.as_mut_ptr(),
            len: abuf.len(),
        },
        Iovec {
            base: cbuf.as_mut_ptr(),
            len: cbuf.len(),
        },
    ];
    let msg = Msghdr {
        name: &mut sa as *mut SockaddrIn as *mut u8,
        namelen: core::mem::size_of::<SockaddrIn>() as u32,
        _pad0: 0,
        iov: iov.as_mut_ptr(),
        iovlen: 2,
        control: core::ptr::null_mut(),
        controllen: 0,
        flags: 0,
        _pad1: 0,
    };
    let sent = unsafe { sc(46, sock, &msg as *const Msghdr as i64, 0) }; // sendmsg
    assert_eq!(
        sent, -38,
        "sendmsg must mirror the interposer ENOSYS, got {sent}"
    );
    let mut recv_buf = [0u8; 32];
    let mut riov = Iovec {
        base: recv_buf.as_mut_ptr(),
        len: recv_buf.len(),
    };
    let mut rmsg = Msghdr {
        name: core::ptr::null_mut(),
        namelen: 0,
        _pad0: 0,
        iov: &mut riov as *mut Iovec,
        iovlen: 1,
        control: core::ptr::null_mut(),
        controllen: 0,
        flags: 0,
        _pad1: 0,
    };
    let got = unsafe { sc(47, sock, &mut rmsg as *mut Msghdr as i64, 0) }; // recvmsg
    assert_eq!(
        got, -38,
        "recvmsg must mirror the interposer ENOSYS, got {got}"
    );
    println!("RAW_MSG sendmsg={sent} recvmsg={got}");
}
