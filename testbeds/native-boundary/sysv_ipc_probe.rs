//! System V IPC through glibc's wrappers (`shmget`, `semop`, `msgrcv`, ...),
//! never `syscall(2)`. `PATINA_SYSV_KEY` names a key the host already holds
//! a segment, a semaphore set and a message queue under: the run's IPC
//! namespace is its own, so none of them is visible here, and every object
//! this run makes under the key is new. A semaphore wait and a message
//! receive each block until the main thread makes them possible, and the
//! namespace-table queries refuse by name (`ENOSYS`).
use std::ffi::{c_int, c_long, c_void};

const IPC_CREAT: c_int = 0o1000;
const IPC_EXCL: c_int = 0o2000;
const IPC_NOWAIT: c_int = 0o4000;
const IPC_RMID: c_int = 0;
const IPC_STAT: c_int = 2;
const IPC_INFO: c_int = 3;
const GETVAL: c_int = 12;
const ENOENT: i32 = 2;
const ENOSYS: i32 = 38;
const ENOMSG: i32 = 42;

#[repr(C)]
struct Sembuf {
    num: u16,
    op: i16,
    flg: i16,
}

#[repr(C)]
struct Message {
    kind: c_long,
    text: [u8; 8],
}

unsafe extern "C" {
    fn shmget(key: c_int, size: usize, flags: c_int) -> c_int;
    fn shmat(id: c_int, address: *const c_void, flags: c_int) -> *mut c_void;
    fn shmdt(address: *const c_void) -> c_int;
    fn shmctl(id: c_int, cmd: c_int, buf: *mut c_void) -> c_int;
    fn semget(key: c_int, count: c_int, flags: c_int) -> c_int;
    fn semop(id: c_int, ops: *mut Sembuf, count: usize) -> c_int;
    fn semctl(id: c_int, num: c_int, cmd: c_int, ...) -> c_int;
    fn msgget(key: c_int, flags: c_int) -> c_int;
    fn msgsnd(id: c_int, message: *const c_void, size: usize, flags: c_int) -> c_int;
    fn msgrcv(id: c_int, message: *mut c_void, size: usize, kind: c_long, flags: c_int) -> isize;
    fn msgctl(id: c_int, cmd: c_int, buf: *mut c_void) -> c_int;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    unsafe { *__errno_location() }
}

fn failed_with(result: isize, expected: i32) -> bool {
    result == -1 && errno() == expected
}

fn main() {
    let key: c_int = std::env::var("PATINA_SYSV_KEY")
        .expect("PATINA_SYSV_KEY")
        .parse()
        .expect("a decimal key");
    let exclusive = IPC_CREAT | IPC_EXCL | 0o600;

    // The host's objects under the key are not this run's.
    assert!(failed_with(unsafe { shmget(key, 0, 0) } as isize, ENOENT));
    assert!(failed_with(unsafe { semget(key, 0, 0) } as isize, ENOENT));
    assert!(failed_with(unsafe { msgget(key, 0) } as isize, ENOENT));

    // Shared memory: a fresh page-sized segment, attached and written.
    let shm = unsafe { shmget(key, 4096, exclusive) };
    assert!(shm >= 0, "shmget {}", errno());
    let view = unsafe { shmat(shm, std::ptr::null(), 0) };
    assert_ne!(view as isize, -1, "shmat {}", errno());
    unsafe { view.cast::<[u8; 5]>().write(*b"guest") };
    let mut stat = [0u64; 16];
    assert_eq!(unsafe { shmctl(shm, IPC_STAT, stat.as_mut_ptr().cast()) }, 0);
    // `shm_segsz` follows the 48-byte `ipc_perm`.
    assert_eq!(stat[6], 4096);
    assert_eq!(unsafe { shmdt(view) }, 0);
    assert_eq!(unsafe { shmctl(shm, IPC_RMID, std::ptr::null_mut()) }, 0);

    // Semaphores: a waiter blocks until the main thread posts.
    let sem = unsafe { semget(key, 1, exclusive) };
    assert!(sem >= 0, "semget {}", errno());
    assert_eq!(unsafe { semctl(sem, 0, GETVAL) }, 0);
    let waiter = std::thread::spawn(move || {
        let mut take = Sembuf { num: 0, op: -1, flg: 0 };
        unsafe { semop(sem, &mut take, 1) }
    });
    std::thread::sleep(std::time::Duration::from_millis(10));
    let mut post = Sembuf { num: 0, op: 1, flg: 0 };
    assert_eq!(unsafe { semop(sem, &mut post, 1) }, 0);
    assert_eq!(waiter.join().unwrap(), 0);
    assert_eq!(unsafe { semctl(sem, 0, GETVAL) }, 0);
    let mut table = [0u64; 16];
    assert!(failed_with(
        unsafe { semctl(sem, 0, IPC_INFO, table.as_mut_ptr()) } as isize,
        ENOSYS
    ));

    // Message queues: an empty queue, then a receiver woken by a send.
    let msq = unsafe { msgget(key, exclusive) };
    assert!(msq >= 0, "msgget {}", errno());
    let mut message = Message { kind: 0, text: [0; 8] };
    let empty = unsafe { msgrcv(msq, (&raw mut message).cast(), 8, 0, IPC_NOWAIT) };
    assert!(failed_with(empty, ENOMSG));
    let receiver = std::thread::spawn(move || {
        let mut message = Message { kind: 0, text: [0; 8] };
        let size = unsafe { msgrcv(msq, (&raw mut message).cast(), 8, 0, 0) };
        (size, message.kind, message.text)
    });
    std::thread::sleep(std::time::Duration::from_millis(10));
    let ping = Message { kind: 5, text: *b"ping\0\0\0\0" };
    assert_eq!(unsafe { msgsnd(msq, (&raw const ping).cast(), 4, 0) }, 0);
    assert_eq!(receiver.join().unwrap(), (4, 5, *b"ping\0\0\0\0"));
    assert!(failed_with(
        unsafe { msgctl(msq, IPC_INFO, table.as_mut_ptr().cast()) } as isize,
        ENOSYS
    ));

    assert_eq!(unsafe { semctl(sem, 0, IPC_RMID) }, 0);
    assert_eq!(unsafe { msgctl(msq, IPC_RMID, std::ptr::null_mut()) }, 0);
    println!("NATIVE_SYSV_IPC_RESULT hidden=3 woke=2 refused=2");
}
