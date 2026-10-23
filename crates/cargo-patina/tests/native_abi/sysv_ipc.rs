//! glibc's System V IPC wrappers reach the run's own IPC namespace and never
//! the host's: the host holds a segment, a semaphore set and a message queue
//! under the key the guest uses, the guest sees none of them (and makes its
//! own), and every host object is exactly as it was after the guest's runs,
//! record and replay included.
use super::common::native::*;

/// One host object of each kind under `key`, removed on drop.
struct HostObjects {
    shm: i32,
    sem: i32,
    msq: i32,
}

const HOST_SEGMENT: usize = 8192;
const HOST_SEMS: i32 = 3;
const HOST_VALUE: i32 = 7;
const HOST_TEXT: &[u8; 4] = b"host";

#[repr(C)]
struct HostMessage {
    kind: libc::c_long,
    text: [u8; 4],
}

impl HostObjects {
    /// Create all three under a key no host object holds yet.
    fn create() -> (i32, HostObjects) {
        let exclusive = libc::IPC_CREAT | libc::IPC_EXCL | 0o600;
        let base = 0x5053_0000 | (std::process::id() as i32 & 0xffff);
        for key in (base..).take(64) {
            // SAFETY: plain host calls on objects this test owns.
            unsafe {
                let shm = libc::shmget(key, HOST_SEGMENT, exclusive);
                if shm < 0 {
                    continue;
                }
                let sem = libc::semget(key, HOST_SEMS, exclusive);
                let msq = libc::msgget(key, exclusive);
                let objects = HostObjects { shm, sem, msq };
                if sem < 0 || msq < 0 {
                    continue;
                }
                let view = libc::shmat(shm, std::ptr::null(), 0);
                assert_ne!(view as isize, -1);
                view.cast::<[u8; 4]>().write(*HOST_TEXT);
                assert_eq!(libc::shmdt(view), 0);
                assert_eq!(libc::semctl(sem, 0, libc::SETVAL, HOST_VALUE), 0);
                let message = HostMessage {
                    kind: 9,
                    text: *HOST_TEXT,
                };
                assert_eq!(libc::msgsnd(msq, (&raw const message).cast(), 4, 0), 0);
                return (key, objects);
            }
        }
        panic!("no free host IPC key near {base:#x}");
    }

    /// Every object still answers to `key` with the contents it was given.
    fn assert_untouched(&self, key: i32) {
        // SAFETY: plain host calls on objects this test owns.
        unsafe {
            assert_eq!(libc::shmget(key, 0, 0), self.shm);
            assert_eq!(libc::semget(key, 0, 0), self.sem);
            assert_eq!(libc::msgget(key, 0), self.msq);
            let mut shm: libc::shmid_ds = std::mem::zeroed();
            assert_eq!(libc::shmctl(self.shm, libc::IPC_STAT, &mut shm), 0);
            assert_eq!(shm.shm_segsz, HOST_SEGMENT);
            assert_eq!(shm.shm_nattch, 0);
            let view = libc::shmat(self.shm, std::ptr::null(), libc::SHM_RDONLY);
            assert_ne!(view as isize, -1);
            assert_eq!(view.cast::<[u8; 4]>().read(), *HOST_TEXT);
            assert_eq!(libc::shmdt(view), 0);
            let mut sem: libc::semid_ds = std::mem::zeroed();
            assert_eq!(libc::semctl(self.sem, 0, libc::IPC_STAT, &mut sem), 0);
            assert_eq!(sem.sem_nsems as i32, HOST_SEMS);
            assert_eq!(libc::semctl(self.sem, 0, libc::GETVAL), HOST_VALUE);
            let mut msq: libc::msqid_ds = std::mem::zeroed();
            assert_eq!(libc::msgctl(self.msq, libc::IPC_STAT, &mut msq), 0);
            assert_eq!(msq.msg_qnum, 1);
        }
    }
}

impl Drop for HostObjects {
    fn drop(&mut self) {
        // SAFETY: removal of objects this test created; a failed creation is -1.
        unsafe {
            if self.shm >= 0 {
                libc::shmctl(self.shm, libc::IPC_RMID, std::ptr::null_mut());
            }
            if self.sem >= 0 {
                libc::semctl(self.sem, 0, libc::IPC_RMID);
            }
            if self.msq >= 0 {
                libc::msgctl(self.msq, libc::IPC_RMID, std::ptr::null_mut());
            }
        }
    }
}

#[test]
fn libc_sysv_ipc_stays_in_the_run_namespace_and_replays() {
    let g = Guest::assert_build("sysv_ipc_probe.rs");
    g.assert_audit_clean();
    let (key, host) = HostObjects::create();
    let env = format!("PATINA_SYSV_KEY={key}");
    let flags = ["--env", env.as_str()];
    let stdout = g.assert_run_success(1, &flags).stdout;
    assert_eq!(
        text(&stdout),
        "NATIVE_SYSV_IPC_RESULT hidden=3 woke=2 refused=2\n"
    );
    host.assert_untouched(key);
}
