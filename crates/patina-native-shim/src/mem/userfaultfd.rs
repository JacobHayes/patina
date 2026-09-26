//! userfaultfd descriptors (fs/userfaultfd.c): the descriptor a caller gets
//! from `userfaultfd(2)` and the `UFFDIO_API` handshake, as the pinned 6.8
//! answers them. A descriptor is a descriptor-table kind
//! ([`FdKind::Userfaultfd`]): 6.8's anonymous `[userfaultfd]` inode, opened
//! read-only with the caller's `O_CLOEXEC`/`O_NONBLOCK`; its handle keys
//! [`CONTEXTS`], which holds the features the handshake enabled (0 until
//! then, as the kernel's `ctx->features`).
//!
//! Nothing is ever registered: `UFFDIO_REGISTER` and the range ioctls
//! (`WAKE`, `COPY`, `ZEROPAGE`, `MOVE`, `WRITEPROTECT`, `CONTINUE`, `POISON`)
//! stop the run by name, so no fault or event can ever be pending. That
//! makes every other answer exact: a read (its buffer judged first, as
//! `vfs_read` does: `EFAULT`) before the handshake is `EINVAL`,
//! after it `EAGAIN` without blocking (and a blocking one, which would wait
//! for a fault nothing can raise until a signal comes, stops by name); poll
//! is `EPOLLERR` until the handshake and for a blocking descriptor, else no
//! event.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::registry::Capability;
use crate::{EINVAL, SpinMutex, uaccess};
use linux_raw_sys::errno;

/// The enabled features of each open descriptor's context, by handle; 0
/// until `UFFDIO_API`. A description's handle leaves with its last number
/// ([`released`]).
static CONTEXTS: SpinMutex<BTreeMap<u64, u32>> = SpinMutex::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

/// `UFFD_API`: the one protocol version.
const UFFD_API: u64 = 0xaa;
/// `sizeof(struct uffd_msg)`: a read takes whole messages.
const MESSAGE: usize = 32;
/// `UFFD_FEATURE_EVENT_FORK`, which needs `CAP_SYS_PTRACE`.
const UFFD_FEATURE_EVENT_FORK: u64 = 1 << 1;
/// `UFFD_FEATURE_WP_UNPOPULATED` and `UFFD_FEATURE_WP_ASYNC`, which implies
/// it.
const UFFD_FEATURE_WP_UNPOPULATED: u64 = 1 << 13;
const UFFD_FEATURE_WP_ASYNC: u64 = 1 << 15;
/// `UFFD_API_FEATURES`: every feature 6.8 knows (bits 0 to 16), what a
/// request may ask for.
const UFFD_API_FEATURES: u64 = 0x1_ffff;
/// What the handshake reports: `UFFD_API_FEATURES` less what the build
/// masks. x86_64 has write-protect (`HAVE_ARCH_USERFAULTFD_WP`,
/// `PTE_MARKER_UFFD_WP`) and minor faults, so nothing is masked (6.8.0-139
/// reports `0x1ffff` live); 6.8's arm64 selects minor faults but not
/// write-protect, so `PAGEFAULT_FLAG_WP`, `WP_HUGETLBFS_SHMEM`,
/// `WP_UNPOPULATED` and `WP_ASYNC` are masked (derived from arch/arm64's
/// Kconfig, not yet read live on an arm64 6.8).
#[cfg(target_arch = "x86_64")]
const REPORTED_FEATURES: u64 = UFFD_API_FEATURES;
#[cfg(target_arch = "aarch64")]
const REPORTED_FEATURES: u64 = UFFD_API_FEATURES & !(1 | 1 << 12 | 1 << 13 | 1 << 15);
/// `UFFD_FEATURE_INITIALIZED`: set in a context's features by the
/// handshake, whatever was asked.
const UFFD_FEATURE_INITIALIZED: u32 = 1 << 31;
/// `UFFD_API_IOCTLS`: `_UFFDIO_REGISTER`, `_UFFDIO_UNREGISTER`,
/// `_UFFDIO_API`.
const UFFD_API_IOCTLS: u64 = 1 << 0 | 1 << 1 | 1 << 63;

/// `UFFDIO_API`: `_IOWR(0xAA, 0x3F, struct uffdio_api)`.
pub(crate) const UFFDIO_API: u64 = 0xc018_aa3f;
/// The requests that act on a registered range (include/uapi/linux/
/// userfaultfd.h: `_IOWR`/`_IOR` of type 0xAA, the `_UFFDIO_*` number and
/// the argument's size).
const RANGE_REQUESTS: [(u64, &str); 9] = [
    (0xc020_aa00, "UFFDIO_REGISTER"),
    (0x8010_aa01, "UFFDIO_UNREGISTER"),
    (0x8010_aa02, "UFFDIO_WAKE"),
    (0xc028_aa03, "UFFDIO_COPY"),
    (0xc020_aa04, "UFFDIO_ZEROPAGE"),
    (0xc028_aa05, "UFFDIO_MOVE"),
    (0xc018_aa06, "UFFDIO_WRITEPROTECT"),
    (0xc020_aa07, "UFFDIO_CONTINUE"),
    (0xc020_aa08, "UFFDIO_POISON"),
];

/// `struct uffdio_api`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Api {
    api: u64,
    features: u64,
    ioctls: u64,
}

/// A new context, its features not yet enabled: the handle a new
/// descriptor's description takes.
pub(crate) fn created() -> u64 {
    let handle = NEXT.fetch_add(1, Ordering::Relaxed);
    CONTEXTS.lock().insert(handle, 0);
    handle
}

/// The context's last description is gone (`userfaultfd_release`).
pub(crate) fn released(handle: u64) {
    CONTEXTS.lock().remove(&handle);
}

fn features(handle: u64) -> u32 {
    CONTEXTS.lock().get(&handle).copied().unwrap_or(0)
}

/// `userfaultfd_poll`: `EPOLLERR` before the handshake and for a blocking
/// descriptor; otherwise no event, none ever being pending.
pub(crate) fn poll(handle: u64, nonblocking: bool) -> u32 {
    const EPOLLERR: u32 = 0x8;
    if features(handle) == 0 || !nonblocking {
        EPOLLERR
    } else {
        0
    }
}

/// `userfaultfd_read`: `EINVAL` before the handshake, then for room short
/// of one message; `EAGAIN` for a nonblocking read, nothing being pending.
/// A blocking one would wait for a fault nothing can raise: a named stop.
pub(crate) fn read(handle: u64, nonblocking: bool, length: usize) -> Result<usize, i32> {
    if features(handle) == 0 || length < MESSAGE {
        return Err(EINVAL);
    }
    if nonblocking {
        return Err(errno::EAGAIN as i32);
    }
    crate::trap_fatal(
        "read: a blocking read of a userfaultfd descriptor waits for a fault, and nothing \
         registered can raise one (registration is not modeled); failing closed",
    )
}

/// `userfaultfd_ioctl`, past the generic requests: before the handshake
/// anything but `UFFDIO_API` is `EINVAL`; the handshake; a range request
/// stops by name; anything else is `EINVAL`.
pub(crate) fn ioctl(handle: u64, request: u64, arg: usize) -> Result<i32, i32> {
    if request == UFFDIO_API {
        return api(handle, arg);
    }
    if features(handle) == 0 {
        return Err(EINVAL);
    }
    match RANGE_REQUESTS.iter().find(|(number, _)| *number == request) {
        Some((_, name)) => crate::trap_fatal(&format!(
            "ioctl: {name} on a userfaultfd descriptor is not modeled (registering and \
             resolving faults); failing closed"
        )),
        None => Err(EINVAL),
    }
}

/// `userfaultfd_api`: the request's copy (`EFAULT`); an unknown api or
/// feature `EINVAL`, `EVENT_FORK` without `CAP_SYS_PTRACE` `EPERM` (both
/// zeroing the caller's structure); the reported features and ioctls copied
/// out (`EFAULT`); then a context already initialized is `EINVAL` (its
/// structure zeroed too), else it takes the features asked for.
fn api(handle: u64, arg: usize) -> Result<i32, i32> {
    let Ok(request) = uaccess::read::<Api>(arg) else {
        return Err(errno::EFAULT as i32);
    };
    let mut asked = request.features;
    let refusal = if request.api != UFFD_API || asked & !UFFD_API_FEATURES != 0 {
        Some(errno::EINVAL)
    } else if asked & UFFD_FEATURE_EVENT_FORK != 0
        && !crate::identity::credential().capable(Capability::SysPtrace)
    {
        Some(errno::EPERM)
    } else {
        None
    };
    let zeroed = |code: u32| match uaccess::write(arg, &Api::default()) {
        Ok(()) => Err(code as i32),
        Err(_) => Err(errno::EFAULT as i32),
    };
    if let Some(code) = refusal {
        return zeroed(code);
    }
    if asked & UFFD_FEATURE_WP_ASYNC != 0 {
        asked |= UFFD_FEATURE_WP_UNPOPULATED;
    }
    let reported = Api {
        api: request.api,
        features: REPORTED_FEATURES,
        ioctls: UFFD_API_IOCTLS,
    };
    if uaccess::write(arg, &reported).is_err() {
        return Err(errno::EFAULT as i32);
    }
    let mut contexts = CONTEXTS.lock();
    match contexts.get_mut(&handle) {
        Some(features) if *features == 0 => {
            *features = asked as u32 | UFFD_FEATURE_INITIALIZED;
            Ok(0)
        }
        _ => {
            drop(contexts);
            zeroed(errno::EINVAL)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(handle: u64, features: u64) -> (Result<i32, i32>, Api) {
        let mut api = Api {
            api: UFFD_API,
            features,
            ioctls: 0,
        };
        let answer = ioctl(handle, UFFDIO_API, &mut api as *mut Api as usize);
        (answer, api)
    }

    #[test]
    fn the_handshake_answers_once() {
        let handle = created();
        assert_eq!(read(handle, true, MESSAGE), Err(EINVAL));
        assert_eq!(poll(handle, true), 0x8);
        // Before the handshake every other request is EINVAL.
        assert_eq!(ioctl(handle, 0x541B, 0), Err(EINVAL));
        let (answer, api) = handshake(handle, 0);
        assert_eq!(answer, Ok(0));
        assert_eq!(
            (api.api, api.features, api.ioctls),
            (UFFD_API, REPORTED_FEATURES, UFFD_API_IOCTLS)
        );
        assert_eq!(read(handle, true, MESSAGE), Err(errno::EAGAIN as i32));
        assert_eq!(read(handle, true, MESSAGE - 1), Err(EINVAL));
        assert_eq!(poll(handle, true), 0);
        assert_eq!(poll(handle, false), 0x8);
        // A second handshake reports, then refuses and zeroes.
        let (answer, api) = handshake(handle, 0);
        assert_eq!(answer, Err(EINVAL));
        assert_eq!((api.api, api.features, api.ioctls), (0, 0, 0));
        // An unknown request after the handshake is EINVAL too.
        assert_eq!(ioctl(handle, 0x541B, 0), Err(EINVAL));
        released(handle);
    }

    #[test]
    fn the_handshake_refuses_in_the_kernels_order() {
        let handle = created();
        let mut api = Api {
            api: 0xab,
            features: 0,
            ioctls: 7,
        };
        let at = &mut api as *mut Api as usize;
        assert_eq!(ioctl(handle, UFFDIO_API, at), Err(EINVAL));
        assert_eq!((api.api, api.ioctls), (0, 0));
        let (answer, _) = handshake(handle, 1 << 17);
        assert_eq!(answer, Err(EINVAL));
        let (answer, api) = handshake(handle, UFFD_FEATURE_EVENT_FORK);
        assert_eq!(answer, Err(errno::EPERM as i32));
        assert_eq!(api.features, 0);
        assert_eq!(ioctl(handle, UFFDIO_API, 0), Err(errno::EFAULT as i32));
        // None of those initialized the context.
        assert_eq!(handshake(handle, 1 << 7).0, Ok(0));
        assert_eq!(features(handle), 1 << 7 | UFFD_FEATURE_INITIALIZED);
        released(handle);
        // WP_ASYNC implies WP_UNPOPULATED.
        let handle = created();
        assert_eq!(handshake(handle, UFFD_FEATURE_WP_ASYNC).0, Ok(0));
        assert_eq!(
            u64::from(features(handle)),
            UFFD_FEATURE_WP_ASYNC
                | UFFD_FEATURE_WP_UNPOPULATED
                | u64::from(UFFD_FEATURE_INITIALIZED)
        );
        released(handle);
    }
}
