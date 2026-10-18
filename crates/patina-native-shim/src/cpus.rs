//! The virtual machine's CPU count (`--cpus`, a recorded run fact): the one
//! value every guest-visible CPU surface answers from, on both platforms. On
//! Linux the affinity masks, `getcpu`, glibc's `sched_getcpu`, the rseq area and
//! `rdtscp`'s `TSC_AUX` (`thread::sched`); on both, `sysconf`'s
//! `_SC_NPROCESSORS_ONLN`/`_CONF`; on Darwin, `hw.ncpu`, `hw.activecpu`,
//! `hw.logicalcpu`, `hw.physicalcpu` (and their `_max`) and
//! `host_processor_info`.
//!
//! The count is the control plane's [`ENV_GUEST_CPUS`] (default
//! [`DEFAULT_CPUS`]), read the first time anything asks. That may be before
//! Patina's startup constructor has captured the control plane or installed
//! the runtime: glibc, a library constructor or a harness's test runner sizes
//! itself from the count during startup, and the answer must not depend on
//! when the runtime arrives. So the count is read from the host environment
//! the capture snapshots ([`crate::posix_env::control_value`]), never through
//! the guest's (still empty) environment. The read takes no lock and makes no
//! allocation, so an allocator may ask too. The installed runtime's count (the
//! configured one, or on replay the trace's) must then be the same, or the run
//! is refused by name ([`confirm`]): the native supervisor forwards the trace's
//! count to a replay, so only a hand-launched replay without it can disagree.
//! The scheduler is unaffected: tasks still run one at a time.

use patina_dst_abi::{DEFAULT_CPUS, MAX_CPUS};
use patina_dst_runtime::ENV_GUEST_CPUS;
use std::sync::atomic::{AtomicU32, Ordering};

/// The count, 0 until first read.
static COUNT: AtomicU32 = AtomicU32::new(0);

/// The virtual machine's CPU count, 1 to [`MAX_CPUS`].
pub(crate) fn count() -> u32 {
    match COUNT.load(Ordering::Acquire) {
        0 => {
            // Racing first readers read the same control plane.
            let cpus = boot();
            COUNT.store(cpus, Ordering::Release);
            cpus
        }
        cpus => cpus,
    }
}

/// The control plane's count. A value the runtime refuses answers the default
/// here; the runtime's configuration refuses the run before the guest starts.
fn boot() -> u32 {
    // The guest archive's control plane; the runner's rlib (no startup
    // constructor, no interposed environment) reads the runtime's.
    #[cfg(patina_posix_exports)]
    let cpus = crate::posix_env::control_value(ENV_GUEST_CPUS).and_then(|value| value.parse().ok());
    #[cfg(not(patina_posix_exports))]
    let cpus = crate::control_env(ENV_GUEST_CPUS).and_then(|value| value.parse().ok());
    cpus.filter(|cpus| (1..=MAX_CPUS).contains(cpus))
        .unwrap_or(DEFAULT_CPUS)
}

/// Check the installed runtime's count against the one the process answers.
pub(crate) fn confirm(installed: u32) -> Result<(), String> {
    let booted = count();
    if installed == booted {
        return Ok(());
    }
    Err(format!(
        "the run's virtual machine has {installed} CPUs, but this process started with \
         {booted} ({ENV_GUEST_CPUS}); a replay needs the trace's count, which `cargo patina \
         replay` supplies: set {ENV_GUEST_CPUS}={installed} when launching the guest directly"
    ))
}
