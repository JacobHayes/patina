//! Probe rows: the one question about a sandboxing facility that libraries
//! ask on startup to learn what the kernel offers. Each answers as the pinned
//! kernel does (`KERNEL_CONFIG`); any other call to the row, which would
//! build or install a sandbox, is a named fatal, since patina enforces
//! neither Landlock nor seccomp.

use crate::registry::KERNEL_CONFIG;
use linux_raw_sys::errno;

/// `LANDLOCK_CREATE_RULESET_VERSION`: the flag that asks for the ABI version.
const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1;

/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`: the
/// ABI version. Building a ruleset is not modeled.
pub(super) fn landlock_create_ruleset(args: [u64; 6]) -> i64 {
    let [attr, size, flags, ..] = args;
    if attr == 0 && size == 0 && flags == LANDLOCK_CREATE_RULESET_VERSION {
        return KERNEL_CONFIG.landlock_abi;
    }
    crate::trap_fatal(
        "landlock_create_ruleset: only the version query is modeled (patina does not enforce \
         Landlock); failing closed",
    )
}

const SECCOMP_SET_MODE_STRICT: u32 = 0;
const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
const SECCOMP_GET_NOTIF_SIZES: u32 = 3;
const SECCOMP_SET_MODE_FILTER_LISTENER: u32 = 4;

/// The actions 6.8's `seccomp_actions_avail` lists: kill process, kill
/// thread, trap, errno, user notification, trace, log, allow.
const ACTIONS: [u32; 8] = [
    0x8000_0000,
    0x0000_0000,
    0x0003_0000,
    0x0005_0000,
    0x7fc0_0000,
    0x7ff0_0000,
    0x7ffc_0000,
    0x7fff_0000,
];

/// `seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action)`: 0 for an action the
/// kernel knows (`EOPNOTSUPP` for any other, `EFAULT` for an unreadable
/// one, `EINVAL` for a flag). An operation the kernel does not have is
/// `EINVAL`; every other one would enter or inspect a mode and is not
/// modeled.
pub(super) fn seccomp(args: [u64; 6]) -> i64 {
    let operation = args[0] as u32;
    match operation {
        SECCOMP_GET_ACTION_AVAIL => {
            if args[1] as u32 != 0 {
                return -i64::from(errno::EINVAL);
            }
            match crate::uaccess::read::<u32>(args[2] as usize) {
                Err(_) => -i64::from(errno::EFAULT),
                Ok(action) if ACTIONS.contains(&action) => 0,
                Ok(_) => -i64::from(errno::EOPNOTSUPP),
            }
        }
        SECCOMP_SET_MODE_STRICT
        | SECCOMP_SET_MODE_FILTER
        | SECCOMP_GET_NOTIF_SIZES
        | SECCOMP_SET_MODE_FILTER_LISTENER => crate::trap_fatal(
            "seccomp: only SECCOMP_GET_ACTION_AVAIL is modeled (patina does not enforce a \
             guest's seccomp mode); failing closed",
        ),
        _ => -i64::from(errno::EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landlock_version_query_answers_the_pinned_abi() {
        let abi = landlock_create_ruleset([0, 0, LANDLOCK_CREATE_RULESET_VERSION, 0, 0, 0]);
        assert_eq!(abi, KERNEL_CONFIG.landlock_abi);
        assert!(abi > 0);
    }

    #[test]
    fn seccomp_action_availability_follows_the_known_actions() {
        let ask = |action: u32, flags: u64| {
            seccomp([
                u64::from(SECCOMP_GET_ACTION_AVAIL),
                flags,
                &action as *const u32 as u64,
                0,
                0,
                0,
            ])
        };
        for action in ACTIONS {
            assert_eq!(ask(action, 0), 0);
        }
        assert_eq!(ask(0x1234_0000, 0), -i64::from(errno::EOPNOTSUPP));
        assert_eq!(ask(ACTIONS[0], 1), -i64::from(errno::EINVAL));
        assert_eq!(seccomp([99, 0, 0, 0, 0, 0]), -i64::from(errno::EINVAL));
    }
}
