mod common;
use common::{invoke, invoke_unchecked, invoke_with, native_workspace};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use common::{invoke_in_with_env, invoke_with_deadline};

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tempfile::tempdir;

#[path = "end_to_end/audit.rs"]
mod audit;
#[path = "end_to_end/campaign_continuation.rs"]
mod campaign_continuation;
#[path = "end_to_end/campaign_fault_planes.rs"]
mod campaign_fault_planes;
#[path = "end_to_end/campaign_forwarding.rs"]
mod campaign_forwarding;
#[path = "end_to_end/campaign_guided.rs"]
mod campaign_guided;
#[path = "end_to_end/campaign_outcomes.rs"]
mod campaign_outcomes;
#[path = "end_to_end/campaign_verify.rs"]
mod campaign_verify;
#[path = "end_to_end/cargo_replay.rs"]
mod cargo_replay;
#[path = "end_to_end/crash_restart.rs"]
mod crash_restart;
#[path = "end_to_end/custom_ops.rs"]
mod custom_ops;
#[path = "end_to_end/help_flags.rs"]
mod help_flags;
#[path = "end_to_end/helpers.rs"]
mod helpers;
#[path = "end_to_end/instrumentation.rs"]
mod instrumentation;
#[path = "end_to_end/minimize.rs"]
mod minimize;
#[path = "end_to_end/native_build.rs"]
mod native_build;
#[path = "end_to_end/native_env.rs"]
mod native_env;
#[path = "end_to_end/native_faults.rs"]
mod native_faults;
#[path = "end_to_end/native_fds.rs"]
mod native_fds;
#[path = "end_to_end/native_fs.rs"]
mod native_fs;
#[path = "end_to_end/native_gate.rs"]
mod native_gate;
#[path = "end_to_end/native_harness.rs"]
mod native_harness;
#[path = "end_to_end/native_net.rs"]
mod native_net;
#[path = "end_to_end/native_platform.rs"]
mod native_platform;
#[path = "end_to_end/native_replay.rs"]
mod native_replay;
#[path = "end_to_end/native_scheduling.rs"]
mod native_scheduling;
#[path = "end_to_end/native_sdk.rs"]
mod native_sdk;
#[path = "end_to_end/output.rs"]
mod output;
#[path = "end_to_end/package_routing.rs"]
mod package_routing;
#[path = "end_to_end/prerun_and_watchdog.rs"]
mod prerun_and_watchdog;
#[path = "end_to_end/proptest.rs"]
mod proptest;
#[path = "end_to_end/run_facts.rs"]
mod run_facts;
#[path = "end_to_end/sdk_harness.rs"]
mod sdk_harness;
#[path = "end_to_end/toolchains.rs"]
mod toolchains;
#[path = "end_to_end/verdict.rs"]
mod verdict;

use helpers::*;

#[cfg(test)]
mod tests {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use super::assert_native_harness_prerun_refusal;

    /// Declared audit limit. Class pairing: the portable import-refusal detector
    /// below and HarnessSeedRun::trace's receipt-only provenance choke point.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn native_harness_audit_refusal_does_not_advertise_a_trace() {
        assert_native_harness_prerun_refusal(
            "text_metadata",
            "executable_metadata_is_not_executed",
            include_str!("../../../testbeds/native-boundary/text_metadata_probe.rs"),
            "undecodable-instruction",
        );
    }
}
