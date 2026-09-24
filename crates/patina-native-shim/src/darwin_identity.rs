//! The virtual Darwin kernel's self-description: what `uname(3)` answers on
//! macOS, the Darwin counterpart of `identity::uname`.
//!
//! `Darwin`, the run's node name (`--hostname`, the same recorded run fact
//! the Linux model reports), the modeled kernel release
//! [`DARWIN_RELEASE`](crate::registry::DARWIN_RELEASE) with a version naming
//! it and its xnu build, and the machine (`arm64` or `x86_64`). Every field is
//! a model constant or run configuration, never the host's `kern.*` sysctls,
//! so the same seed reads the same bytes on any Mac.

/// Darwin's `_SYS_NAMELEN`: every `struct utsname` field is 256 bytes.
const UTS_LEN: usize = 256;

/// Darwin's `struct utsname`: sysname, nodename, release, version, machine
/// (no NIS domain name).
#[repr(C)]
pub(crate) struct Utsname {
    fields: [[u8; UTS_LEN]; 5],
}

/// The Darwin machine name of the build's architecture.
const MACHINE: &str = if cfg!(target_arch = "x86_64") {
    "x86_64"
} else {
    "arm64"
};

/// The kernel configuration a Darwin version string ends with.
const KERNEL_CONFIG: &str = if cfg!(target_arch = "x86_64") {
    "RELEASE_X86_64"
} else {
    "RELEASE_ARM64"
};

/// The virtual Darwin kernel's `struct utsname` for a machine named
/// `nodename`. A value longer than a field is cut to leave its NUL.
pub(crate) fn describe(nodename: &str) -> Utsname {
    let release = crate::registry::DARWIN_RELEASE;
    let version = format!(
        "Darwin Kernel Version {release}: patina; root:{}/{KERNEL_CONFIG}",
        crate::registry::DARWIN_XNU
    );
    let values = ["Darwin", nodename, release, version.as_str(), MACHINE];
    let mut name = Utsname {
        fields: [[0; UTS_LEN]; 5],
    };
    for (field, value) in name.fields.iter_mut().zip(values) {
        let bytes = &value.as_bytes()[..value.len().min(UTS_LEN - 1)];
        field[..bytes.len()].copy_from_slice(bytes);
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn field(name: &Utsname, index: usize) -> &str {
        CStr::from_bytes_until_nul(&name.fields[index])
            .expect("a NUL-terminated field")
            .to_str()
            .expect("UTF-8")
    }

    #[test]
    fn darwin_uname_reports_the_modeled_kernel_and_the_run_node_name() {
        let name = describe("db-1.internal");
        let [sysname, nodename, release, version, machine] =
            [0, 1, 2, 3, 4].map(|index| field(&name, index));
        assert_eq!(sysname, "Darwin");
        assert_eq!(nodename, "db-1.internal");
        assert_eq!(release, crate::registry::DARWIN_RELEASE);
        assert!(
            crate::registry::parse_release(release).is_some(),
            "{release}"
        );
        // The version names the release it describes and its xnu build.
        assert!(version.contains(release), "{version}");
        assert!(version.contains(crate::registry::DARWIN_XNU), "{version}");
        let expected_machine = if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else {
            "arm64"
        };
        assert_eq!(machine, expected_machine);
        // The same node name yields the same bytes.
        assert!(describe("db-1.internal").fields == name.fields);
    }

    #[test]
    fn an_oversized_node_name_keeps_its_nul() {
        let long = "n".repeat(UTS_LEN + 10);
        let name = describe(&long);
        assert_eq!(field(&name, 1), &long[..UTS_LEN - 1]);
        assert_eq!(field(&name, 0), "Darwin");
    }

    /// The model's layout is the platform's own `struct utsname`, and its
    /// release is the Darwin the vendored xnu tables come from.
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_utsname_matches_the_platform_and_the_vendored_xnu() {
        assert_eq!(
            std::mem::size_of::<Utsname>(),
            std::mem::size_of::<libc::utsname>()
        );
        let vendored: std::collections::BTreeSet<&str> = crate::registry::generated::SOURCES
            .iter()
            .filter(|source| source.0 == "darwin")
            .map(|source| source.1)
            .collect();
        assert_eq!(
            vendored,
            std::collections::BTreeSet::from([crate::registry::DARWIN_XNU])
        );
    }
}
