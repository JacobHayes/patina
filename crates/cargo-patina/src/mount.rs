//! `--mount HOST_DIR[:GUEST_DIR]`: a host directory captured read-only into
//! the guest filesystem at a guest directory, `/` unless one is named.

use crate::CliError;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// One `--mount`: the host directory captured, and the guest directory its
/// contents appear under. The guest directory is absolute and normal (no `.`,
/// `..`, empty or trailing components), so one location has one spelling and
/// the corpus hash, which carries every captured entry's guest path, names it
/// exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Mount {
    pub(crate) host: PathBuf,
    pub(crate) guest: String,
}

impl Mount {
    /// Read `--mount`'s value. `HOST_DIR:GUEST_DIR` when the text after the
    /// last `:` is an absolute path; otherwise the whole value is the host
    /// directory, mounted at `/`.
    pub(crate) fn parse(value: &OsStr) -> Result<Self, CliError> {
        let bytes = value.as_bytes();
        let split = bytes
            .iter()
            .rposition(|byte| *byte == b':')
            .filter(|at| bytes.get(at + 1) == Some(&b'/'));
        let Some(at) = split else {
            return Ok(Mount {
                host: PathBuf::from(value),
                guest: "/".into(),
            });
        };
        let host = &bytes[..at];
        if host.is_empty() {
            return Err(CliError::usage(
                "--mount HOST_DIR:GUEST_DIR names no host directory",
            ));
        }
        let guest = std::str::from_utf8(&bytes[at + 1..])
            .map_err(|_| CliError::usage("--mount's guest directory must be UTF-8"))?;
        let normal = guest == "/"
            || guest[1..]
                .split('/')
                .all(|part| !matches!(part, "" | "." | ".."));
        if !normal {
            return Err(CliError::usage(format!(
                "--mount's guest directory {guest:?} must be absolute, without `.`, `..`, \
                 repeated or trailing slashes"
            )));
        }
        Ok(Mount {
            host: PathBuf::from(OsString::from_vec(host.to_vec())),
            guest: guest.to_owned(),
        })
    }

    /// The flag's value again: the bare host directory for a mount at `/`
    /// (the form every existing command line and campaign uses), else
    /// `HOST_DIR:GUEST_DIR`.
    pub(crate) fn to_arg(&self) -> OsString {
        let mut arg = self.host.clone().into_os_string();
        if self.guest != "/" {
            arg.push(":");
            arg.push(&self.guest);
        }
        arg
    }

    /// The guest path an entry at `relative` (under the host directory) has:
    /// `""` is the mount point itself.
    pub(crate) fn guest_prefix(&self) -> &str {
        if self.guest == "/" { "" } else { &self.guest }
    }

    /// Where on the host the guest path `guest_path` is captured from, when
    /// it lies under this mount.
    pub(crate) fn host_path_of(&self, guest_path: &str) -> Option<PathBuf> {
        let rest = guest_path.strip_prefix(self.guest_prefix())?;
        if !(rest.is_empty() || rest.starts_with('/')) {
            return None;
        }
        let rest = rest.trim_start_matches('/');
        Some(if rest.is_empty() {
            self.host.clone()
        } else {
            self.host.join(rest)
        })
    }

    /// The same mount with its host directory made absolute and canonical, so
    /// a command naming it works from any directory.
    pub(crate) fn canonical(&self) -> Result<Self, CliError> {
        let host = std::fs::canonicalize(&self.host).map_err(|error| {
            CliError(format!(
                "failed to resolve --mount directory {}: {error}",
                self.host.display()
            ))
        })?;
        Ok(Mount {
            host,
            guest: self.guest.clone(),
        })
    }
}

/// The host directory and guest directory of a mount, for messages.
impl std::fmt::Display for Mount {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", Path::new(&self.to_arg()).display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Mount, CliError> {
        Mount::parse(OsStr::new(text))
    }

    #[test]
    fn a_bare_directory_mounts_at_the_root_and_round_trips() {
        for text in ["corpus", "/abs/dir", "with:colon", "trailing:"] {
            let mount = parse(text).unwrap();
            assert_eq!(mount.host, PathBuf::from(text));
            assert_eq!(mount.guest, "/");
            assert_eq!(mount.to_arg(), OsString::from(text));
        }
    }

    #[test]
    fn a_guest_directory_is_split_off_and_round_trips() {
        let mount = parse("fixtures:/data/in").unwrap();
        assert_eq!(mount.host, PathBuf::from("fixtures"));
        assert_eq!(mount.guest, "/data/in");
        assert_eq!(parse(mount.to_arg().to_str().unwrap()).unwrap(), mount);
        assert_eq!(parse("/a:b:/c").unwrap().host, PathBuf::from("/a:b"));
        assert_eq!(
            mount.host_path_of("/data/in/x/y"),
            Some(PathBuf::from("fixtures/x/y"))
        );
        assert_eq!(
            mount.host_path_of("/data/in"),
            Some(PathBuf::from("fixtures"))
        );
        assert_eq!(mount.host_path_of("/data/inner"), None);
        assert_eq!(
            parse("d").unwrap().host_path_of("/x"),
            Some(PathBuf::from("d/x"))
        );
    }

    #[test]
    fn a_guest_directory_must_be_normal() {
        for text in [":/x", "d:/x/", "d:/x//y", "d:/x/../y", "d:/./y"] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert_eq!(parse("d:/").unwrap().guest, "/");
    }
}
