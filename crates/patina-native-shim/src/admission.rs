//! The programs the guest may spawn: the supervisor's admission table
//! ([`ENV_ADMIT`]), read once at startup.
//!
//! Each entry says what a path the guest may name is: admitted (the
//! supervisor holds the artifact, by id), refused (with the reason), or, on a
//! replay, missing. A path matches as `execve` would take it: exactly, byte
//! for byte. A bare name is not resolved through `PATH`, so it is never
//! admitted.
#![cfg_attr(not(patina_posix_exports), allow(dead_code))]

use crate::runtime::control_env;
use core::ffi::CStr;
use patina_dst_runtime::{ENV_ADMIT, RuntimeError};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// What the table says of a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Admission<'a> {
    /// Admitted: the supervisor's artifact of this id stands in for it.
    Admitted(u64),
    /// Refused admission, for this reason.
    Refused(&'a str),
    /// A replay's program whose recorded artifact is gone, for this reason.
    Missing(&'a str),
    /// Not a program the guest may spawn.
    Unadmitted,
}

#[derive(Debug)]
enum Entry {
    Admitted(u64),
    Refused(String),
    Missing(String),
}

#[derive(Debug, Default)]
struct Table(BTreeMap<Vec<u8>, Entry>);

impl Table {
    /// The table the control-plane value describes; a malformed one is a
    /// configuration error.
    fn parse(value: Option<&str>) -> Result<Self, RuntimeError> {
        let invalid = |what: &str| RuntimeError::Config(format!("{ENV_ADMIT} is invalid: {what}"));
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let object: BTreeMap<String, serde_json::Value> =
            serde_json::from_str(value).map_err(|error| invalid(&error.to_string()))?;
        let mut table = BTreeMap::new();
        for (path, entry) in object {
            let entry = match entry
                .as_object()
                .map(|entry| entry.iter().collect::<Vec<_>>())
            {
                Some(fields) if fields.len() == 1 => match (fields[0].0.as_str(), fields[0].1) {
                    ("admitted", id) => Entry::Admitted(id.as_u64().ok_or_else(|| invalid(&path))?),
                    ("refused", reason) => {
                        Entry::Refused(reason.as_str().ok_or_else(|| invalid(&path))?.to_owned())
                    }
                    ("missing", reason) => {
                        Entry::Missing(reason.as_str().ok_or_else(|| invalid(&path))?.to_owned())
                    }
                    _ => return Err(invalid(&path)),
                },
                _ => return Err(invalid(&path)),
            };
            table.insert(path.into_bytes(), entry);
        }
        Ok(Self(table))
    }

    fn lookup(&self, path: &CStr) -> Admission<'_> {
        match self.0.get(path.to_bytes()) {
            Some(Entry::Admitted(id)) => Admission::Admitted(*id),
            Some(Entry::Refused(reason)) => Admission::Refused(reason),
            Some(Entry::Missing(reason)) => Admission::Missing(reason),
            None => Admission::Unadmitted,
        }
    }
}

static TABLE: OnceLock<Table> = OnceLock::new();

/// Read the table from the control plane. Called once, at startup; a
/// malformed table fails the run's start.
pub(crate) fn capture() -> Result<(), RuntimeError> {
    let table = Table::parse(control_env(ENV_ADMIT).as_deref())?;
    let _ = TABLE.set(table);
    Ok(())
}

/// What the guest's spawn of the program at `path` meets.
pub(crate) fn admitted_program(path: &CStr) -> Admission<'static> {
    TABLE
        .get()
        .map_or(Admission::Unadmitted, |table| table.lookup(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path is what the supervisor named it, matched exactly, and a
    /// malformed table is refused.
    #[test]
    fn the_table_matches_exact_paths_and_refuses_a_malformed_one() {
        let table = Table::parse(Some(
            r#"{"/t/bin":{"admitted":3},"/t/bad":{"refused":"why"},"/t/gone":{"missing":"gone"}}"#,
        ))
        .unwrap();
        assert_eq!(table.lookup(c"/t/bin"), Admission::Admitted(3));
        assert_eq!(table.lookup(c"/t/bad"), Admission::Refused("why"));
        assert_eq!(table.lookup(c"/t/gone"), Admission::Missing("gone"));
        for other in [c"bin", c"/t/bin/", c"/t//bin"] {
            assert_eq!(table.lookup(other), Admission::Unadmitted);
        }
        for malformed in [
            r#"{"/t/bin":3}"#,
            r#"{"/t/bin":{"admitted":"/host/copy"}}"#,
            r#"{"/t/bin":{"admitted":1,"refused":"both"}}"#,
            "[]",
        ] {
            assert!(Table::parse(Some(malformed)).is_err(), "{malformed}");
        }
    }
}
