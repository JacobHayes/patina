//! Regression tests for minimize.

use super::*;

pub(super) fn strings(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn params_minimization_keeps_only_what_the_failure_needs() {
    // The command fails (status 3) while `keep` is set to a number;
    // a candidate that fails another way (status 4, `drop` alone) is not the
    // failure.
    let invocation = ParamsMinimize {
        head: strings(&[
            "sh",
            "-c",
            "case \"$*\" in *keep=[0-9]*) exit 3;; *drop=*) exit 4;; esac",
            "sh",
        ]),
        tail: strings(&["--", "guest"]),
        params: [("keep", "17"), ("drop", "5")]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
    };
    let (reduced, _) = minimize_params(&invocation).unwrap();
    assert_eq!(
        reduced.into_iter().collect::<Vec<_>>(),
        [("keep".to_string(), "0".to_string())]
    );
}

#[test]
fn params_minimization_tells_fatal_signals_apart() {
    // SIGTERM while `keep` is set, SIGKILL without it: dropping `keep` changes
    // the failure, so it stays.
    let invocation = ParamsMinimize {
        head: strings(&[
            "sh",
            "-c",
            "case \"$*\" in *keep=*) kill -TERM $$;; *) kill -KILL $$;; esac",
            "sh",
        ]),
        tail: Vec::new(),
        params: [("keep".to_string(), "x".to_string())]
            .into_iter()
            .collect(),
    };
    let (reduced, _) = minimize_params(&invocation).unwrap();
    assert!(reduced.contains_key("keep"), "{reduced:?}");
}

pub(super) fn verdict(kind: &str, label: &str) -> VerdictFacts {
    VerdictFacts {
        kind: kind.to_string(),
        label: label.to_string(),
    }
}
