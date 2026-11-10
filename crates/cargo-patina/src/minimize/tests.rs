//! Regression tests for minimize.

use super::*;

pub(super) fn strings(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

/// A stand-in for `patina run --format json`: a shell script that prints the
/// run envelope `body` builds from the command's words.
fn fake_run(body: &str) -> Vec<OsString> {
    let script = format!(
        "envelope() {{ printf '{{\"schema\":\"{}\",\"verb\":\"run\",\"result\":\"%s\",\"guest_exit\":{{%s}}}}\\n' \"$1\" \"$2\"; }}\n{body}",
        crate::output::ENVELOPE_SCHEMA
    );
    strings(&["sh", "-c", &script, "sh"])
}

fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

#[test]
fn params_minimization_keeps_only_what_the_failure_needs() {
    // The run fails (guest status 3) while `keep` is set to a number; a
    // candidate that fails another way (status 4, `drop` alone) is not the
    // failure.
    let invocation = ParamsMinimize {
        head: fake_run(
            "case \"$*\" in *keep=[0-9]*) envelope failure '\"code\":3';; \
             *drop=*) envelope failure '\"code\":4';; *) envelope ok '\"code\":0';; esac",
        ),
        tail: strings(&["--", "guest"]),
        params: params(&[("keep", "17"), ("drop", "5")]),
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
        head: fake_run(
            "case \"$*\" in *keep=*) envelope failure '\"code\":143,\"signal\":15';; \
             *) envelope failure '\"code\":137,\"signal\":9';; esac",
        ),
        tail: Vec::new(),
        params: params(&[("keep", "x")]),
    };
    let (reduced, _) = minimize_params(&invocation).unwrap();
    assert!(reduced.contains_key("keep"), "{reduced:?}");
}

#[test]
fn params_minimization_refuses_a_command_that_reports_no_run() {
    // A failing command is not a failing run: with no result envelope there is
    // no failure of a guest to preserve, whatever the exit status.
    for head in [
        strings(&["false"]),
        strings(&["sh", "-c", "echo not an envelope; exit 3", "sh"]),
    ] {
        let invocation = ParamsMinimize {
            head,
            tail: Vec::new(),
            params: params(&[("a", "1")]),
        };
        assert!(minimize_params(&invocation).is_err());
    }
}

pub(super) fn verdict(kind: &str, label: &str) -> VerdictFacts {
    VerdictFacts {
        kind: kind.to_string(),
        label: label.to_string(),
    }
}
