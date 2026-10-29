//! Parameter reduction for `minimize --params`.

use std::collections::{BTreeMap, HashSet};

use crate::CliError;

/// Reduce `params` while `fails` keeps holding: each pass drops every
/// parameter the failure does not need, then shrinks each survivor toward a
/// simpler value (numbers toward zero, anything toward the empty string),
/// repeating until a pass changes nothing. The input must already fail.
pub(super) fn reduce(
    params: &BTreeMap<String, String>,
    mut fails: impl FnMut(&BTreeMap<String, String>) -> Result<bool, CliError>,
) -> Result<BTreeMap<String, String>, CliError> {
    let mut current = params.clone();
    loop {
        let mut changed = false;
        for key in current.keys().cloned().collect::<Vec<_>>() {
            let mut candidate = current.clone();
            candidate.remove(&key);
            if fails(&candidate)? {
                current = candidate;
                changed = true;
            }
        }
        for key in current.keys().cloned().collect::<Vec<_>>() {
            for smaller in shrink_value(&current[&key]) {
                let mut candidate = current.clone();
                candidate.insert(key.clone(), smaller);
                if fails(&candidate)? {
                    current = candidate;
                    changed = true;
                    break;
                }
            }
        }
        if !changed {
            return Ok(current);
        }
    }
}

/// Ordered replacement candidates for a parameter value, simplest first and
/// never equal to the original: a number steps toward zero by halving, and any
/// non-empty value can collapse to the empty string.
fn shrink_value(value: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(number) = value.parse::<u64>()
        && number != 0
    {
        candidates.push("0".to_string());
        let mut half = number / 2;
        while half > 0 {
            candidates.push(half.to_string());
            half /= 2;
        }
    }
    if !value.is_empty() {
        candidates.push(String::new());
    }
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter(|candidate| candidate != value && seen.insert(candidate.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn drops_unneeded_keys_and_shrinks_the_load_bearing_values() {
        let reduced = reduce(&map(&[("a", "1"), ("b", "2"), ("c", "3")]), |candidate| {
            Ok(candidate.get("b").map(String::as_str) == Some("2"))
        })
        .unwrap();
        assert_eq!(reduced, map(&[("b", "2")]));

        let reduced = reduce(&map(&[("n", "100")]), |candidate| {
            Ok(candidate
                .get("n")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|value| value >= 10))
        })
        .unwrap();
        let value: u64 = reduced["n"].parse().unwrap();
        assert!((10..100).contains(&value), "{value}");
    }
}
