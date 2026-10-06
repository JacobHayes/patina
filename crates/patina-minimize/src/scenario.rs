//! Scenario inputs, seed search, and parameter reduction.

use crate::MinimizeError;
use std::collections::{BTreeMap, HashSet};

/// The externally varied inputs that select one deterministic run: the root
/// seed and the key/value parameters exposed through `Context::param`. Reducing
/// a scenario shrinks a reproduction toward the smallest inputs that still
/// trigger the failure, complementing the trace reducers that shrink recorded
/// decisions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scenario {
    pub seed: u64,
    pub params: BTreeMap<String, String>,
}

impl Scenario {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            params: BTreeMap::new(),
        }
    }

    /// Add or replace a parameter, returning the scenario for chaining.
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }
}

/// Decides whether a candidate [`Scenario`] still reproduces the failure. The
/// caller owns running the scenario (typically a fresh process); the reducers
/// only propose candidates and never touch the filesystem or spawn work.
pub trait ScenarioOracle {
    type Error;

    /// Return true only when the candidate scenario reproduces the failure.
    fn reproduces_failure(&mut self, scenario: &Scenario) -> Result<bool, Self::Error>;
}

impl<F, E> ScenarioOracle for F
where
    F: FnMut(&Scenario) -> Result<bool, E>,
{
    type Error = E;

    fn reproduces_failure(&mut self, scenario: &Scenario) -> Result<bool, Self::Error> {
        self(scenario)
    }
}

/// Reduce a scenario across all of its inputs.
///
/// The seed is canonicalized first (see [`reduce_seed`]) and the parameters are
/// then reduced (see [`reduce_params`]); the two passes repeat to a fixed point
/// so a smaller seed can unlock further parameter shrinking and vice versa.
/// `seed_budget` bounds the seed search on each pass. Returns
/// [`MinimizeError::OriginalDoesNotFail`] if the input scenario does not
/// reproduce the failure.
pub fn reduce_scenario<O: ScenarioOracle>(
    scenario: &Scenario,
    oracle: &mut O,
    seed_budget: u64,
) -> Result<Scenario, MinimizeError<O::Error>> {
    require_reproduces(scenario, oracle)?;
    let mut current = scenario.clone();
    loop {
        let before = current.clone();
        current = reduce_seed(&current, oracle, seed_budget)?;
        current = reduce_params(&current, oracle)?;
        if current == before {
            break;
        }
    }
    Ok(current)
}

/// Canonicalize the root seed toward the smallest value that still reproduces
/// the failure.
///
/// Seeds have no structural order - any change yields an unrelated run - so this
/// is a bounded ascending *search*, not a delta-debug: it tries seeds `0, 1, 2,
/// …` below the current seed and returns the first that reproduces, trying at
/// most `budget` candidates. If none reproduces within the budget the original
/// failing scenario is returned unchanged. A `budget` of zero leaves the seed
/// untouched.
pub fn reduce_seed<O: ScenarioOracle>(
    scenario: &Scenario,
    oracle: &mut O,
    budget: u64,
) -> Result<Scenario, MinimizeError<O::Error>> {
    require_reproduces(scenario, oracle)?;
    let mut tried = 0u64;
    let mut candidate_seed = 0u64;
    while candidate_seed < scenario.seed && tried < budget {
        let mut candidate = scenario.clone();
        candidate.seed = candidate_seed;
        if oracle
            .reproduces_failure(&candidate)
            .map_err(MinimizeError::Oracle)?
        {
            return Ok(candidate);
        }
        tried += 1;
        candidate_seed += 1;
    }
    Ok(scenario.clone())
}

/// Reduce the parameter map while preserving the failure.
///
/// Each pass first drops any parameter that is not needed to reproduce the
/// failure, then shrinks each surviving value toward a simpler form (numeric
/// values toward zero, any value toward the empty string). Passes repeat until a
/// full pass changes nothing, yielding a locally minimal set of parameters and
/// values. Returns [`MinimizeError::OriginalDoesNotFail`] if the input scenario
/// does not reproduce the failure.
pub fn reduce_params<O: ScenarioOracle>(
    scenario: &Scenario,
    oracle: &mut O,
) -> Result<Scenario, MinimizeError<O::Error>> {
    require_reproduces(scenario, oracle)?;
    let mut current = scenario.clone();
    loop {
        let mut changed = false;
        for key in current.params.keys().cloned().collect::<Vec<_>>() {
            let mut candidate = current.clone();
            candidate.params.remove(&key);
            if oracle
                .reproduces_failure(&candidate)
                .map_err(MinimizeError::Oracle)?
            {
                current = candidate;
                changed = true;
            }
        }
        for key in current.params.keys().cloned().collect::<Vec<_>>() {
            let value = current.params[&key].clone();
            for smaller in shrink_value(&value) {
                let mut candidate = current.clone();
                candidate.params.insert(key.clone(), smaller);
                if oracle
                    .reproduces_failure(&candidate)
                    .map_err(MinimizeError::Oracle)?
                {
                    current = candidate;
                    changed = true;
                    break;
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(current)
}

/// Ordered replacement candidates for a parameter value, simplest first and
/// never equal to the original: numeric values step toward zero by halving,
/// and any non-empty value can collapse to the empty string.
fn shrink_value(value: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(number) = value.parse::<u64>() {
        if number != 0 {
            candidates.push("0".to_string());
            let mut half = number / 2;
            while half > 0 {
                candidates.push(half.to_string());
                half /= 2;
            }
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

fn require_reproduces<O: ScenarioOracle>(
    scenario: &Scenario,
    oracle: &mut O,
) -> Result<(), MinimizeError<O::Error>> {
    if oracle
        .reproduces_failure(scenario)
        .map_err(MinimizeError::Oracle)?
    {
        Ok(())
    } else {
        Err(MinimizeError::OriginalDoesNotFail)
    }
}

#[cfg(test)]
mod tests;
