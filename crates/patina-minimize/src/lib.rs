//! Failure-preserving reducers for experiment inputs: the root seed and the
//! `Context::param` parameters.

use std::convert::Infallible;
use std::fmt;

mod scenario;

pub use scenario::{Scenario, ScenarioOracle, reduce_params, reduce_scenario, reduce_seed};

#[derive(Debug)]
pub enum MinimizeError<E = Infallible> {
    Oracle(E),
    OriginalDoesNotFail,
}

impl<E: fmt::Display> fmt::Display for MinimizeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oracle(error) => write!(f, "failure oracle failed: {error}"),
            Self::OriginalDoesNotFail => {
                f.write_str("the original scenario does not reproduce the failure")
            }
        }
    }
}

impl<E> std::error::Error for MinimizeError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Oracle(error) => Some(error),
            Self::OriginalDoesNotFail => None,
        }
    }
}
