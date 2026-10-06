//! Shared async test context and invalid-state assertions.

use patina_dst_abi::ErrorCode;
use patina_dst_runtime::{Context, RuntimeConfig, RuntimeError};

pub(super) fn context(seed: u64) -> Context {
    Context::from_config(RuntimeConfig::seeded(seed)).unwrap()
}

pub(super) fn assert_invalid_state(error: RuntimeError) {
    match error {
        RuntimeError::Effect(effect) => assert_eq!(effect.code, ErrorCode::InvalidState),
        other => panic!("expected InvalidState, got {other:?}"),
    }
}
