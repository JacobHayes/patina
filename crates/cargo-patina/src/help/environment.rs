//! The environment variables the CLI honors.

use super::*;

/// Every environment variable the tool reads. The supervisor-to-guest control
/// plane (`PATINA_RT_*`) is internal and documented in ARCHITECTURE.md.
pub const ENVIRONMENT: &[EnvVar] = &[
    EnvVar {
        name: "PATINA_SEED / PATINA_SEEDS / PATINA_FORMAT",
        scope: "user",
        doc: "Defaults for --seed, --seeds and --format where a verb takes them. A typed flag wins, then a non-empty variable, then the built-in default. No other flag has an environment default.",
    },
    EnvVar {
        name: "PATINA_CLI",
        scope: "user",
        doc: "Absolute path to the patina a `#[patina_dst::test]` launches under plain `cargo test` (default: patina on PATH).",
    },
    EnvVar {
        name: "CARGO / RUSTC / CC",
        scope: "tool",
        doc: "Override the cargo, rustc, and C compiler binaries (default cargo/rustc/cc).",
    },
    EnvVar {
        name: "RUSTFLAGS / CARGO_TARGET_DIR",
        scope: "tool",
        doc: "Honored as usual; Patina augments RUSTFLAGS via CARGO_ENCODED_RUSTFLAGS for package builds and uses CARGO_TARGET_DIR as the base for its namespaced shim staging.",
    },
    EnvVar {
        name: "PATINA_SHIM_TARGET_DIR",
        scope: "tool",
        doc: "The base for Patina's namespaced shim staging in place of CARGO_TARGET_DIR, which still holds the guest's own build: guests built in separate target dirs share one shim build.",
    },
];
