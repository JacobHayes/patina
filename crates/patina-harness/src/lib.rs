//! Configure-then-run harness for ordinary application code under [Patina].
//!
//! This is *usage mode 2* of [USAGE-MODES.md]: a harness binary configures
//! the deterministic runtime and then calls **ordinary application code** whose
//! `std::fs`, `std::net`, clock, thread, and entropy effects are interposed by
//! Patina's native shim — the same global runtime context the shim installs for a
//! transparent run. The application body uses plain `std`, and those effects
//! flow through the one installed runtime.
//!
//! ```no_run
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     patina_dst_harness::run_with(
//!         |harness| Ok(harness.sleep_jitter_nanos(1_000, 5_000)),
//!         || {
//!             // ordinary application code; std effects are interposed
//!             std::fs::write("/state/value", b"hello")?;
//!             Ok::<(), std::io::Error>(())
//!         },
//!     )?;
//!     Ok(())
//! }
//! ```
//!
//! # Execution model — must run through Patina
//!
//! A shim-backed harness MUST be built and run through Patina's native shim
//! (startup Option B, deferred initialization):
//!
//! ```sh
//! cargo patina run path/to/harness/Cargo.toml --seed 1
//! cargo patina run path/to/harness/Cargo.toml --record trace.patina
//! cargo patina replay path/to/harness/Cargo.toml trace.patina
//! ```
//!
//! A harness binary identifies itself: this crate embeds a marker
//! ([`rt::HARNESS_MARKER`]) in the program image, and the supervisor sets
//! `PATINA_RT_DEFER_INIT=1` whenever it finds it, so no flag has to be repeated
//! on `run`, `replay` or `campaign`. The variable tells the packaged constructor to
//! capture and scrub the control plane and register finalization but leave the
//! runtime uninstalled; [`run`]/[`run_with`] then install it after applying the
//! configuration overlay. A plain `cargo run` (or any execution without the
//! Patina control plane) fails loudly with [`HarnessError::NotUnderPatina`]
//! *before* the application closure runs — it never falls back to host effects.
//! If any interposed effect reaches the deterministic boundary before the harness
//! installs, the run fails closed (the shim aborts, or install returns
//! [`HarnessError::BoundaryBeforeInstall`]).
//!
//! # Configuration overlay and replay identity
//!
//! [`HarnessBuilder`] knobs are applied as an overlay on top of the CLI-provided
//! control plane, flowing through the **same** `RuntimeConfig` fields the
//! `cargo patina run` environment path sets. There is no separate harness
//! fingerprint component: the existing fingerprint folds and the runtime's
//! `reconcile_replay_*` conflict checks apply unchanged. On replay, a harness
//! configuration that conflicts with the recorded trace fails closed
//! ([`HarnessError::Config`]).
//!
//! Every knob records into the trace header, and the policy part of the
//! compatibility fingerprint (`+buggify`, `+pct`, `+swarm`, `+yieldstride`) is
//! computed by the runtime from the configuration it actually installed, so a
//! harness that enables buggify in code records and replays with no extra flags.
//! A crash (`--machine-crash-permille`, `--process-crash-permille`) is not a
//! harness knob: the supervisor that boots the next incarnation reads it from
//! the CLI.
//!
//! # Named services
//!
//! [`HarnessBuilder::dns_service`] names a service and allocates it a virtual
//! address; [`HarnessBuilder::dns_entry`] pins a name to an address you choose.
//! Either way the application code stays ordinary production code — it resolves
//! the name through plain `std`, and a server binding `0.0.0.0:PORT` receives
//! whatever address the client dialed on that port, so nothing service-side has
//! to know the name exists:
//!
//! ```no_run
//! use std::net::ToSocketAddrs;
//!
//! patina_dst_harness::run_with(
//!     |harness| Ok(harness.dns_service("db.internal").dns_entry("cache", "10.9.9.9")),
//!     || {
//!         let addr = ("db.internal", 9000).to_socket_addrs()?.next();
//!         println!("db.internal -> {addr:?}"); // 10.0.0.1:9000
//!         Ok::<(), std::io::Error>(())
//!     },
//! )?;
//! # Ok::<(), patina_dst_harness::HarnessError>(())
//! ```
//!
//! # Threads
//!
//! Application code may spawn threads. They become managed tasks on the same
//! deterministic scheduler a transparent run uses, so the listener half of a
//! client/server scenario can run on its own thread inside the closure. The run's
//! deterministic body ends when the closure returns — exactly as it ends when
//! `main` returns under the supervisor — so a worker still running at that point
//! is cut off there; join anything whose completion the run depends on.
//!
//! # v1 scope
//!
//! Building an initial virtual filesystem image from code is out of scope for v1:
//! the CLI `--mount` owns the filesystem image. Network *topology* is likewise out
//! of scope — the DNS builders above are one host-table entry per name, not a
//! topology model, and multi-process topologies remain future work.
//!
//! [Patina]: https://github.com/JacobHayes/patina
//! [USAGE-MODES.md]: https://github.com/JacobHayes/patina/blob/main/USAGE-MODES.md

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use patina_dst_runtime as rt;

/// The bytes of [`rt::HARNESS_MARKER`], placed in every program that links this
/// crate. `cargo patina run` scans the image for them (as it does for the
/// instrumentation marker) and defers runtime installation to [`run_with`].
#[used]
static HARNESS_MARKER: [u8; rt::HARNESS_MARKER.len()] = {
    let mut bytes = [0u8; rt::HARNESS_MARKER.len()];
    let mut index = 0;
    while index < bytes.len() {
        bytes[index] = rt::HARNESS_MARKER[index];
        index += 1;
    }
    bytes
};

/// An error from a harness run.
#[derive(Debug)]
pub enum HarnessError {
    /// The binary is not running under `cargo patina run`: there is no
    /// Patina control plane (plain `cargo run`, or a missing supervisor). The
    /// application closure never ran.
    NotUnderPatina,
    /// A deterministic runtime is already installed. Call
    /// [`run`]/[`run_with`] once, from a binary run through `cargo patina`.
    AlreadyInstalled,
    /// A deterministic boundary effect ran before the harness installed the
    /// runtime, so reconfiguring it would make replay ambiguous.
    BoundaryBeforeInstall,
    /// The runtime configuration could not be built or reconciled: a malformed
    /// knob value, or (on replay) a harness configuration that conflicts with the
    /// authoritative trace. The shim printed the specific diagnostic to stderr.
    Config(String),
    /// Finalizing the run (writing the trace, flushing captured output) failed.
    Finalize(String),
    /// The application closure returned an error. The run was finalized first.
    Entry(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HarnessError::NotUnderPatina => write!(
                formatter,
                "not running under Patina: build and run the harness with \
                 `cargo patina run <manifest>`"
            ),
            HarnessError::AlreadyInstalled => write!(
                formatter,
                "a deterministic runtime is already installed; call run/run_with exactly once, \
                 from a binary run through `cargo patina`"
            ),
            HarnessError::BoundaryBeforeInstall => write!(
                formatter,
                "a deterministic boundary effect ran before the harness installed the runtime; \
                 do all configuration and application effects inside the harness closure"
            ),
            HarnessError::Config(message) => write!(formatter, "harness configuration: {message}"),
            HarnessError::Finalize(message) => write!(formatter, "harness finalize: {message}"),
            HarnessError::Entry(error) => write!(formatter, "application error: {error}"),
        }
    }
}

impl Error for HarnessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HarnessError::Entry(error) => Some(&**error),
            _ => None,
        }
    }
}

/// Desired runtime configuration for a harness run, applied as an overlay over the
/// CLI-provided control plane. Every knob maps to the same `PATINA_*` control-plane
/// value the `cargo patina run` environment path sets, so harness configuration
/// flows through the identical `RuntimeConfig` fields (and the same fingerprint
/// folds and replay-reconciliation checks). See the [crate docs](crate) for the
/// non-fingerprinted vs. fingerprinted knob distinction under `--record`/`replay`.
#[derive(Clone, Debug, Default)]
pub struct HarnessBuilder {
    overlay: BTreeMap<String, String>,
    params: BTreeMap<String, String>,
    dns_entries: BTreeMap<String, String>,
    /// Names registered through [`HarnessBuilder::dns_service`], in registration
    /// order — the order their virtual addresses are allocated from.
    dns_services: Vec<String>,
}

impl HarnessBuilder {
    /// A builder with no overrides: the run uses exactly the CLI-provided
    /// configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn set(mut self, key: &str, value: impl Into<String>) -> Self {
        self.overlay.insert(key.to_string(), value.into());
        self
    }

    /// Ensure buggify is enabled without clobbering an explicit firing per-mille.
    fn enable_buggify(mut self) -> Self {
        self.overlay.entry(rt::ENV_BUGGIFY.to_string()).or_default();
        self
    }

    /// Maximum boundary operations before the run fails with a step-budget error.
    #[must_use]
    pub fn step_budget(self, budget: u64) -> Self {
        self.set(rt::ENV_STEP_BUDGET, budget.to_string())
    }

    /// Base link latency (nanoseconds) applied to the default virtual network.
    #[must_use]
    pub fn net_latency_nanos(self, nanos: u64) -> Self {
        self.set(rt::ENV_NET_LATENCY, nanos.to_string())
    }

    /// A run parameter default, read by the application through
    /// `patina_dst::param(key)`. A `cargo patina run --param` for the same key
    /// overrides it; the merged set is recorded and restored on replay.
    #[must_use]
    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }

    /// Enable the PCT exploration scheduling policy with bug depth `depth` and an
    /// expected schedule length of `steps` boundaries.
    #[must_use]
    pub fn schedule_pct(self, depth: u32, steps: u64) -> Self {
        self.set(rt::ENV_SCHED_PCT, depth.to_string())
            .set(rt::ENV_SCHED_PCT_STEPS, steps.to_string())
    }

    /// Arm the generic no-progress liveness watchdog with a virtual-time budget in
    /// nanoseconds. Schedule-invariant (not fingerprinted).
    #[must_use]
    pub fn liveness_watchdog_nanos(self, nanos: u64) -> Self {
        self.set(rt::ENV_LIVENESS_WATCHDOG, nanos.to_string())
    }

    /// Arm the heal-then-converge liveness watchdog with a convergence budget in
    /// nanoseconds. Schedule-invariant (not fingerprinted).
    #[must_use]
    pub fn converge_within_nanos(self, nanos: u64) -> Self {
        self.set(rt::ENV_CONVERGE_WITHIN, nanos.to_string())
    }

    /// Override the heal-then-converge arm-time (elapsed virtual nanoseconds
    /// since guest start). Inert
    /// without [`HarnessBuilder::converge_within_nanos`].
    #[must_use]
    pub fn heal_after_nanos(self, nanos: u64) -> Self {
        self.set(rt::ENV_HEAL_AFTER, nanos.to_string())
    }

    /// Add seeded extra latency to every guest sleep, drawn from `[min, max]`
    /// nanoseconds.
    #[must_use]
    pub fn sleep_jitter_nanos(self, min: u64, max: u64) -> Self {
        self.set(rt::ENV_SLEEP_JITTER, format!("{min}..{max}"))
    }

    /// Add seeded per-datagram delivery jitter drawn from `[min, max]` nanoseconds.
    #[must_use]
    pub fn net_jitter_nanos(self, min: u64, max: u64) -> Self {
        self.set(rt::ENV_NET_JITTER, format!("{min}..{max}"))
    }

    /// Drop datagrams with the given per-mille (0..=1000) probability.
    #[must_use]
    pub fn net_drop_permille(self, permille: u16) -> Self {
        self.set(rt::ENV_NET_DROP_PERMILLE, permille.to_string())
    }

    /// Enable cooperative-SUT (buggify) fault injection at its default firing
    /// per-mille.
    #[must_use]
    pub fn buggify(self) -> Self {
        self.enable_buggify()
    }

    /// Enable buggify with an explicit per-evaluation firing per-mille (0..=1000).
    ///
    #[must_use]
    pub fn buggify_fire_permille(self, permille: u16) -> Self {
        self.set(rt::ENV_BUGGIFY, permille.to_string())
    }

    /// Set the per-run site activation per-mille (0..=1000). Enables buggify.
    #[must_use]
    pub fn buggify_activation_permille(self, permille: u16) -> Self {
        self.enable_buggify()
            .set(rt::ENV_BUGGIFY_ACTIVATION, permille.to_string())
    }

    /// Gate buggify off until the guest calls
    /// `patina_dst::lifecycle::setup_complete()`. Enables buggify.
    #[must_use]
    pub fn buggify_after_setup(self) -> Self {
        self.enable_buggify().set(rt::ENV_BUGGIFY_AFTER_SETUP, "1")
    }

    /// Apply a seed-derived subset of the enabled fault classes this run instead
    /// of all of them.
    #[must_use]
    pub fn swarm(self) -> Self {
        self.set(rt::ENV_SWARM, "1")
    }

    /// Define `name` in the run's DNS host table, resolving to the IPv4 literal
    /// `address` — the code-side twin of `--dns-entry NAME=ADDR`.
    ///
    /// Names the table does not define are NXDOMAIN, and the `--dns-*` fault
    /// knobs act only on defined names. A malformed name or address is rejected
    /// when the runtime installs, as [`HarnessError::Config`], the same as any
    /// other malformed knob value.
    #[must_use]
    pub fn dns_entry(mut self, name: impl Into<String>, address: impl Into<String>) -> Self {
        self.dns_entries.insert(name.into(), address.into());
        self
    }

    /// Define `name` as a service running inside this harness, resolving it to a
    /// virtual address the builder allocates.
    ///
    /// The service body needs no registration of its own: it binds
    /// `0.0.0.0:PORT` the way production server code does, and a client that
    /// resolves `name` and dials the resulting address reaches it, because a
    /// wildcard bind receives traffic addressed to any address on its port.
    ///
    /// Addresses are allocated `10.0.0.1`, `10.0.0.2`, … in registration order,
    /// skipping any address an explicit [`HarnessBuilder::dns_entry`] already
    /// claims, so every name in the table resolves somewhere distinct. The
    /// allocation is a pure function of the registered names, so it is identical
    /// on record and replay.
    #[must_use]
    pub fn dns_service(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        if !self.dns_services.contains(&name) {
            self.dns_services.push(name);
        }
        self
    }

    /// Resolve the registered services into host-table entries, allocating each
    /// an address no explicit entry claims.
    fn allocate_dns_services(&mut self) -> Result<(), HarnessError> {
        if self.dns_services.is_empty() {
            return Ok(());
        }
        // Seeded with the explicitly pinned addresses and grown as services are
        // allocated, so the result depends only on the registration ORDER and the
        // pinned set — never on the host table's map iteration order.
        let mut claimed: Vec<String> = self.dns_entries.values().cloned().collect();
        for name in std::mem::take(&mut self.dns_services) {
            if self.dns_entries.contains_key(&name) {
                return Err(HarnessError::Config(format!(
                    "DNS service {name:?} is also defined by dns_entry; a name resolves to one \
                     address, so register it as a service OR pin it explicitly, not both"
                )));
            }
            let address = (1..=254u8)
                .map(|host| format!("10.0.0.{host}"))
                .find(|candidate| !claimed.contains(candidate))
                .ok_or_else(|| {
                    HarnessError::Config(
                        "the harness DNS service address pool (10.0.0.1-10.0.0.254) is exhausted"
                            .into(),
                    )
                })?;
            claimed.push(address.clone());
            self.dns_entries.insert(name, address);
        }
        Ok(())
    }

    /// Finalize the overlay into a flat `PATINA_*` map (params and the DNS host
    /// table folded to JSON).
    fn into_overlay(mut self) -> Result<BTreeMap<String, String>, HarnessError> {
        if !self.params.is_empty() {
            let json = serde_json::to_string(&self.params).map_err(|error| {
                HarnessError::Config(format!("failed to encode harness params: {error}"))
            })?;
            self.overlay.insert(rt::ENV_PARAMS_JSON.to_string(), json);
        }
        self.allocate_dns_services()?;
        if !self.dns_entries.is_empty() {
            let json = serde_json::to_string(&self.dns_entries).map_err(|error| {
                HarnessError::Config(format!("failed to encode the harness DNS table: {error}"))
            })?;
            self.overlay.insert(rt::ENV_DNS_ENTRIES.to_string(), json);
        }
        Ok(self.overlay)
    }
}

/// Configure Patina and then run ordinary application code, using no overrides
/// beyond the CLI-provided configuration. Equivalent to [`run_with`] with an
/// identity configuration closure.
///
/// The application closure's `Ok`/`Err` propagates after the run is finalized; see
/// [`run_with`] for the ordering contract.
pub fn run<E>(entry: impl FnOnce() -> Result<(), E>) -> Result<(), HarnessError>
where
    E: Into<Box<dyn Error + Send + Sync>>,
{
    run_with(Ok, entry)
}

/// Configure Patina with `configure`, install the runtime, then run ordinary
/// application code in `entry`.
///
/// # Ordering and finalization
///
/// 1. `configure` builds the [`HarnessBuilder`]; its `Err` short-circuits before
///    the runtime is installed.
/// 2. The overlay is applied and the runtime is installed. Any fail-closed reason
///    (not under Patina, already installed, boundary already seen, bad config)
///    returns the matching [`HarnessError`] and `entry` never runs.
/// 3. `entry` runs against the installed runtime.
/// 4. The run is finalized (trace written, captured output flushed) **regardless
///    of `entry`'s result**, so a recorded trace exists even when the application
///    errored. The packaged `atexit` finalizer remains an idempotent backup for
///    panics and explicit `exit`.
/// 5. `entry`'s `Err` is returned (as [`HarnessError::Entry`]) after finalization;
///    if `entry` succeeded, a finalization failure is returned instead.
pub fn run_with<E>(
    configure: impl FnOnce(HarnessBuilder) -> Result<HarnessBuilder, HarnessError>,
    entry: impl FnOnce() -> Result<(), E>,
) -> Result<(), HarnessError>
where
    E: Into<Box<dyn Error + Send + Sync>>,
{
    // Anchor the marker in the image so the supervisor can recognise a harness
    // binary even after the linker drops unreferenced statics.
    std::hint::black_box(&HARNESS_MARKER);
    let builder = configure(HarnessBuilder::new())?;

    #[cfg(patina_shim)]
    {
        install(builder)?;
        let entry_result = entry().map_err(|error| HarnessError::Entry(error.into()));
        let finalize_result = finalize();
        entry_result?;
        finalize_result
    }
    #[cfg(not(patina_shim))]
    {
        // Not built through `cargo patina build` (no shim linked below): the
        // deterministic runtime cannot exist, so fail closed before running any
        // application code rather than execute it against host effects.
        let _ = (builder.into_overlay(), entry);
        Err(HarnessError::NotUnderPatina)
    }
}

/// FFI into the native shim. Present only when the shim is actually linked
/// (`cfg(patina_shim)`, injected by `cargo patina build`). Under a plain
/// `cargo build` these symbols are never referenced, so nothing is left
/// unresolved at link time — mirroring `patina-dst`'s own shim bridge.
#[cfg(patina_shim)]
mod ffi {
    use std::ffi::c_char;

    unsafe extern "C" {
        /// Inject one `PATINA_NAME=value` control-plane entry (overlay).
        pub fn patina_control_set_entry(entry: *const c_char);
        /// Build the runtime from the (overlaid) control plane and install it.
        pub fn patina_harness_install() -> i32;
        /// Finalize the run: write any recorded trace and flush captured output.
        pub fn patina_shutdown() -> i32;
    }
}

#[cfg(patina_shim)]
fn install(builder: HarnessBuilder) -> Result<(), HarnessError> {
    use std::ffi::CString;

    for (name, value) in builder.into_overlay()? {
        let entry = CString::new(format!("{name}={value}")).map_err(|_| {
            HarnessError::Config(format!(
                "overlay value for {name} contains an interior NUL byte"
            ))
        })?;
        // SAFETY: `entry` is a valid NUL-terminated string for the call's duration.
        unsafe { ffi::patina_control_set_entry(entry.as_ptr()) };
    }

    // SAFETY: no arguments; the shim reads the (now-overlaid) control plane.
    let code = unsafe { ffi::patina_harness_install() };
    match code {
        rt::HARNESS_OK => Ok(()),
        rt::HARNESS_ERR_NOT_UNDER_PATINA => Err(HarnessError::NotUnderPatina),
        rt::HARNESS_ERR_ALREADY_INSTALLED => Err(HarnessError::AlreadyInstalled),
        rt::HARNESS_ERR_BOUNDARY_BEFORE_INSTALL => Err(HarnessError::BoundaryBeforeInstall),
        _ => Err(HarnessError::Config(
            "the shim rejected the harness configuration (see the diagnostic on stderr)".into(),
        )),
    }
}

#[cfg(patina_shim)]
fn finalize() -> Result<(), HarnessError> {
    // SAFETY: no arguments; idempotent with the atexit finalizer.
    let code = unsafe { ffi::patina_shutdown() };
    if code == 0 {
        Ok(())
    } else {
        Err(HarnessError::Finalize(format!(
            "patina_shutdown reported failure (code {code})"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // These run under a plain `cargo test` (no `patina_shim`), so the shim is not
    // linked: `run`/`run_with` take the fail-closed `NotUnderPatina` path. That is
    // exactly the property to prove — outside Patina the harness never runs the
    // application closure. The full shim-linked behavior is exercised by the
    // cargo-patina `end_to_end` harness gates.

    #[test]
    fn outside_patina_or_after_a_configure_error_the_entry_never_runs() {
        let ran = Cell::new(false);
        let result = run(|| {
            ran.set(true);
            Ok::<(), std::io::Error>(())
        });
        assert!(matches!(result, Err(HarnessError::NotUnderPatina)));
        assert!(!ran.get(), "application closure ran without Patina");

        let result = run_with(
            |_| Err(HarnessError::Config("rejected".into())),
            || {
                ran.set(true);
                Ok::<(), std::io::Error>(())
            },
        );
        assert!(matches!(result, Err(HarnessError::Config(message)) if message == "rejected"));
        assert!(
            !ran.get(),
            "application closure ran after a configuration error"
        );
    }

    #[test]
    fn builder_maps_knobs_to_control_plane_overlay() {
        let overlay = HarnessBuilder::new()
            .sleep_jitter_nanos(1, 2)
            .net_drop_permille(250)
            .buggify_fire_permille(100)
            .schedule_pct(3, 1000)
            .liveness_watchdog_nanos(5)
            .step_budget(42)
            .net_latency_nanos(7)
            .param("k", "v")
            .into_overlay()
            .unwrap();
        assert_eq!(overlay[rt::ENV_SLEEP_JITTER], "1..2");
        assert_eq!(overlay[rt::ENV_NET_DROP_PERMILLE], "250");
        assert_eq!(overlay[rt::ENV_BUGGIFY], "100");
        assert_eq!(overlay[rt::ENV_SCHED_PCT], "3");
        assert_eq!(overlay[rt::ENV_SCHED_PCT_STEPS], "1000");
        assert_eq!(overlay[rt::ENV_LIVENESS_WATCHDOG], "5");
        assert_eq!(overlay[rt::ENV_STEP_BUDGET], "42");
        assert_eq!(overlay[rt::ENV_NET_LATENCY], "7");
        assert_eq!(overlay[rt::ENV_PARAMS_JSON], "{\"k\":\"v\"}");
    }

    #[test]
    fn buggify_sub_knobs_enable_buggify_without_clobbering_its_rate() {
        let overlay = HarnessBuilder::new()
            .buggify_activation_permille(500)
            .into_overlay()
            .unwrap();
        assert_eq!(
            overlay[rt::ENV_BUGGIFY],
            "",
            "activation knob must enable buggify"
        );
        assert_eq!(overlay[rt::ENV_BUGGIFY_ACTIVATION], "500");

        // A later sub-knob must not clobber an explicit firing per-mille.
        let overlay = HarnessBuilder::new()
            .buggify_fire_permille(250)
            .buggify_after_setup()
            .into_overlay()
            .unwrap();
        assert_eq!(overlay[rt::ENV_BUGGIFY], "250");
        assert_eq!(overlay[rt::ENV_BUGGIFY_AFTER_SETUP], "1");
    }

    #[test]
    fn dns_entries_and_services_fold_into_one_host_table_or_none() {
        // Services allocate in registration order and SKIP an address an explicit
        // entry already claims: two names resolving to one address would make a
        // multi-service test pass for the wrong reason.
        let overlay = HarnessBuilder::new()
            .dns_entry("pinned.internal", "10.0.0.2")
            .dns_service("db.internal")
            .dns_service("cache.internal")
            .dns_service("db.internal") // repeat: same allocation, not a second one
            .into_overlay()
            .unwrap();
        assert_eq!(
            overlay[rt::ENV_DNS_ENTRIES],
            r#"{"cache.internal":"10.0.0.3","db.internal":"10.0.0.1","pinned.internal":"10.0.0.2"}"#
        );

        let overlay = HarnessBuilder::new().step_budget(1).into_overlay().unwrap();
        assert!(!overlay.contains_key(rt::ENV_DNS_ENTRIES));

        // A name that is both a service and a pinned entry is refused.
        let error = HarnessBuilder::new()
            .dns_entry("db.internal", "10.9.9.9")
            .dns_service("db.internal")
            .into_overlay()
            .unwrap_err();
        assert!(
            matches!(&error, HarnessError::Config(message) if message.contains("db.internal")),
            "expected a loud conflict, got {error:?}"
        );
    }
}
