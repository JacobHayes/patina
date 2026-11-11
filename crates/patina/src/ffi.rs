//! Native shim ABI declarations.

/// Declare the shim's entries, and list their names.
///
/// The declarations exist only in a build that links the shim. The names are
/// always there: a build for Patina also compiles programs it does not link
/// to the shim (a package's own binary, built beside the integration test
/// Patina was asked for), and the tool gives each a stand-in for every entry.
macro_rules! shim_entries {
    ($(pub fn $name:ident($($argument:ident: $type:ty),* $(,)?) $(-> $result:ty)?;)*) => {
        #[cfg(patina_shim)]
        unsafe extern "C" {
            $(pub fn $name($($argument: $type),*) $(-> $result)?;)*
        }

        /// The name of every shim entry the SDK calls.
        pub const SHIM_ENTRIES: &[&str] = &[$(stringify!($name)),*];
    };
}

shim_entries! {
    pub fn patina_is_simulated() -> i32;
    pub fn patina_buggify(
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
        prob_permille: i32,
    ) -> i32;
    pub fn patina_buggify_delay(
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
    ) -> i32;
    pub fn patina_buggify_knob(
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
        default_value: i64,
        lo: i64,
        hi: i64,
    ) -> i64;
    pub fn patina_always(
        condition: i32,
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
    ) -> i32;
    pub fn patina_sometimes(
        condition: i32,
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
    ) -> i32;
    pub fn patina_reachable(
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
    ) -> i32;
    pub fn patina_rng() -> u64;
    pub fn patina_param(key: *const u8, key_len: usize, out: *mut u8, out_cap: usize) -> isize;
    pub fn patina_lifecycle_setup_complete() -> i32;
    pub fn patina_lifecycle_event(label: *const u8, label_len: usize) -> i32;
    pub fn patina_verdict(
        kind: u32,
        label: *const u8,
        label_len: usize,
        detail: *const u8,
        detail_len: usize,
    ) -> i32;
}
