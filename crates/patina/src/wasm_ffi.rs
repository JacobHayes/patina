//! WASI host imports for the SDK ABI.

#[link(wasm_import_module = "patina_sdk")]
unsafe extern "C" {
    pub fn is_simulated() -> i32;
    pub fn buggify(
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
        prob_permille: i32,
    ) -> i32;
    pub fn buggify_delay(
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
    ) -> i32;
    pub fn buggify_knob(
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
        default_value: i64,
        lo: i64,
        hi: i64,
    ) -> i64;
    pub fn always(
        condition: i32,
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
    ) -> i32;
    pub fn sometimes(
        condition: i32,
        label: *const u8,
        label_len: usize,
        site: *const u8,
        site_len: usize,
    ) -> i32;
    pub fn reachable(label: *const u8, label_len: usize, site: *const u8, site_len: usize) -> i32;
    pub fn rng() -> u64;
    pub fn lifecycle_setup_complete() -> i32;
    pub fn lifecycle_event(label: *const u8, label_len: usize) -> i32;
    pub fn verdict(
        kind: u32,
        label: *const u8,
        label_len: usize,
        detail: *const u8,
        detail_len: usize,
    ) -> i32;
    pub fn custom_op_begin(
        label: *const u8,
        label_len: usize,
        key: *const u8,
        key_len: usize,
        fault_eligible: i32,
        out_len: *mut usize,
    ) -> i32;
    pub fn custom_op_replay_result(out: *mut u8, out_cap: usize) -> i32;
    pub fn custom_op_record(result: *const u8, result_len: usize) -> i32;
}
