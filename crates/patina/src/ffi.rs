//! Native shim ABI declarations.

unsafe extern "C" {
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
    pub fn patina_lifecycle_setup_complete() -> i32;
    pub fn patina_lifecycle_event(label: *const u8, label_len: usize) -> i32;
    pub fn patina_verdict(
        kind: u32,
        label: *const u8,
        label_len: usize,
        detail: *const u8,
        detail_len: usize,
    ) -> i32;
    pub fn patina_custom_op_begin(
        label: *const u8,
        label_len: usize,
        key: *const u8,
        key_len: usize,
        fault_eligible: i32,
        out_len: *mut usize,
    ) -> i32;
    pub fn patina_custom_op_replay_result(out: *mut u8, out_cap: usize) -> isize;
    pub fn patina_custom_op_record(result: *const u8, result_len: usize) -> i32;
}
