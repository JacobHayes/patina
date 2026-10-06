//! Native site descriptors and WASM static site encoding.

/// Link-time SDK site descriptor emitted by literal-label SDK macro calls in
/// native Patina builds. Embedders enumerate the `patina_sites` linker
/// section before the guest runs, so never-reached sites can still appear in
/// runtime-joined reports without constructors or external dependencies.
#[repr(C)]
pub struct StaticSiteDescriptor {
    pub label_ptr: *const u8,
    pub label_len: usize,
    pub site_ptr: *const u8,
    pub site_len: usize,
    pub kind: u8,
    pub _reserved: [u8; 7],
}

// SAFETY: descriptors point at immutable string literals and are never
// mutated; sharing them between threads is safe.
unsafe impl Sync for StaticSiteDescriptor {}

impl StaticSiteDescriptor {
    pub const fn new(label: &'static str, site: &'static str, kind: u8) -> Self {
        Self {
            label_ptr: label.as_ptr(),
            label_len: label.len(),
            site_ptr: site.as_ptr(),
            site_len: site.len(),
            kind,
            _reserved: [0; 7],
        }
    }
}

pub const STATIC_SITE_KIND_FAULT: u8 = 1;
pub const STATIC_SITE_KIND_DELAY: u8 = 2;
pub const STATIC_SITE_KIND_KNOB: u8 = 3;
pub const STATIC_SITE_KIND_ALWAYS: u8 = 4;
pub const STATIC_SITE_KIND_SOMETIMES: u8 = 5;
pub const STATIC_SITE_KIND_REACHABLE: u8 = 6;

pub const WASM_STATIC_SITE_RECORD_HEADER_LEN: usize = 14;

pub const fn wasm_static_site_len(label: &str, site: &str) -> usize {
    WASM_STATIC_SITE_RECORD_HEADER_LEN + label.len() + site.len()
}

/// Encode one WASM `patina_sites` custom-section record. The wasm target
/// rejects custom-section statics with relocations, so wasm descriptors are
/// self-contained bytes rather than native pointer records.
pub const fn encode_wasm_static_site<const N: usize>(kind: u8, label: &str, site: &str) -> [u8; N] {
    let label_bytes = label.as_bytes();
    let site_bytes = site.as_bytes();
    let label_len = label_bytes.len() as u32;
    let site_len = site_bytes.len() as u32;
    let mut out = [0_u8; N];
    out[0] = b'P';
    out[1] = b'T';
    out[2] = b'S';
    out[3] = b'1';
    out[4] = kind;
    out[5] = 0;
    out[6] = (label_len & 0xff) as u8;
    out[7] = ((label_len >> 8) & 0xff) as u8;
    out[8] = ((label_len >> 16) & 0xff) as u8;
    out[9] = ((label_len >> 24) & 0xff) as u8;
    out[10] = (site_len & 0xff) as u8;
    out[11] = ((site_len >> 8) & 0xff) as u8;
    out[12] = ((site_len >> 16) & 0xff) as u8;
    out[13] = ((site_len >> 24) & 0xff) as u8;

    let mut cursor = WASM_STATIC_SITE_RECORD_HEADER_LEN;
    let mut i = 0;
    while i < label_bytes.len() {
        out[cursor] = label_bytes[i];
        cursor += 1;
        i += 1;
    }
    i = 0;
    while i < site_bytes.len() {
        out[cursor] = site_bytes[i];
        cursor += 1;
        i += 1;
    }
    out
}
