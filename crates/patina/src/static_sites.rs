//! Link-time SDK site descriptors.

/// Link-time SDK site descriptor emitted by literal-label SDK macro calls in
/// Patina builds. Embedders enumerate the `patina_sites` linker
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
