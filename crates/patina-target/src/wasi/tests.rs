//! WASI import metadata and fail-closed import auditing tests.

use super::*;
use crate::TargetError;
use crate::tests::module_importing;

#[test]
fn accepts_supported_preview1_imports() {
    let bytes = module_importing(WASI_PREVIEW1_MODULE, "random_get");
    let audit = WasiAudit::audit(&bytes).unwrap();
    assert_eq!(audit.imports[0].name, "random_get");
}

#[test]
fn rejects_unknown_modules_and_unsupported_wasi_calls() {
    let host = WasiAudit::audit(&module_importing("host", "escape")).unwrap_err();
    assert!(matches!(host, TargetError::UnsupportedImports(_)));
    let wasi = WasiAudit::audit(&module_importing(
        WASI_PREVIEW1_MODULE,
        "nonexistent_import",
    ))
    .unwrap_err();
    assert!(wasi.to_string().contains("nonexistent_import"));
}
