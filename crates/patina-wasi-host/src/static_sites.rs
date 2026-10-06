//! Embedded WebAssembly SDK site-table decoding and declaration.

use crate::sdk::patina_buggify_fatal;
use crate::{WasiHostError, WasiRunError};
use patina_dst_runtime::{BuggifyKind, Context, RuntimeError, SiteOutcome};

const PATINA_STATIC_SITE_SECTION: &str = "patina_sites";

const PATINA_STATIC_SITE_MAGIC: &[u8; 4] = b"PTS1";

const PATINA_STATIC_SITE_HEADER_LEN: usize = 14;

/// A malformed `patina_sites` custom section is a host-side configuration
/// failure: the module claims Patina SDK sites but cannot describe them.
fn static_site_error(message: String) -> WasiRunError {
    WasiRunError::Host(WasiHostError::from(RuntimeError::Config(message)))
}

pub(super) fn declare_wasm_static_sites(
    context: &mut Context,
    module_bytes: &[u8],
) -> Result<(), WasiRunError> {
    if module_bytes.len() < 8 || &module_bytes[..4] != b"\0asm" {
        return Ok(());
    }
    let mut cursor = 8;
    while cursor < module_bytes.len() {
        let section_id = module_bytes[cursor];
        cursor += 1;
        let section_size = read_wasm_uleb(module_bytes, &mut cursor)? as usize;
        let section_end = cursor.checked_add(section_size).ok_or_else(|| {
            static_site_error("WASM section size overflows module length".to_string())
        })?;
        if section_end > module_bytes.len() {
            return Err(static_site_error(
                "WASM section extends past end of module".to_string(),
            ));
        }
        if section_id == 0 {
            let mut body_cursor = cursor;
            let name_len = read_wasm_uleb(module_bytes, &mut body_cursor)? as usize;
            let name_end = body_cursor.checked_add(name_len).ok_or_else(|| {
                static_site_error("WASM custom-section name length overflows".to_string())
            })?;
            if name_end > section_end {
                return Err(static_site_error(
                    "WASM custom-section name extends past section".to_string(),
                ));
            }
            let name =
                std::str::from_utf8(&module_bytes[body_cursor..name_end]).map_err(|error| {
                    static_site_error(format!("WASM custom-section name is not UTF-8: {error}"))
                })?;
            if name == PATINA_STATIC_SITE_SECTION {
                parse_wasm_static_site_payload(context, &module_bytes[name_end..section_end])?;
            }
        }
        cursor = section_end;
    }
    Ok(())
}

fn read_wasm_uleb(module_bytes: &[u8], cursor: &mut usize) -> Result<u32, WasiRunError> {
    let mut result = 0_u32;
    let mut shift = 0_u32;
    loop {
        if *cursor >= module_bytes.len() {
            return Err(static_site_error(
                "truncated WASM section length".to_string(),
            ));
        }
        let byte = module_bytes[*cursor];
        *cursor += 1;
        if shift >= 32 {
            return Err(static_site_error(
                "WASM section length exceeds u32".to_string(),
            ));
        }
        result |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 35 {
            return Err(static_site_error(
                "malformed WASM section length".to_string(),
            ));
        }
    }
}

fn parse_wasm_static_site_payload(
    context: &mut Context,
    payload: &[u8],
) -> Result<(), WasiRunError> {
    let mut cursor = 0;
    while cursor < payload.len() {
        if payload.len() - cursor < PATINA_STATIC_SITE_HEADER_LEN {
            return Err(static_site_error(
                "truncated Patina WASM static site record".to_string(),
            ));
        }
        if &payload[cursor..cursor + 4] != PATINA_STATIC_SITE_MAGIC {
            return Err(static_site_error(
                "malformed Patina WASM static site record magic".to_string(),
            ));
        }
        let kind = BuggifyKind::from_static_site_kind(payload[cursor + 4]).ok_or_else(|| {
            static_site_error(format!(
                "Patina WASM static site record has unknown kind {}",
                payload[cursor + 4]
            ))
        })?;
        let flags = payload[cursor + 5];
        if flags != 0 {
            return Err(static_site_error(format!(
                "Patina WASM static site record has unsupported flags {flags}"
            )));
        }
        let label_len = u32::from_le_bytes(
            payload[cursor + 6..cursor + 10]
                .try_into()
                .expect("fixed label length field"),
        ) as usize;
        let site_len = u32::from_le_bytes(
            payload[cursor + 10..cursor + 14]
                .try_into()
                .expect("fixed site length field"),
        ) as usize;
        let label_start = cursor + PATINA_STATIC_SITE_HEADER_LEN;
        let site_start = label_start.checked_add(label_len).ok_or_else(|| {
            static_site_error("Patina WASM static site label length overflows".to_string())
        })?;
        let next = site_start.checked_add(site_len).ok_or_else(|| {
            static_site_error("Patina WASM static site identity length overflows".to_string())
        })?;
        if next > payload.len() {
            return Err(static_site_error(
                "Patina WASM static site record extends past section".to_string(),
            ));
        }
        let label = std::str::from_utf8(&payload[label_start..site_start]).map_err(|error| {
            static_site_error(format!(
                "Patina WASM static site label is not valid UTF-8: {error}"
            ))
        })?;
        let site = std::str::from_utf8(&payload[site_start..next]).map_err(|error| {
            static_site_error(format!(
                "Patina WASM static site identity is not valid UTF-8: {error}"
            ))
        })?;
        let outcome = context
            .declare_static_site(label, site, kind)
            .map_err(|error| static_site_error(error.to_string()))?;
        if outcome == SiteOutcome::DuplicateLabel {
            return Err(WasiRunError::Engine(patina_buggify_fatal(
                "PATINA_BUGGIFY_DUPLICATE_LABEL",
                label,
            )));
        }
        cursor = next;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use patina_dst_runtime::RuntimeConfig;

    /// Encode one `patina_sites` record the way the SDK macro does, so the
    /// duplicate-label mapping below is gated on the real record layout.
    fn static_site_record(kind: u8, label: &str, site: &str) -> Vec<u8> {
        let mut record = PATINA_STATIC_SITE_MAGIC.to_vec();
        record.push(kind);
        record.push(0);
        record.extend_from_slice(&(label.len() as u32).to_le_bytes());
        record.extend_from_slice(&(site.len() as u32).to_le_bytes());
        assert_eq!(record.len(), PATINA_STATIC_SITE_HEADER_LEN);
        record.extend_from_slice(label.as_bytes());
        record.extend_from_slice(site.as_bytes());
        record
    }

    // A link-time site table that binds one label to two call sites is the same
    // fatal duplicate the evaluation path rejects, and must surface the SAME
    // named marker rather than a generic host configuration failure.
    #[test]
    fn wasm_static_site_duplicate_label_reports_the_duplicate_marker() {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let mut payload = static_site_record(6, "dup", "src/main.rs:3");
        payload.extend(static_site_record(6, "dup", "src/main.rs:4"));
        let error = parse_wasm_static_site_payload(&mut context, &payload)
            .expect_err("a duplicate link-time label must fail closed");
        assert!(
            error
                .to_string()
                .contains("PATINA_BUGGIFY_DUPLICATE_LABEL label=dup"),
            "expected the named duplicate marker, got: {error}"
        );
    }

    // The same table without a conflict declares the site without evaluating it.
    #[test]
    fn wasm_static_site_table_declares_without_registering() {
        let mut context = Context::from_config(RuntimeConfig::seeded(1)).unwrap();
        let payload = static_site_record(6, "never", "src/main.rs:9");
        parse_wasm_static_site_payload(&mut context, &payload).unwrap();
        let diagnostics = context.buggify_diagnostics();
        assert_eq!(diagnostics.sites_registered, 0);
        assert_eq!(diagnostics.declared_sites.len(), 1);
        assert_eq!(diagnostics.declared_sites[0].label, "never");
    }
}
