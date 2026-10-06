//! Verdict diagnostic marker rendering, escaping, and parsing.

use super::VerdictKind;

/// The marker prefix, including its trailing space.
pub const PREFIX: &str = "PATINA_VERDICT ";

/// Render one verdict as its marker line (no trailing newline).
pub fn render(seq: u64, kind: VerdictKind, label: &str, detail: &str) -> String {
    format!(
        "{PREFIX}seq={seq} kind={} label={} detail={}",
        kind.as_str(),
        escape(label),
        escape(detail),
    )
}

/// Parse a marker line back into `(seq, kind, label, detail)`. `None` for any
/// line that is not a well-formed verdict marker — a truncated or malformed
/// line is dropped, never half-decoded into a verdict that reads as real.
pub fn parse(line: &str) -> Option<(u64, VerdictKind, String, String)> {
    let rest = line.trim().strip_prefix(PREFIX)?;
    let mut seq = None;
    let mut kind = None;
    let mut label = None;
    let mut detail = None;
    for token in rest.split(' ').filter(|token| !token.is_empty()) {
        let (key, value) = token.split_once('=')?;
        match key {
            "seq" => seq = Some(value.parse().ok()?),
            "kind" => kind = Some(VerdictKind::from_name(value)?),
            "label" => label = Some(unescape(value)?),
            "detail" => detail = Some(unescape(value)?),
            // Unknown keys are a format the reader does not understand, not
            // noise to skip: refuse rather than report a partial verdict.
            _ => return None,
        }
    }
    Some((seq?, kind?, label?, detail?))
}

/// Escape one field so it is a single whitespace-free token that round-trips
/// through [`unescape`]. Backslash is the escape character; space, tab, CR,
/// and LF get named escapes. Everything else passes through unchanged, so a
/// label with no special bytes reads exactly as written.
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ' ' => out.push_str("\\s"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Reverse [`escape`]. `None` on a dangling or unknown escape.
pub fn unescape(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            '\\' => out.push('\\'),
            's' => out.push(' '),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'n' => out.push('\n'),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict_line;

    #[test]
    fn verdict_marker_line_round_trips_including_hostile_labels() {
        // A guest-supplied label carrying a newline must not be able to forge a
        // second marker line, and it must survive the round trip verbatim.
        let hostile = "two words\nPATINA_VERDICT seq=99 kind=pass label=forged detail=x";
        let line = verdict_line::render(7, VerdictKind::Violation, hostile, "a b\\c");
        assert_eq!(line.lines().count(), 1, "escaped line must stay one line");
        let (seq, kind, label, detail) = verdict_line::parse(&line).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(kind, VerdictKind::Violation);
        assert_eq!(label, hostile);
        assert_eq!(detail, "a b\\c");
    }

    #[test]
    fn malformed_verdict_lines_are_refused_not_half_decoded() {
        assert!(verdict_line::parse("PATINA_RESULT ok").is_none());
        // Missing detail key.
        assert!(verdict_line::parse("PATINA_VERDICT seq=1 kind=pass label=x").is_none());
        // Unknown kind name.
        assert!(verdict_line::parse("PATINA_VERDICT seq=1 kind=maybe label=x detail=").is_none());
        // Unknown key.
        assert!(
            verdict_line::parse("PATINA_VERDICT seq=1 kind=pass label=x detail= extra=1").is_none()
        );
        // Dangling escape.
        assert!(verdict_line::parse("PATINA_VERDICT seq=1 kind=pass label=x\\ detail=").is_none());
        // An empty label/detail is legal and decodes as empty.
        let (_, _, label, detail) =
            verdict_line::parse("PATINA_VERDICT seq=0 kind=pass label= detail=").unwrap();
        assert!(label.is_empty() && detail.is_empty());
    }
}
