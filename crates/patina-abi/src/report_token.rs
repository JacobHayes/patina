//! Escaping for free-text fields inside Patina's one-line stderr reports.

/// Escape one field so it is a single token that holds no whitespace and no
/// `|`, and round-trips through [`unescape`]. Backslash is the escape
/// character; space, tab, CR, LF and `|` get named escapes, and any other
/// Unicode whitespace is written as `\u{<hex>}`. Everything else passes through
/// unchanged, so a label with no special characters reads exactly as written.
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ' ' => out.push_str("\\s"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '|' => out.push_str("\\p"),
            other if other.is_whitespace() => {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(other)));
            }
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
            'p' => out.push('|'),
            'u' => {
                if chars.next()? != '{' {
                    return None;
                }
                let mut hex = String::new();
                loop {
                    match chars.next()? {
                        '}' => break,
                        digit => hex.push(digit),
                    }
                }
                // Hex digits only: `from_str_radix` alone would also take a sign.
                if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return None;
                }
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Awkward fragments; the test joins every ordered pair and triple so each
    /// fragment meets every other at both ends.
    const FRAGMENTS: &[&str] = &[
        "",
        "plain",
        " ",
        "  two  spaces ",
        "\"quoted\"",
        "'single'",
        "k=v",
        "==",
        "a|b",
        "|",
        "line\nbreak",
        "\r\n",
        "\t",
        "back\\slash",
        "\\",
        "\\s",
        "\\u{20}",
        "naïve café",
        "日本語",
        "emoji 🦀",
        "\u{a0}nbsp",
        "\u{2003}em\u{3000}",
        "\u{200b}zero-width",
        "@src/main.rs:3",
    ];

    fn awkward_values() -> impl Iterator<Item = String> {
        FRAGMENTS.iter().flat_map(|a| {
            FRAGMENTS.iter().flat_map(move |b| {
                FRAGMENTS
                    .iter()
                    .map(move |c| format!("{a}{b}{c}"))
                    .chain(std::iter::once(format!("{a}{b}")))
            })
        })
    }

    #[test]
    fn every_awkward_value_escapes_to_one_separator_free_token_and_round_trips() {
        for value in awkward_values() {
            let escaped = escape(&value);
            assert!(
                !escaped.contains(|c: char| c.is_whitespace() || c == '|'),
                "escaped {value:?} as {escaped:?}, which still holds a separator"
            );
            assert_eq!(unescape(&escaped).as_deref(), Some(value.as_str()));
        }
    }

    #[test]
    fn malformed_escapes_are_refused() {
        for bad in [
            "x\\",
            "\\q",
            "\\u20",
            "\\u{}",
            "\\u{zz}",
            "\\u{d800}",
            "\\u{20",
            "\\u{+20}",
            "\\u{+1f980}",
            "\\u{-0}",
            "\\u{110000}",
        ] {
            assert_eq!(unescape(bad), None, "{bad:?} must not decode");
        }
    }
}
