//! The typed value grammars, one function per [`help::Kind`].
//!
//! The registry names a grammar; this module is what that name means. Every
//! value-bearing flag reaches its parser through the validator its declared
//! `Kind` selects here, so a flag cannot be validated by a grammar other than
//! the one its help advertises — the class of bug that shipped once as
//! `--sleep-jitter-nanos 0:N` documented against a parser that only accepted
//! `0..N`.
//!
//! Validators return the value's text unchanged. Converting that text into a
//! `u64`, a preopen, or a socket route is the caller's job; by then the grammar
//! is already guaranteed, so those conversions cannot fail.

use crate::help::Kind;
use crate::trace_view;

/// Validate `value` against `kind` on behalf of `name`, yielding the text
/// unchanged. The `Err` string is the message the user sees.
pub(crate) fn validate(kind: Kind, name: &str, value: &str) -> Result<(), String> {
    match kind {
        Kind::U64 => u64_of(name, value).map(drop),
        Kind::U32 => value
            .parse::<u32>()
            .map(drop)
            .map_err(|_| format!("{name} must be an unsigned 32-bit integer")),
        Kind::Usize => value
            .parse::<usize>()
            .map(drop)
            .map_err(|_| format!("{name} must be a non-negative integer")),
        Kind::PositiveU64 => match u64_of(name, value)? {
            0 => Err(format!("{name} must be >= 1")),
            _ => Ok(()),
        },
        Kind::Permille => match u64_of(name, value)? {
            0..=1000 => Ok(()),
            _ => Err(format!("{name} must be within [0, 1000]")),
        },
        Kind::NanosRange => range_of(name, value, "..").map(drop),
        Kind::U64Range => range_of(name, value, "..").map(drop),
        Kind::OpKindList => kind_list(value).map(drop),
        Kind::TaskSelector => match value {
            "main" => Ok(()),
            other => u64_of(name, other).map(drop),
        },
        Kind::CrashSpec => crash_spec(name, value),
        Kind::KeyValue => match value.split_once('=') {
            Some((key, _)) if !key.is_empty() => Ok(()),
            _ => Err(format!("{name} requires KEY=VALUE")),
        },
        Kind::DnsEntry => dns_entry(name, value).map(drop),
        Kind::Socket => socket(name, value).map(drop),
        Kind::Preopen => preopen(name, value).map(drop),
        Kind::UnsupportedSymbols => unsupported_symbols(name, value).map(drop),
        Kind::Enum(allowed) => {
            if allowed.contains(&value) {
                Ok(())
            } else {
                Err(format!(
                    "{name} must be one of {}; got {value:?}",
                    allowed.join("|")
                ))
            }
        }
        Kind::Symbol => {
            if value.is_empty() {
                Err(format!("{name} must not be empty"))
            } else {
                Ok(())
            }
        }
        // A path flag names a file or directory; the empty string names nothing,
        // and accepting it only defers the failure to a confusing I/O error
        // ("failed to read campaign spec : No such file or directory").
        Kind::Path => {
            if value.is_empty() {
                Err(format!("{name} must not be empty"))
            } else {
                Ok(())
            }
        }
        Kind::Str => Ok(()),
    }
}

fn u64_of(name: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned 64-bit integer"))
}

/// An inclusive `MIN..MAX` range with `MIN <= MAX`, shared by the nanosecond
/// jitter knobs and the trace sequence selector.
pub(crate) fn range_of(name: &str, value: &str, separator: &str) -> Result<(u64, u64), String> {
    let (min, max) = value
        .split_once(separator)
        .ok_or_else(|| format!("{name} must be a MIN..MAX range; got {value:?}"))?;
    let min = u64_of(name, min)?;
    let max = u64_of(name, max)?;
    if min > max {
        return Err(format!("{name} requires MIN <= MAX; got {value:?}"));
    }
    Ok((min, max))
}

fn crash_spec(name: &str, value: &str) -> Result<(), String> {
    let (op, ordinal) = value.split_once(':').unwrap_or((value, "1"));
    if !matches!(op, "open" | "write" | "sync" | "close") {
        return Err(format!(
            "{name} op must be open, write, sync, or close; got {op:?}"
        ));
    }
    match ordinal.parse::<u64>() {
        Ok(0) | Err(_) => Err(format!(
            "{name} ordinal must be a positive integer; got {value:?}"
        )),
        Ok(_) => Ok(()),
    }
}

/// A DNS host-table entry `NAME=IPV4`. The address half must be a dotted quad:
/// the virtual network's address space is IPv4 `ip:port` strings, and a name
/// pointed at something else would resolve to an address nothing can be bound
/// at — a failure the guest would meet as a confusing connect error rather than
/// as the typo it is.
pub(crate) fn dns_entry<'a>(name: &str, value: &'a str) -> Result<(&'a str, &'a str), String> {
    let Some((host, address)) = value.split_once('=') else {
        return Err(format!("{name} requires NAME=ADDR"));
    };
    if host.is_empty() {
        return Err(format!("{name} requires a non-empty NAME"));
    }
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4 || !octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        return Err(format!(
            "{name} requires NAME=ADDR with ADDR a dotted-quad IPv4 address; got {address:?}"
        ));
    }
    Ok((host, address))
}

/// A datagram socket route `FD=BIND->PEER`. Uniqueness of the FD across
/// repetitions is a cross-value rule the WASI parser still enforces.
pub(crate) fn socket<'a>(name: &str, value: &'a str) -> Result<(u32, &'a str, &'a str), String> {
    let (fd, route) = value
        .split_once('=')
        .ok_or_else(|| format!("{name} requires FD=BIND->PEER"))?;
    let fd = fd
        .parse::<u32>()
        .map_err(|_| format!("{name} FD must be an unsigned 32-bit integer"))?;
    let (bind, peer) = route
        .split_once("->")
        .ok_or_else(|| format!("{name} requires FD=BIND->PEER"))?;
    if fd <= 3 || bind.is_empty() || peer.is_empty() {
        return Err(format!(
            "{name} requires a unique FD above 3 and non-empty addresses"
        ));
    }
    Ok((fd, bind, peer))
}

/// A preopen `GUEST[:ro|:rw]`, split into its guest path and read-only flag.
pub(crate) fn preopen<'a>(name: &str, value: &'a str) -> Result<(&'a str, bool), String> {
    let (guest_path, read_only) = match value.rsplit_once(':') {
        Some((guest_path, "ro")) => (guest_path, true),
        Some((guest_path, "rw")) => (guest_path, false),
        Some(_) => return Err(format!("{name} requires GUEST, GUEST:ro, or GUEST:rw")),
        None => (value, false),
    };
    if guest_path.is_empty() {
        return Err(format!("{name} guest path must not be empty"));
    }
    Ok((guest_path, read_only))
}

/// `all`, or a comma-separated list of at least one non-empty symbol.
pub(crate) fn unsupported_symbols<'a>(
    name: &str,
    value: &'a str,
) -> Result<Option<Vec<&'a str>>, String> {
    if value == "all" {
        return Ok(None);
    }
    let symbols: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    if symbols.is_empty() {
        return Err(format!(
            "{name} requires `all` or a comma-separated symbol list"
        ));
    }
    Ok(Some(symbols))
}

/// A `--kind` list, split into operation tags and category labels.
pub(crate) fn kind_list(value: &str) -> Result<(Vec<&str>, Vec<trace_view::Category>), String> {
    let valid_kinds = trace_view::valid_op_kinds();
    let mut kinds = Vec::new();
    let mut categories = Vec::new();
    for token in value.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err("--kind entries must be non-empty".to_string());
        }
        if valid_kinds.contains(token) {
            kinds.push(token);
        } else if let Some(category) = trace_view::Category::parse_label(token) {
            categories.push(category);
        } else {
            let kind_list = valid_kinds.iter().copied().collect::<Vec<_>>().join(",");
            let category_list = trace_view::valid_category_labels()
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .join(",");
            return Err(format!(
                "unknown --kind token {token:?}; valid operation tags: {kind_list}; valid categories: {category_list}"
            ));
        }
    }
    if kinds.is_empty() && categories.is_empty() {
        return Err("--kind requires at least one entry".to_string());
    }
    Ok((kinds, categories))
}
