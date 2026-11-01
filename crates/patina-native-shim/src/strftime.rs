//! `strftime` in the C locale: glibc 2.39's conversions (time/strftime_l.c),
//! over a broken-down time the caller owns.
//!
//! The run never leaves the C locale (the shim's `setlocale` answers only
//! it), so every name is the C locale's and `%E`/`%O` are plain. The two
//! conversions that read time-zone state answer from the shim's zone model,
//! as glibc answers from its own: `%Z` on a time with no zone name names the
//! zone's standard or daylight half (glibc's `tzname`), and `%s` is the
//! model's `mktime`. Formatting is generic over the code unit, so `wcsftime`
//! is the same formatter over `wchar_t`, but for `%Z` (see [`Unit`]). Output
//! is bounded as it is produced: a result that would not fit stops there.

/// The broken-down time a conversion reads (`struct tm`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tm {
    pub(crate) sec: i32,
    pub(crate) min: i32,
    pub(crate) hour: i32,
    pub(crate) mday: i32,
    pub(crate) mon: i32,
    pub(crate) year: i32,
    pub(crate) wday: i32,
    pub(crate) yday: i32,
    pub(crate) isdst: i32,
    pub(crate) gmtoff: i64,
}

/// What `%Z` and `%s` read beyond the time's fields.
pub(crate) trait Zone {
    /// The time's own zone name (`tm_zone`), if any: read only for `%Z`, as
    /// glibc reads it.
    fn own_name(&self) -> Option<Vec<u8>>;
    /// The zone half's name `tzname[isdst]`, for a time with no zone name.
    fn name(&self, isdst: bool) -> Vec<u8>;
    /// `mktime` of the time.
    fn mktime(&self, tm: &Tm) -> i64;
}

const TM_YEAR_BASE: i64 = 1900;
const DAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// glibc's `iso_week_days`: the days since the Monday starting the ISO
/// week-numbering year of a day `yday` that is a `wday`.
fn iso_week_days(yday: i64, wday: i64) -> i64 {
    const BIG_ENOUGH_MULTIPLE_OF_7: i64 = (366 / 7 + 2) * 7;
    yday - (yday - wday + 4 + BIG_ENOUGH_MULTIPLE_OF_7) % 7 + 4 - 1
}

/// A formatter code unit: a byte (`strftime`) or a wide character
/// (`wcsftime`).
pub(crate) trait Unit: Copy + From<u8> + Into<u32> {
    /// glibc's wide `%Z`: the zone name converted from multibyte (in the C
    /// locale, ASCII only: anything else is `EILSEQ`), copied without the
    /// case flags, and unpadded under `-`.
    const WIDE: bool;
}

impl Unit for u8 {
    const WIDE: bool = false;
}

/// Why a time does not format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The result does not fit the bound.
    Overflow,
    /// A wide `%Z` of a zone name with no wide form (`EILSEQ`).
    Ilseq,
}

impl<U: Unit> Out<'_, U> {
    /// glibc's `bad_format`: a conversion it does not know, copied as it
    /// stands but padded and cased like any other text.
    fn verbatim(&mut self, spec: Spec, units: &[U]) -> Result<(), Failure> {
        let width = spec.width.unwrap_or(0);
        if width > units.len() {
            self.pad(width - units.len(), spec.pad == b'0')?;
        }
        for &unit in units {
            let upper = u8::try_from(unit.into())
                .ok()
                .filter(|byte| spec.upcase && byte.is_ascii_lowercase());
            self.push(upper.map_or(unit, |byte| U::from(byte.to_ascii_uppercase())))?;
        }
        Ok(())
    }
}

/// A conversion's flags and width.
#[derive(Clone, Copy, Default)]
struct Spec {
    /// `_`, `-`, `0` or `+`, or 0 for none.
    pad: u8,
    upcase: bool,
    swapcase: bool,
    width: Option<usize>,
}

struct Out<'a, U> {
    buf: &'a mut Vec<U>,
    /// The most units the result may hold.
    limit: usize,
}

impl<U: Unit> Out<'_, U> {
    fn room(&self, count: usize) -> Result<(), Failure> {
        if count > self.limit - self.buf.len() {
            return Err(Failure::Overflow);
        }
        Ok(())
    }

    fn push(&mut self, unit: U) -> Result<(), Failure> {
        self.room(1)?;
        self.buf.push(unit);
        Ok(())
    }

    fn pad(&mut self, count: usize, zero: bool) -> Result<(), Failure> {
        self.room(count)?;
        let fill = U::from(if zero { b'0' } else { b' ' });
        self.buf.extend(std::iter::repeat_n(fill, count));
        Ok(())
    }

    /// glibc's `add`: `text`, padded first to `width` (with zeros under the
    /// `0` flag, spaces otherwise), cased by the flags.
    fn add(&mut self, spec: Spec, width: usize, text: &[u8], lower: bool) -> Result<(), Failure> {
        if width > text.len() {
            self.pad(width - text.len(), spec.pad == b'0')?;
        }
        self.room(text.len())?;
        for &byte in text {
            let byte = if spec.upcase {
                byte.to_ascii_uppercase()
            } else if lower {
                byte.to_ascii_lowercase()
            } else {
                byte
            };
            self.buf.push(U::from(byte));
        }
        Ok(())
    }

    fn text(&mut self, spec: Spec, text: &[u8], lower: bool) -> Result<(), Failure> {
        self.add(spec, spec.width.unwrap_or(0), text, lower)
    }

    /// glibc's `DO_NUMBER`: `value` padded to `digits`, then to the width,
    /// each counting its sign: with zeros after the sign (by default, or
    /// under `0`), or spaces before it (under `_`, for a space-padded
    /// conversion, or for the width under `-`, which pads no digits).
    fn number(
        &mut self,
        spec: Spec,
        digits: usize,
        value: i64,
        spacepad: bool,
    ) -> Result<(), Failure> {
        let pad = match spec.pad {
            0 if spacepad => b'_',
            0 => b'0',
            pad => pad,
        };
        let text = value.unsigned_abs().to_string().into_bytes();
        let sign = usize::from(value < 0);
        let digits = if pad == b'-' { 0 } else { digits };
        let (mut spaces, mut zeros) = (0, 0);
        let filled = |length: usize, target: usize| target.saturating_sub(length);
        match pad {
            b'_' => spaces += filled(sign + text.len(), digits),
            b'-' => {}
            _ => zeros += filled(sign + text.len(), digits),
        }
        let width = filled(sign + zeros + spaces + text.len(), spec.width.unwrap_or(0));
        if pad == b'0' {
            zeros += width;
        } else {
            spaces += width;
        }
        self.pad(spaces, false)?;
        if sign == 1 {
            self.push(U::from(b'-'))?;
        }
        self.pad(zeros, true)?;
        self.add(Spec { pad, ..spec }, 0, &text, false)
    }
}

/// Format `format` for `tm` into at most `limit` units. Every conversion
/// glibc does not know is copied through, as glibc copies it.
pub(crate) fn format<U: Unit>(
    format: &[U],
    tm: &Tm,
    zone: &dyn Zone,
    limit: usize,
) -> Result<Vec<U>, Failure> {
    let mut formatted = Vec::new();
    let mut out = Out {
        buf: &mut formatted,
        limit,
    };
    let byte = |unit: U| u8::try_from(unit.into()).ok();
    let mut index = 0;
    while index < format.len() {
        let unit = format[index];
        if byte(unit) != Some(b'%') {
            out.push(unit)?;
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        let mut spec = Spec::default();
        while let Some(flag) = format.get(index).copied().and_then(byte) {
            match flag {
                b'_' | b'-' | b'0' => spec.pad = flag,
                b'^' => spec.upcase = true,
                b'#' => spec.swapcase = true,
                _ => break,
            }
            index += 1;
        }
        let mut width: Option<usize> = None;
        while let Some(digit) = format
            .get(index)
            .copied()
            .and_then(byte)
            .filter(u8::is_ascii_digit)
        {
            width = Some(
                width
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(usize::from(digit - b'0')),
            );
            index += 1;
        }
        spec.width = width;
        // The C locale's alternative representations are the plain ones.
        let modifier = format
            .get(index)
            .copied()
            .and_then(byte)
            .filter(|m| matches!(m, b'E' | b'O'));
        if modifier.is_some() {
            index += 1;
        }
        let Some(conversion) = format.get(index).copied() else {
            // A trailing `%...`: copied as it stands.
            out.verbatim(spec, &format[start..])?;
            break;
        };
        index += 1;
        // glibc copies a modifier its conversion does not take as it stands;
        // these are the conversions glibc 2.39 lets each modifier through to.
        let modified = match modifier {
            Some(b'E') => b"%CPRTXYZcnprstuxyz".as_slice(),
            Some(_) => b"%BCGHIMPRSTUVWZbdeghjklmnprstuwyz".as_slice(),
            None => b"".as_slice(),
        };
        if modifier.is_some() && !byte(conversion).is_some_and(|c| modified.contains(&c)) {
            out.verbatim(spec, &format[start..index])?;
            continue;
        }
        let year = i64::from(tm.year) + TM_YEAR_BASE;
        let hour12 = (i64::from(tm.hour) + 11) % 12 + 1;
        let name = |names: &[&'static str], at: i32, abbreviated: bool| -> Vec<u8> {
            usize::try_from(at)
                .ok()
                .and_then(|at| names.get(at))
                .map_or(b"?".to_vec(), |full| {
                    if abbreviated {
                        full.as_bytes()[..3].to_vec()
                    } else {
                        full.as_bytes().to_vec()
                    }
                })
        };
        // A composite conversion, formatted by itself (glibc's `subfmt`).
        let composite = |out: &mut Out<'_, U>, sub: &str| {
            let units: Vec<U> = sub.bytes().map(U::from).collect();
            let text = self::format(&units, tm, zone, out.limit - out.buf.len())?;
            let bytes: Vec<u8> = text.iter().filter_map(|unit| byte(*unit)).collect();
            out.text(spec, &bytes, false)
        };
        let upper = Spec {
            upcase: spec.upcase || spec.swapcase,
            ..spec
        };
        // `#` lower-cases `%p` and `%Z`, whatever `^` says.
        let lower = Spec {
            upcase: spec.upcase && !spec.swapcase,
            ..spec
        };
        match byte(conversion) {
            Some(b'%') => out.text(spec, b"%", false),
            Some(b'n') => out.text(spec, b"\n", false),
            Some(b't') => out.text(spec, b"\t", false),
            // `#` upper-cases the day and month names.
            Some(b'a') => out.text(upper, &name(&DAYS, tm.wday, true), false),
            Some(b'A') => out.text(upper, &name(&DAYS, tm.wday, false), false),
            Some(b'b' | b'h') => out.text(upper, &name(&MONTHS, tm.mon, true), false),
            Some(b'B') => out.text(upper, &name(&MONTHS, tm.mon, false), false),
            Some(b'c') => composite(&mut out, "%a %b %e %H:%M:%S %Y"),
            Some(b'D' | b'x') => composite(&mut out, "%m/%d/%y"),
            Some(b'F') => composite(&mut out, "%Y-%m-%d"),
            Some(b'r') => composite(&mut out, "%I:%M:%S %p"),
            Some(b'R') => composite(&mut out, "%H:%M"),
            Some(b'T' | b'X') => composite(&mut out, "%H:%M:%S"),
            Some(b'C') => out.number(spec, 1, year / 100 - i64::from(year % 100 < 0), false),
            // The year's last two digits, as of a year before the epoch too.
            Some(b'y') => out.number(spec, 2, year.rem_euclid(100), false),
            Some(b'Y') => out.number(spec, 1, year, false),
            Some(b'd') => out.number(spec, 2, i64::from(tm.mday), false),
            Some(b'e') => out.number(spec, 2, i64::from(tm.mday), true),
            Some(b'H') => out.number(spec, 2, i64::from(tm.hour), false),
            Some(b'k') => out.number(spec, 2, i64::from(tm.hour), true),
            Some(b'I') => out.number(spec, 2, hour12, false),
            Some(b'l') => out.number(spec, 2, hour12, true),
            Some(b'j') => out.number(spec, 3, i64::from(tm.yday) + 1, false),
            Some(b'm') => out.number(spec, 2, i64::from(tm.mon) + 1, false),
            Some(b'M') => out.number(spec, 2, i64::from(tm.min), false),
            Some(b'S') => out.number(spec, 2, i64::from(tm.sec), false),
            Some(b'u') => out.number(spec, 1, (i64::from(tm.wday) + 6) % 7 + 1, false),
            Some(b'w') => out.number(spec, 1, i64::from(tm.wday), false),
            Some(b'U') => out.number(
                spec,
                2,
                (i64::from(tm.yday) - i64::from(tm.wday) + 7) / 7,
                false,
            ),
            Some(b'W') => out.number(
                spec,
                2,
                (i64::from(tm.yday) - (i64::from(tm.wday) - 1 + 7) % 7 + 7) / 7,
                false,
            ),
            Some(b'p' | b'P') => {
                let text: &[u8] = if tm.hour > 11 { b"PM" } else { b"AM" };
                let lowered = byte(conversion) == Some(b'P') || spec.swapcase;
                out.text(if spec.swapcase { lower } else { spec }, text, lowered)
            }
            Some(b'g' | b'G' | b'V') => {
                let yday = i64::from(tm.yday);
                let wday = i64::from(tm.wday);
                let mut adjust = 0;
                let mut days = iso_week_days(yday, wday);
                if days < 0 {
                    adjust = -1;
                    days = iso_week_days(yday + 365 + i64::from(is_leap(year - 1)), wday);
                } else {
                    let next = iso_week_days(yday - (365 + i64::from(is_leap(year))), wday);
                    if next >= 0 {
                        adjust = 1;
                        days = next;
                    }
                }
                match byte(conversion) {
                    Some(b'g') => out.number(spec, 2, (year + adjust).rem_euclid(100), false),
                    Some(b'G') => out.number(spec, 1, year + adjust, false),
                    _ => out.number(spec, 2, days / 7 + 1, false),
                }
            }
            Some(b's') => out.number(spec, 1, zone.mktime(tm), false),
            Some(b'z') => {
                if tm.isdst >= 0 {
                    // The sign is its own padded `add`, as glibc writes it.
                    let sign: &[u8] = if tm.gmtoff < 0 { b"-" } else { b"+" };
                    out.text(spec, sign, false)?;
                    let minutes = tm.gmtoff.abs() / 60;
                    out.number(spec, 4, minutes / 60 * 100 + minutes % 60, false)?;
                }
                Ok(())
            }
            Some(b'Z') => {
                let name = match zone.own_name().filter(|name| !name.is_empty()) {
                    Some(name) => name,
                    None if tm.isdst == 0 || tm.isdst == 1 => zone.name(tm.isdst == 1),
                    None if tm.isdst > 1 => b"?".to_vec(),
                    None => Vec::new(),
                };
                if !U::WIDE {
                    out.text(lower, &name, spec.swapcase)
                } else if !name.is_ascii() {
                    Err(Failure::Ilseq)
                } else {
                    let width = if spec.pad == b'-' {
                        0
                    } else {
                        spec.width.unwrap_or(0)
                    };
                    let plain = Spec {
                        upcase: false,
                        ..spec
                    };
                    out.add(plain, width, &name, false)
                }
            }
            _ => out.verbatim(spec, &format[start..index]),
        }?;
    }
    Ok(formatted)
}

#[cfg(test)]
mod tests;
