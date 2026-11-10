//! `localtime_r`: glibc's time zone (time/tzset.c, time/offtime.c, glibc
//! 2.39) over the virtual machine.
//!
//! glibc reads `TZ` the first time `localtime_r` runs and keeps the answer
//! (`tzset_internal` with `always` 0); `tzset`, `mktime` and `strftime`'s
//! `%Z` read it again when it changed (`always` 1), and so does [`current`].
//! Reading it:
//!
//! * unset `TZ` names the default file `/etc/localtime`, an empty one names
//!   UTC, a leading `:` is dropped, and a name without a leading `/` is looked
//!   up under `TZDIR` (default `/usr/share/zoneinfo`);
//! * the virtual machine ships no time zone database, so that file normally
//!   does not exist, and glibc then parses `TZ` as a POSIX rule string
//!   (`XST5XDT,M3.2.0,M11.1.0`, `<+0530>-5:30`, …), or answers UTC for the
//!   default file or an empty name. A guest that PUT a zoneinfo (TZif) file
//!   where glibc would read it is refused by name: those files are not
//!   modeled, and a silently different zone would be the worse answer;
//! * the conversion is `__offtime` plus `__tz_compute`: the UTC year fixes
//!   the year's two transition instants, the instant picks standard or
//!   daylight time, and a year that does not fit `int` is `EOVERFLOW`.
//!
//! The answers are pure functions of the time, the environment and the
//! deterministic filesystem, so nothing is recorded.

use std::ffi::{CStr, CString, c_char, c_int};

use crate::SpinMutex;

const SECS_PER_DAY: i64 = 86_400;
/// glibc's `TZDEFAULT` and `TZDIR` on Ubuntu 24.04.
const TZ_DEFAULT: &str = "/etc/localtime";
const TZ_DIR: &str = "/usr/share/zoneinfo";
const EOVERFLOW: c_int = 75;

/// When in the year a transition happens (`tz_rule::type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// `n`: day of the year, 0-based, leap days counted.
    J0,
    /// `Jn`: day of the year, 1-based, February 29 never counted.
    J1,
    /// `Mm.n.d`: day `d` of week `n` of month `m`.
    M,
}

/// One half of the zone (`tz_rule`): standard time (0) or daylight time (1),
/// with the transition INTO it.
#[derive(Clone, Copy, Debug)]
struct Rule {
    name: &'static CStr,
    /// Seconds east of UTC.
    offset: i64,
    kind: Kind,
    m: u16,
    n: u16,
    d: u16,
    /// Local time of day of the transition, seconds.
    secs: i64,
}

impl Default for Rule {
    fn default() -> Self {
        Rule {
            name: c"",
            offset: 0,
            kind: Kind::J0,
            m: 0,
            n: 0,
            d: 0,
            secs: 0,
        }
    }
}

/// The zone `TZ` chose.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Zone {
    rules: [Rule; 2],
}

/// A zoneinfo file glibc would read, which the model refuses to guess at.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ZoneFile(pub(crate) String);

/// The broken-down time the C layer copies into `struct tm`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatinaTm {
    pub sec: c_int,
    pub min: c_int,
    pub hour: c_int,
    pub mday: c_int,
    pub mon: c_int,
    pub year: c_int,
    pub wday: c_int,
    pub yday: c_int,
    pub isdst: c_int,
    pub gmtoff: i64,
    pub zone: *const c_char,
}

impl Default for PatinaTm {
    fn default() -> Self {
        PatinaTm {
            sec: 0,
            min: 0,
            hour: 0,
            mday: 0,
            mon: 0,
            year: 0,
            wday: 0,
            yday: 0,
            isdst: 0,
            gmtoff: 0,
            zone: std::ptr::null(),
        }
    }
}

/// A zone name kept for the life of the process (`__tzstring`).
fn intern(name: &[u8]) -> &'static CStr {
    let name = CString::new(name).unwrap_or_default();
    Box::leak(name.into_boxed_c_str())
}

/// `t` broken down in UTC, as `gmtime_r` answers with no leap seconds: its
/// zone name is "GMT", as glibc's. `EOVERFLOW` for a year past `int`.
#[cfg(patina_posix_exports)]
pub(crate) fn universal(t: i64) -> Result<PatinaTm, c_int> {
    utc(c"GMT").local(t)
}

fn utc(name: &'static CStr) -> Zone {
    let rule = Rule {
        name,
        ..Rule::default()
    };
    Zone {
        rules: [rule, rule],
    }
}

impl Zone {
    /// The zone `TZ` (and `TZDIR`) name (`tzset_internal`); `is_file` says
    /// whether the deterministic filesystem holds a regular file at a path.
    pub(crate) fn choose(
        tz: Option<&[u8]>,
        tzdir: Option<&[u8]>,
        is_file: impl Fn(&str) -> bool,
    ) -> Result<Zone, ZoneFile> {
        let mut tz = tz.map(|tz| if tz.is_empty() { &b"Universal"[..] } else { tz });
        if let Some(rest) = tz.and_then(|tz| tz.strip_prefix(b":")) {
            tz = Some(rest);
        }
        // `__tzfile_read`: which file glibc would open.
        let file = match tz {
            None => Some(TZ_DEFAULT.to_owned()),
            Some([]) => None,
            Some(name) if name.starts_with(b"/") => {
                Some(String::from_utf8_lossy(name).into_owned())
            }
            Some(name) => {
                let dir = tzdir
                    .filter(|dir| !dir.is_empty())
                    .map_or(TZ_DIR.into(), String::from_utf8_lossy);
                Some(format!("{dir}/{}", String::from_utf8_lossy(name)))
            }
        };
        if let Some(file) = file.filter(|file| is_file(file)) {
            return Err(ZoneFile(file));
        }
        Ok(match tz {
            None | Some([]) => utc(c"UTC"),
            Some(name) if name == TZ_DEFAULT.as_bytes() => utc(c"UTC"),
            Some(name) => Zone::parse(name),
        })
    }

    /// `__tzset_parse_tz`: a POSIX rule string, whatever of it parses.
    fn parse(mut tz: &[u8]) -> Zone {
        let mut zone = utc(c"");
        if parse_name(&mut tz, &mut zone.rules[0]) && parse_offset(&mut tz, &mut zone.rules, 0) {
            if tz.is_empty() {
                zone.rules[1].name = zone.rules[0].name;
                zone.rules[1].offset = zone.rules[0].offset;
            } else {
                if parse_name(&mut tz, &mut zone.rules[1]) {
                    parse_offset(&mut tz, &mut zone.rules, 1);
                    // No rule: glibc would read TZDIR/posixrules, which the
                    // virtual machine does not ship, and falls back to the
                    // US rules below.
                }
                if parse_rule(&mut tz, &mut zone.rules[0], 0) {
                    parse_rule(&mut tz, &mut zone.rules[1], 1);
                }
            }
        }
        zone
    }

    /// `__tz_convert` for `localtime_r`: the local broken-down time of `t`.
    pub(crate) fn local(&self, t: i64) -> Result<PatinaTm, c_int> {
        let utc = offtime(t, 0)?;
        let year = utc.year.wrapping_add(1900);
        let start = change(&self.rules[0], year);
        let end = change(&self.rules[1], year);
        // The southern hemisphere's daylight time spans the new year.
        let isdst = if start > end {
            t < end || t >= start
        } else {
            t >= start && t < end
        };
        let rule = &self.rules[usize::from(isdst)];
        let mut tm = offtime(t, rule.offset)?;
        tm.isdst = c_int::from(isdst);
        tm.gmtoff = rule.offset;
        tm.zone = rule.name.as_ptr();
        Ok(tm)
    }
}

// The tzname face, for strftime's door.
#[cfg(patina_posix_exports)]
impl Zone {
    /// The name of standard (`isdst` false) or daylight time (`tzname`).
    pub(crate) fn name(&self, isdst: bool) -> &'static CStr {
        self.rules[usize::from(isdst)].name
    }
}

// The mktime face, for the posix doors.
#[cfg(any(all(test, target_os = "linux"), patina_posix_exports))]
impl Zone {
    /// `mktime` (`__mktime_internal`): the instant whose local time is `tm`'s
    /// fields (each may be out of range, and is carried into the next), and
    /// that instant broken down again. `tm.isdst` positive or zero reads the
    /// fields as daylight or standard time, as glibc does, even where that
    /// time is not in effect (lending the offset of the nearest time it is);
    /// negative asks the zone. A time the zone skips or repeats reads as the
    /// time asked for, and otherwise as standard time: glibc's answer there
    /// turns on its previous calls. `EOVERFLOW` when the instant or its year does
    /// not fit.
    pub(crate) fn mktime(&self, tm: &PatinaTm) -> Result<(i64, PatinaTm), c_int> {
        let floor_div = |a: i64, b: i64| a.div_euclid(b);
        // glibc searches with the seconds held to a minute (a leap second
        // may matter there) and adds the rest back after.
        let clamped = tm.sec.clamp(0, 59);
        let mon = i64::from(tm.mon);
        let year = i64::from(tm.year) + 1900 + floor_div(mon, 12);
        let mon = mon.rem_euclid(12);
        // Days from 1970-01-01 to the first of the month (civil-from-days
        // inverted, with March-based years).
        let (y, m) = if mon < 2 {
            (year - 1, mon + 10)
        } else {
            (year, mon - 2)
        };
        let era = floor_div(y, 400);
        let yoe = y - era * 400;
        let doy = (153 * m + 2) / 5;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe - 719_468 + i64::from(tm.mday) - 1;
        let local = days
            .checked_mul(SECS_PER_DAY)
            .and_then(|secs| secs.checked_add(i64::from(tm.hour) * 3600))
            .and_then(|secs| secs.checked_add(i64::from(tm.min) * 60))
            .and_then(|secs| secs.checked_add(i64::from(clamped)))
            .ok_or(EOVERFLOW)?;
        let reading = |isdst: bool| {
            local
                .checked_sub(self.rules[usize::from(isdst)].offset)
                .ok_or(EOVERFLOW)
        };
        let isdst_of = |t: i64| self.local(t).map(|tm| tm.isdst != 0);
        let standard = reading(false)?;
        let daylight = reading(true)?;
        // The reading the zone agrees with: standard time first, and standard
        // time again for a time the zone skips.
        let natural = if !isdst_of(standard)? {
            standard
        } else if isdst_of(daylight)? {
            daylight
        } else {
            standard
        };
        let t = match tm.isdst {
            isdst if isdst < 0 => natural,
            isdst => {
                let want = isdst > 0;
                let wanted = reading(want)?;
                if isdst_of(wanted)? == want {
                    wanted
                } else {
                    // glibc's search: the nearest time, a week apart either
                    // way out to some seven years, whose `isdst` is the one
                    // asked for lends its offset; with none, daylight time is
                    // taken to be an hour ahead.
                    const STRIDE: i64 = 601_200;
                    const BOUND: i64 = 457_243_200 / 2 + STRIDE;
                    let found = (1..)
                        .map(|step| step * STRIDE)
                        .take_while(|delta| *delta < BOUND)
                        .flat_map(|delta| [natural.checked_sub(delta), natural.checked_add(delta)])
                        .flatten()
                        .find_map(|probe| {
                            self.local(probe)
                                .ok()
                                .filter(|tm| (tm.isdst != 0) == want)
                                .map(|tm| tm.gmtoff)
                        });
                    match found {
                        Some(offset) => local.checked_sub(offset).ok_or(EOVERFLOW)?,
                        None => {
                            let shift = 3600 * (i64::from(isdst_of(natural)?) - i64::from(want));
                            natural.checked_add(shift).ok_or(EOVERFLOW)?
                        }
                    }
                }
            }
        };
        let t = t
            .checked_add(i64::from(tm.sec) - i64::from(clamped))
            .ok_or(EOVERFLOW)?;
        Ok((t, self.local(t)?))
    }
}

/// `sscanf("%hu")` at the front of `text`: the value and the bytes consumed.
fn scan_u16(text: &[u8]) -> Option<(u16, usize)> {
    let mut at = text.iter().take_while(|b| b.is_ascii_whitespace()).count();
    let negative = match text.get(at) {
        Some(b'-') => {
            at += 1;
            true
        }
        Some(b'+') => {
            at += 1;
            false
        }
        _ => false,
    };
    let digits = text[at..].iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let value = text[at..at + digits].iter().fold(0u64, |value, digit| {
        value.wrapping_mul(10).wrapping_add(u64::from(digit - b'0'))
    });
    let value = if negative {
        value.wrapping_neg()
    } else {
        value
    };
    Some((value as u16, at + digits))
}

/// `sscanf(text, "%hu%n:%hu%n:%hu%n", …)`: the fields scanned (unset ones
/// keep `values`' defaults) and the bytes the last `%n` saw.
fn scan_hms(text: &[u8], values: &mut [u16; 3]) -> (usize, usize) {
    let (mut scanned, mut consumed, mut at) = (0, 0, 0);
    for (index, value) in values.iter_mut().enumerate() {
        if index > 0 {
            if text.get(at) != Some(&b':') {
                break;
            }
            at += 1;
        }
        let Some((parsed, length)) = scan_u16(&text[at..]) else {
            break;
        };
        *value = parsed;
        at += length;
        consumed = at;
        scanned += 1;
    }
    (scanned, consumed)
}

/// `parse_tzname`: three or more letters, or `<…>` of letters, digits and
/// signs.
fn parse_name(tz: &mut &[u8], rule: &mut Rule) -> bool {
    let letters = tz.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    let (start, length, end) = if letters >= 3 {
        (0, letters, letters)
    } else {
        if tz.first() != Some(&b'<') {
            return false;
        }
        let length = tz[1..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'+' || **b == b'-')
            .count();
        if tz.get(1 + length) != Some(&b'>') || length < 3 {
            return false;
        }
        (1, length, length + 2)
    };
    rule.name = intern(&tz[start..start + length]);
    *tz = &tz[end..];
    true
}

/// `parse_offset`: `[+-]hh[:mm[:ss]]`, west positive; daylight time
/// defaults to an hour ahead of standard time.
fn parse_offset(tz: &mut &[u8], rules: &mut [Rule; 2], which: usize) -> bool {
    let first = tz.first().copied();
    if which == 0 && !matches!(first, Some(b'+' | b'-' | b'0'..=b'9')) {
        return false;
    }
    let sign = if first == Some(b'-') { 1 } else { -1 };
    if matches!(first, Some(b'+' | b'-')) {
        *tz = &tz[1..];
    }
    let mut hms = [0u16; 3];
    let (scanned, consumed) = scan_hms(tz, &mut hms);
    if scanned > 0 {
        let [hh, mm, ss] = hms;
        rules[which].offset = sign
            * (i64::from(ss.min(59)) + i64::from(mm.min(59)) * 60 + i64::from(hh.min(24)) * 3600);
    } else if which == 0 {
        rules[0].offset = 0;
        return false;
    } else {
        rules[1].offset = rules[0].offset + 3600;
    }
    *tz = &tz[consumed..];
    true
}

/// `parse_rule`: `,date[/time]`; nothing left means the US rules, March's
/// second Sunday to November's first.
fn parse_rule(tz: &mut &[u8], rule: &mut Rule, which: usize) -> bool {
    let mut text = *tz;
    if text.first() == Some(&b',') {
        text = &text[1..];
    }
    match text.first() {
        Some(b'J' | b'0'..=b'9') => {
            let julian = text[0] == b'J';
            if julian {
                text = &text[1..];
                if !text.first().is_some_and(u8::is_ascii_digit) {
                    return false;
                }
            }
            let digits = text.iter().take_while(|b| b.is_ascii_digit()).count();
            let day = text[..digits].iter().try_fold(0u64, |value, digit| {
                value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
            });
            let Some(day) = day.filter(|day| *day <= 365 && !(julian && *day == 0)) else {
                return false;
            };
            rule.kind = if julian { Kind::J1 } else { Kind::J0 };
            rule.d = day as u16;
            text = &text[digits..];
        }
        Some(b'M') => {
            let mut at = 1;
            let mut fields = [0u16; 3];
            for (index, field) in fields.iter_mut().enumerate() {
                if index > 0 {
                    if text.get(at) != Some(&b'.') {
                        return false;
                    }
                    at += 1;
                }
                let Some((value, length)) = scan_u16(&text[at..]) else {
                    return false;
                };
                *field = value;
                at += length;
            }
            let [m, n, d] = fields;
            if !(1..=12).contains(&m) || !(1..=5).contains(&n) || d > 6 {
                return false;
            }
            (rule.kind, rule.m, rule.n, rule.d) = (Kind::M, m, n, d);
            text = &text[at..];
        }
        None => {
            (rule.kind, rule.n, rule.d) = (Kind::M, if which == 0 { 2 } else { 1 }, 0);
            rule.m = if which == 0 { 3 } else { 11 };
        }
        Some(_) => return false,
    }
    match text.first() {
        None | Some(b',') => rule.secs = 2 * 3600,
        Some(b'/') => {
            text = &text[1..];
            if text.is_empty() {
                return false;
            }
            let negative = text[0] == b'-';
            if negative {
                text = &text[1..];
            }
            let mut hms = [2u16, 0, 0];
            let (_, consumed) = scan_hms(text, &mut hms);
            text = &text[consumed..];
            let [hh, mm, ss] = hms.map(i64::from);
            rule.secs = if negative { -1 } else { 1 } * (hh * 3600 + mm * 60 + ss);
        }
        Some(_) => return false,
    }
    *tz = text;
    true
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Days before each month, and the year's length (`__mon_yday`).
fn month_days(leap: bool) -> [i64; 13] {
    let mut days = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];
    if leap {
        days[2..].iter_mut().for_each(|day| *day += 1);
    }
    days
}

/// `compute_change`: the UTC instant `year`'s transition into `rule` happens.
/// glibc computes in `int` here — the year is `1900 + tm_year` and the day
/// counts are `int` — so a year near `INT_MAX` wraps exactly as it does
/// there.
fn change(rule: &Rule, year: i32) -> i64 {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    // January 1st, 00:00 UTC of YEAR; glibc takes 1970's for any earlier year.
    let mut t = if year > 1970 {
        let days = (year - 1970)
            .wrapping_mul(365)
            .wrapping_add((year - 1) / 4 - 1970 / 4)
            .wrapping_sub((year - 1) / 100 - 1970 / 100)
            .wrapping_add((year - 1) / 400 - 1970 / 400);
        i64::from(days) * SECS_PER_DAY
    } else {
        0
    };
    match rule.kind {
        Kind::J1 => {
            t += (i64::from(rule.d) - 1) * SECS_PER_DAY;
            if rule.d >= 60 && leap {
                t += SECS_PER_DAY;
            }
        }
        Kind::J0 => t += i64::from(rule.d) * SECS_PER_DAY,
        Kind::M => {
            let days = month_days(leap);
            let m = usize::from(rule.m);
            t += days[m - 1] * SECS_PER_DAY;
            // Zeller's congruence: the weekday of the month's first day.
            let m1 = (i32::from(rule.m) + 9) % 12 + 1;
            let yy0 = if rule.m <= 2 {
                year.wrapping_sub(1)
            } else {
                year
            };
            let (yy1, yy2) = (yy0 / 100, yy0 % 100);
            let mut dow = ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
            if dow < 0 {
                dow += 7;
            }
            let mut d = i64::from(rule.d) - i64::from(dow);
            if d < 0 {
                d += 7;
            }
            for _ in 1..rule.n {
                if d + 7 >= days[m] - days[m - 1] {
                    break;
                }
                d += 7;
            }
            t += d * SECS_PER_DAY;
        }
    }
    t - rule.offset + rule.secs
}

/// `__offtime`: `t` shifted by `offset` seconds, broken down; `EOVERFLOW`
/// when its year does not fit `int`.
fn offtime(t: i64, offset: i64) -> Result<PatinaTm, c_int> {
    let floor_div = |a: i64, b: i64| a / b - i64::from(a % b < 0);
    let leaps_thru_end_of = |y: i64| floor_div(y, 4) - floor_div(y, 100) + floor_div(y, 400);
    let mut days = t / SECS_PER_DAY;
    let mut rem = t % SECS_PER_DAY + offset;
    while rem < 0 {
        rem += SECS_PER_DAY;
        days -= 1;
    }
    while rem >= SECS_PER_DAY {
        rem -= SECS_PER_DAY;
        days += 1;
    }
    let mut tm = PatinaTm {
        hour: (rem / 3600) as c_int,
        min: (rem % 3600 / 60) as c_int,
        sec: (rem % 60) as c_int,
        ..PatinaTm::default()
    };
    // January 1, 1970 was a Thursday.
    let mut wday = (4 + days) % 7;
    if wday < 0 {
        wday += 7;
    }
    tm.wday = wday as c_int;
    let mut y: i64 = 1970;
    while days < 0 || days >= if is_leap(y) { 366 } else { 365 } {
        let guess = y + days / 365 - i64::from(days % 365 < 0);
        days -= (guess - y) * 365 + leaps_thru_end_of(guess - 1) - leaps_thru_end_of(y - 1);
        y = guess;
    }
    tm.year = c_int::try_from(y - 1900).map_err(|_| EOVERFLOW)?;
    tm.yday = days as c_int;
    let months = month_days(is_leap(y));
    let month = (1..12).rev().find(|&m| days >= months[m]).unwrap_or(0);
    tm.mon = month as c_int;
    tm.mday = (days - months[month] + 1) as c_int;
    Ok(tm)
}

/// The zone `tzset_internal` last read, and the `TZ` it read it from
/// (`old_tz`, after glibc's `""` and `:` rewrites).
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
struct Current {
    zone: Zone,
    tz: Vec<u8>,
}

#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
static CURRENT: SpinMutex<Option<Current>> = SpinMutex::new(None);

/// glibc's `tzset_internal`: the zone in effect. The first call reads `TZ`;
/// later calls keep that zone unless `reread` (glibc's `always`: `tzset`,
/// `mktime`, and `strftime`'s `%Z` of a time with no zone name), and even then
/// keep it while `TZ` is the string it was read from, as glibc compares it.
/// A zoneinfo file where glibc would read one is a named fatal naming `op`.
/// `settings` reads `TZ` and `TZDIR`.
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
pub(crate) fn current(op: &str, settings: &dyn Fn() -> Settings, reread: bool) -> Zone {
    loop {
        let (tz, tzdir) = settings();
        if let Some(zone) = cached(tz.as_deref(), reread) {
            return zone;
        }
        let zone = chosen(op, tz.as_deref(), tzdir.as_deref());
        // Chosen outside the lock: the choice reads the filesystem, a
        // scheduling point, and a task spinning on a lock another task holds
        // would wait on the host with the baton. Published only while the
        // settings are still the ones it was chosen for (read again with no
        // scheduling point between), so a choice another task's later
        // settings overtook is chosen again rather than replacing theirs.
        let mut current = CURRENT.lock();
        if settings() == (tz.clone(), tzdir) {
            let tz = normalized(tz.as_deref())
                .unwrap_or(TZ_DEFAULT.as_bytes())
                .to_vec();
            *current = Some(Current { zone, tz });
            return zone;
        }
    }
}

/// `TZ` and `TZDIR`, each unset or its value.
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
pub(crate) type Settings = (Option<Vec<u8>>, Option<Vec<u8>>);

/// `TZ` as glibc compares it with the zone in effect's.
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
fn normalized(tz: Option<&[u8]>) -> Option<&[u8]> {
    tz.map(|tz| match tz {
        [] => &b"Universal"[..],
        [b':', rest @ ..] => rest,
        tz => tz,
    })
}

/// The zone in effect, unless `reread` and `tz` is not the string it was
/// read from.
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
fn cached(tz: Option<&[u8]>, reread: bool) -> Option<Zone> {
    let current = CURRENT.lock();
    let current = current.as_ref()?;
    (!reread || normalized(tz) == Some(current.tz.as_slice())).then_some(current.zone)
}

/// The zone `tz` and `tzdir` name, a zoneinfo file a named fatal.
#[cfg_attr(not(patina_posix_exports), allow(dead_code))]
fn chosen(op: &str, tz: Option<&[u8]>, tzdir: Option<&[u8]>) -> Zone {
    let chosen = Zone::choose(tz, tzdir, |path| {
        // A zone file is a regular file on the volume; the entropy device and
        // a namespace file are none.
        matches!(
            crate::paths::resolve(crate::paths::AT_FDCWD, path, 0),
            Ok(crate::paths::Resolution::Volume(resolved)) if resolved
                .metadata
                .is_some_and(|metadata| metadata.kind == crate::FsEntryKind::File)
        )
    });
    match chosen {
        Ok(zone) => zone,
        Err(ZoneFile(path)) => crate::trap_unmodeled(&format!(
            "{op}: TZ names the zoneinfo file {path}, which exists in the deterministic filesystem; zoneinfo (TZif) files are not modeled; failing closed"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(tm: &PatinaTm) -> (i64, [c_int; 9], String) {
        // SAFETY: zone names are interned for the process.
        let zone = unsafe { CStr::from_ptr(tm.zone) }
            .to_string_lossy()
            .into_owned();
        (
            tm.gmtoff,
            [
                tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec, tm.wday, tm.yday, tm.isdst,
            ],
            zone,
        )
    }

    fn none(_: &str) -> bool {
        false
    }

    /// The zones glibc cannot find a file for: the default file and the
    /// empty name answer "UTC", a name without an offset keeps its name; a
    /// zone file that is there is refused.
    #[test]
    fn a_missing_zone_file_falls_back_as_glibc_does_and_a_present_one_is_refused() {
        let zone = |tz: Option<&[u8]>| Zone::choose(tz, None, none).unwrap().local(0).unwrap();
        for (tz, name) in [
            (None, "UTC"),
            (Some(&b""[..]), "Universal"),
            (Some(b":"), "UTC"),
            (Some(b":/etc/localtime"), "UTC"),
            (Some(b"UTC"), "UTC"),
            (Some(b"AB5"), ""),
            (Some(b"America/New_York"), "America"),
            (Some(b":/nonexistent"), ""),
        ] {
            let tm = zone(tz);
            assert_eq!(fields(&tm).2, name, "{tz:?}");
            assert_eq!((tm.gmtoff, tm.isdst, tm.hour), (0, 0, 0), "{tz:?}");
        }

        // A regular file where glibc would read one is refused, not guessed.
        let at = |wanted: &'static str| move |path: &str| path == wanted;
        assert_eq!(
            Zone::choose(None, None, at("/etc/localtime")).unwrap_err(),
            ZoneFile("/etc/localtime".into())
        );
        assert_eq!(
            Zone::choose(
                Some(b":Europe/Paris"),
                None,
                at("/usr/share/zoneinfo/Europe/Paris")
            )
            .unwrap_err(),
            ZoneFile("/usr/share/zoneinfo/Europe/Paris".into())
        );
        assert_eq!(
            Zone::choose(Some(b"EST5EDT"), Some(b"/z"), at("/z/EST5EDT")).unwrap_err(),
            ZoneFile("/z/EST5EDT".into())
        );
        assert!(Zone::choose(Some(b"EST5EDT"), Some(b"/z"), none).is_ok());
    }

    /// Differential against the host's glibc: every rule string and instant
    /// converts exactly as `localtime_r` does, with `TZDIR` pointing nowhere
    /// so glibc reads no file either (the virtual machine ships none).
    #[cfg(target_os = "linux")]
    #[test]
    fn rule_strings_convert_as_the_host_glibc_does() {
        unsafe extern "C" {
            fn tzset();
        }
        let zones: &[&str] = &[
            "XST5XDT,M3.2.0,M11.1.0",
            "EST5EDT",
            "EST5EDT4,J60/3,300/1:30",
            "CET-1CEST,M3.5.0,M10.5.0/3",
            "AEST-10AEDT,M10.1.0,M4.1.0/3",
            "<+0530>-5:30",
            "<-03>3",
            "NZST-12NZDT,M9.5.0,M4.1.0/3",
            "IST-5:30",
            "XXX3:15:20YYY2:10,J1/0,J365/25",
            "ABC+4DEF,59/-1,M12.5.6/167",
            "UTC",
            "GMT0",
            "Universal",
            "AB5",
            "",
            ":",
            ":ABC-2",
            "WAT-1WAST,M9.1.0,M4.1.0",
        ];
        let instants: &[i64] = &[
            0,
            -1,
            1_690_000_000,
            1_678_604_399,
            1_678_604_400,
            1_699_163_999,
            1_699_164_000,
            -2_208_988_800,
            4_102_444_800,
            951_782_400,
            1_711_846_800,
            1_729_987_200,
            -62_135_596_800,
            253_402_300_799,
            67_767_976_233_532_799,
            67_767_976_233_532_800,
            -67_768_040_609_740_801,
            -67_768_040_609_740_800,
            i64::MAX,
            i64::MIN,
        ];
        /// Puts TZ and TZDIR back (and glibc's zone with them) when the test
        /// ends, passing or not: the other tests in this binary, and the
        /// processes they spawn, inherit the environment.
        struct Restore([(&'static str, Option<std::ffi::OsString>); 2]);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (name, value) in &self.0 {
                    // SAFETY: as below.
                    unsafe {
                        match value {
                            Some(value) => std::env::set_var(name, value),
                            None => std::env::remove_var(name),
                        }
                    }
                }
                // SAFETY: as below.
                unsafe { tzset() };
            }
        }
        let _restore = Restore(["TZ", "TZDIR"].map(|name| (name, std::env::var_os(name))));
        // SAFETY: this test is the only one in the binary touching TZ/TZDIR.
        unsafe { std::env::set_var("TZDIR", "/nonexistent-patina-zoneinfo") };
        for zone in zones {
            // SAFETY: as above.
            unsafe {
                std::env::set_var("TZ", zone);
                tzset();
            }
            let model = Zone::choose(
                Some(zone.as_bytes()),
                Some(b"/nonexistent-patina-zoneinfo"),
                none,
            )
            .unwrap();
            for &t in instants {
                // SAFETY: an all-zero `struct tm` is a valid out-parameter.
                let mut native: libc::tm = unsafe { std::mem::zeroed() };
                // SAFETY: valid pointers.
                let answer = unsafe { libc::localtime_r(&t, &mut native) };
                let ours = model.local(t);
                if answer.is_null() {
                    assert_eq!(ours.map(|tm| fields(&tm)), Err(EOVERFLOW), "{zone} {t}");
                    continue;
                }
                // SAFETY: glibc's zone names live for the process.
                let name = unsafe { CStr::from_ptr(native.tm_zone) }
                    .to_string_lossy()
                    .into_owned();
                let expected = (
                    native.tm_gmtoff,
                    [
                        native.tm_year,
                        native.tm_mon,
                        native.tm_mday,
                        native.tm_hour,
                        native.tm_min,
                        native.tm_sec,
                        native.tm_wday,
                        native.tm_yday,
                        native.tm_isdst,
                    ],
                    name,
                );
                assert_eq!(ours.map(|tm| fields(&tm)), Ok(expected), "{zone} {t}");
                if t.abs() < 10_000_000_000 {
                    mktime_agrees(zone, &model, &native);
                }
            }
        }
    }

    /// `mktime` of `base`'s fields, and of them carried out of range, read
    /// each way `tm_isdst` asks, agrees with the host's: the instant, the
    /// normalized fields, or the overflow. A time the zone skips or repeats
    /// is left out: glibc's answer there turns on its previous calls.
    #[cfg(target_os = "linux")]
    fn mktime_agrees(zone: &str, model: &Zone, base: &libc::tm) {
        let shifts: [[c_int; 6]; 5] = [
            [0; 6],
            [0, 13, 40, 0, 0, 0],
            [0, -14, -400, -30, 0, 0],
            [0, 0, 0, 0, 90, 70],
            [1, 0, 0, 1, -59, -3600],
        ];
        for shift in shifts {
            for isdst in [-1, 0, 1] {
                let mut native = *base;
                native.tm_year += shift[0];
                native.tm_mon += shift[1];
                native.tm_mday += shift[2];
                native.tm_hour += shift[3];
                native.tm_min += shift[4];
                native.tm_sec += shift[5];
                native.tm_isdst = isdst;
                let input = PatinaTm {
                    sec: native.tm_sec,
                    min: native.tm_min,
                    hour: native.tm_hour,
                    mday: native.tm_mday,
                    mon: native.tm_mon,
                    year: native.tm_year,
                    isdst,
                    ..PatinaTm::default()
                };
                {
                    // Where glibc searches: the seconds held to a minute.
                    let readings = [false, true].map(|dst| {
                        let mut tm = input;
                        tm.sec = tm.sec.clamp(0, 59);
                        tm.isdst = c_int::from(dst);
                        model
                            .mktime(&tm)
                            .is_ok_and(|(_, local)| local.isdst == c_int::from(dst))
                    });
                    if readings[0] == readings[1] {
                        continue;
                    }
                }
                let case = format!("{zone} {input:?}");
                // SAFETY: a valid, writable `struct tm`.
                let t = unsafe { libc::mktime(&mut native) };
                let ours = model.mktime(&input);
                if t == -1 && ours.is_err() {
                    continue;
                }
                let (ours_t, ours_tm) = ours.expect(&case);
                assert_eq!(ours_t, t, "{case}");
                assert_eq!(
                    fields(&ours_tm).1,
                    [
                        native.tm_year,
                        native.tm_mon,
                        native.tm_mday,
                        native.tm_hour,
                        native.tm_min,
                        native.tm_sec,
                        native.tm_wday,
                        native.tm_yday,
                        native.tm_isdst,
                    ],
                    "{case}"
                );
            }
        }
    }
}
