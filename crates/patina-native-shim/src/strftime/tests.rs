use super::*;

/// UTC, and the time's own zone name.
struct Utc<'a>(Option<&'a [u8]>);

impl Zone for Utc<'_> {
    fn own_name(&self) -> Option<Vec<u8>> {
        self.0.map(<[u8]>::to_vec)
    }
    fn name(&self, _isdst: bool) -> Vec<u8> {
        b"UTC".to_vec()
    }
    fn mktime(&self, tm: &Tm) -> i64 {
        // SAFETY: a local tm for the host's timegm.
        unsafe { libc::timegm(&mut host_tm(tm, None)) }
    }
}

fn host_tm(tm: &Tm, zone: Option<&std::ffi::CStr>) -> libc::tm {
    libc::tm {
        tm_sec: tm.sec,
        tm_min: tm.min,
        tm_hour: tm.hour,
        tm_mday: tm.mday,
        tm_mon: tm.mon,
        tm_year: tm.year,
        tm_wday: tm.wday,
        tm_yday: tm.yday,
        tm_isdst: tm.isdst,
        tm_gmtoff: tm.gmtoff as _,
        tm_zone: zone.map_or(std::ptr::null(), |zone| zone.as_ptr()) as _,
    }
}

fn ours(format: &str, tm: &Tm, zone: Option<&[u8]>) -> Vec<u8> {
    super::format(format.as_bytes(), tm, &Utc(zone), usize::MAX).unwrap()
}

/// A wide character, as `wcsftime` formats them.
#[derive(Clone, Copy, Debug, PartialEq)]
struct W(u32);

impl From<u8> for W {
    fn from(byte: u8) -> Self {
        W(u32::from(byte))
    }
}

impl From<W> for u32 {
    fn from(unit: W) -> u32 {
        unit.0
    }
}

impl Unit for W {
    const WIDE: bool = true;
}

fn ours_wide(format: &str, tm: &Tm, zone: &[u8]) -> Result<String, Failure> {
    let units: Vec<W> = format.bytes().map(W::from).collect();
    let wide = super::format(&units, tm, &Utc(Some(zone)), usize::MAX)?;
    Ok(wide
        .iter()
        .map(|unit| char::from_u32(unit.0).unwrap())
        .collect())
}

#[cfg(target_os = "linux")]
fn host(format: &str, tm: &Tm, zone: Option<&std::ffi::CStr>) -> Vec<u8> {
    let format = std::ffi::CString::new(format).unwrap();
    let mut buf = vec![0u8; 512];
    let tm = host_tm(tm, zone);
    // SAFETY: a writable buffer of its length and a NUL-terminated format.
    let n = unsafe { libc::strftime(buf.as_mut_ptr().cast(), buf.len(), format.as_ptr(), &tm) };
    buf.truncate(n);
    buf
}

/// A spread of broken-down times: ordinary days, the ISO-week edges of the
/// new year, leap days, midnight and noon, negative and far years, and
/// out-of-range names.
#[cfg(target_os = "linux")]
fn times() -> Vec<Tm> {
    let mut times = Vec::new();
    for t in [
        0i64,
        951_782_400,
        1_104_537_600,
        1_230_768_000,
        1_609_459_199,
        1_735_689_600,
        -86_400 * 400,
        253_402_300_799,
        -62_135_596_800,
        1_784_773_554,
    ] {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: local storage for the host's gmtime_r.
        unsafe { libc::gmtime_r(&t, &mut tm) };
        for (hour, gmtoff) in [
            (tm.tm_hour, 0),
            (0, 3600 * 5 + 1800),
            (12, -3600 * 8),
            (23, 0),
        ] {
            times.push(Tm {
                sec: tm.tm_sec,
                min: tm.tm_min,
                hour,
                mday: tm.tm_mday,
                mon: tm.tm_mon,
                year: tm.tm_year,
                wday: tm.tm_wday,
                yday: tm.tm_yday,
                isdst: 0,
                gmtoff,
            });
        }
    }
    times.push(Tm {
        wday: 9,
        mon: 14,
        isdst: -1,
        ..Tm::default()
    });
    times
}

#[cfg(target_os = "linux")]
#[test]
fn every_conversion_and_flag_formats_as_glibc_does() {
    let mut formats = Vec::new();
    for conversion in "aAbBcCdDeFgGhHIjklmMnprRsStTuUVwWxXyYzZ%Qqf".chars() {
        for flag in ["", "_", "-", "0", "^", "#", "+"] {
            for width in ["", "1", "6"] {
                formats.push(format!("%{flag}{width}{conversion}"));
            }
        }
        formats.push(format!("%E{conversion}"));
        formats.push(format!("%O{conversion}"));
    }
    formats.extend(["%", "%Q", "a%5", "plain text", "%Y-%m-%dT%H:%M:%S%z"].map(String::from));
    for tm in times() {
        for zone in [None, Some(c"EST")] {
            for format in &formats {
                // The host answers these two from its own zone, which the
                // test does not control; the model's answers are below.
                if format.ends_with('s') || (zone.is_none() && format.ends_with('Z')) {
                    continue;
                }
                assert_eq!(
                    String::from_utf8_lossy(&ours(format, &tm, zone.map(|zone| zone.to_bytes()))),
                    String::from_utf8_lossy(&host(format, &tm, zone)),
                    "{format:?} for {tm:?} with zone {zone:?}"
                );
            }
        }
    }
}

#[test]
fn a_time_with_no_zone_name_names_the_models_zone() {
    let tm = Tm {
        mday: 1,
        ..Tm::default()
    };
    assert_eq!(ours("%Z", &tm, None), b"UTC");
    assert_eq!(ours("%Z", &tm, Some(b"")), b"UTC");
    assert_eq!(ours("%Z", &Tm { isdst: -1, ..tm }, None), b"");
    assert_eq!(ours("%s", &tm, None), b"-2208988800");
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn wcsftime(
        out: *mut libc::wchar_t,
        max: usize,
        format: *const libc::wchar_t,
        tm: *const libc::tm,
    ) -> usize;
}

#[cfg(target_os = "linux")]
#[test]
fn a_wide_zone_name_formats_as_glibc_does() {
    let tm = Tm {
        mday: 1,
        year: 70,
        ..Tm::default()
    };
    for format in [
        "%Z", "%^Z", "%#Z", "%-10Z", "%_10Z", "%010Z", "%10Z", "%^#6Z",
    ] {
        let wide: Vec<libc::wchar_t> = format
            .chars()
            .map(|c| c as libc::wchar_t)
            .chain([0])
            .collect();
        let mut buf = vec![0 as libc::wchar_t; 64];
        let zone = c"XsT";
        let host = host_tm(&tm, Some(zone));
        // SAFETY: a writable buffer of its length and a NUL-terminated format.
        let n = unsafe { wcsftime(buf.as_mut_ptr(), buf.len(), wide.as_ptr(), &host) };
        let host: String = buf[..n]
            .iter()
            .map(|&unit| char::from_u32(i64::from(unit) as u32).unwrap())
            .collect();
        assert_eq!(
            ours_wide(format, &tm, zone.to_bytes()),
            Ok(host),
            "{format:?}"
        );
    }
}

#[test]
fn a_wide_zone_name_past_ascii_has_no_wide_form() {
    let tm = Tm {
        mday: 1,
        ..Tm::default()
    };
    assert_eq!(ours_wide("%Z", &tm, b"GMT"), Ok("GMT".to_owned()));
    // The C locale has no wide form of a byte past ASCII.
    assert_eq!(ours_wide("%Z", &tm, "café".as_bytes()), Err(Failure::Ilseq));
}

#[test]
fn a_year_before_the_epoch_formats_with_its_sign_first() {
    let year = |year: i32| Tm {
        mday: 1,
        year: year - 1900,
        ..Tm::default()
    };
    let cases = [
        (
            -101,
            "%y %C %05Y %_5Y %-Y %5C %3y",
            "99 -2 -0101  -101 -101 -0002 099",
        ),
        (-100, "%y %C %05Y", "00 -1 -0100"),
        (-99, "%y %C %05Y", "01 -1 -0099"),
        (-1, "%y %C %_5Y", "99 -1    -1"),
        (99, "%y %C %05Y", "99 0 00099"),
    ];
    for (y, format, expected) in cases {
        assert_eq!(
            String::from_utf8(ours(format, &year(y), None)).unwrap(),
            expected,
            "{format:?} for year {y}"
        );
    }
}

#[test]
fn a_result_past_the_bound_stops_there() {
    let tm = Tm {
        mday: 1,
        ..Tm::default()
    };
    let format = |format: &str, limit| super::format(format.as_bytes(), &tm, &Utc(None), limit);
    assert_eq!(format("%Y", 4), Ok(b"1900".to_vec()));
    assert_eq!(format("%Y", 3), Err(Failure::Overflow));
    // A width past any buffer fails at the bound, not after padding to it.
    assert_eq!(format("%999999999999999999Y", 64), Err(Failure::Overflow));
    assert_eq!(format("%999999999999999999c", 64), Err(Failure::Overflow));
}
