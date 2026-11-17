//! The host requirements of this architecture that are facts of the machine and its kernel,
//! not of the sandbox: checked by `patina doctor` (which explains) and by the launcher before
//! any run (which refuses with an `error`). `Facts::probe` reads them; `checks` judges them, a
//! pure function the unit tests feed other hosts' facts.

use std::collections::BTreeMap;

/// One requirement: `Ok(detail)`, or `Err((what is wrong, the fix or ""))`.
pub type Check = (&'static str, Result<String, (String, String)>);

/// The facts `checks` judges.
#[derive(Clone, Debug)]
pub struct Facts {
    /// `std::env::consts::ARCH`.
    pub arch: &'static str,
    /// The kernel's release (`uname -r`).
    pub kernel: String,
    /// The page size in bytes.
    pub page_size: u64,
    /// The width of the user address space: the highest `n` of those probed for which the
    /// page below `1 << n` can be mapped.
    pub va_bits: u32,
    /// Whether `PR_SET_TSC` makes the counter read fault (rdtsc; arm64: the counter-timer
    /// registers), else why not.
    pub counter_trap: Result<(), String>,
    /// arm64: the pointer-authentication keys can be disabled (`Ok(true)`), the CPU has none
    /// (`Ok(false)`), or why they cannot.
    pub pac: Result<bool, String>,
    /// arm64: each allowed CPU and its `MIDR_EL1` (`None`: unreadable).
    pub midr: Vec<(usize, Option<u64>)>,
    /// arm64: `AT_HWCAP`, `AT_HWCAP2`.
    pub hwcap: u64,
    pub hwcap2: u64,
    /// arm64: the SVE vector length in bytes programs start with (0: no SVE).
    pub sve_vl: u64,
}

/// The layout (`proto::layout`) ends below `STACK_TOP`: a 47-bit address space holds it.
pub const VA_BITS_NEEDED: u32 = 47;
/// The largest SVE vector length whose full register record, with every other record the
/// runtime builds, fits in a signal frame's 4,096 bytes (`arch/aarch64/sigframe.rs`).
pub const SVE_VL_MAX: u64 = 64;

const HWCAP_SVE: u64 = 1 << 22;
const HWCAP_PACA: u64 = 1 << 30;
const HWCAP_PACG: u64 = 1 << 31;
const HWCAP2_SME: u64 = 1 << 23;
/// Features whose records the kernel adds to every signal frame and the runtime does not
/// build (each would end every run that takes a signal `signal-context`).
const HWCAP2_FRAME_RECORDS: [(u64, &str); 2] = [(1 << 48, "FPMR"), (1 << 63, "POE")];

impl Facts {
    /// This host's facts. On x86_64 only the counter trap is probed. `cpu`: a CPU a run is
    /// pinned to (`[sched] host-cpu`), whose model is checked with the allowed ones.
    pub fn probe(cpu: Option<usize>) -> Facts {
        let arm = cfg!(target_arch = "aarch64");
        let (hwcap, hwcap2) = if arm {
            unsafe {
                (
                    libc::getauxval(libc::AT_HWCAP),
                    libc::getauxval(libc::AT_HWCAP2),
                )
            }
        } else {
            (0, 0)
        };
        let real = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
        // Test hook: another page size, to see the refusal on a host without one. It can only
        // add a refusal: 4096 leaves the real size.
        let page_size = match std::env::var("PATINA_TEST_PAGE_SIZE") {
            Ok(v) if v != "4096" => v.parse().unwrap_or(0),
            _ => real,
        };
        Facts {
            arch: std::env::consts::ARCH,
            kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|s| s.trim().to_string())
                .unwrap_or_default(),
            page_size,
            va_bits: if arm { probe_va_bits() } else { VA_BITS_NEEDED },
            counter_trap: in_child(tsc_child),
            pac: if !arm || hwcap & (HWCAP_PACA | HWCAP_PACG) == 0 {
                Ok(false)
            } else {
                in_child(pac_child).map(|_| true)
            },
            midr: if arm {
                let mut cpus = crate::launch::allowed_cpus();
                if let Some(c) = cpu.filter(|c| !cpus.contains(c)) {
                    cpus.push(c);
                    cpus.sort();
                }
                cpus.into_iter().map(|c| (c, midr(c))).collect()
            } else {
                vec![]
            },
            hwcap,
            hwcap2,
            sve_vl: if arm && hwcap & HWCAP_SVE != 0 {
                const PR_SVE_GET_VL: i32 = 51;
                let r = unsafe { libc::prctl(PR_SVE_GET_VL, 0, 0, 0, 0) };
                if r < 0 {
                    0
                } else {
                    r as u64 & 0xffff
                }
            } else {
                0
            },
        }
    }

    /// Host facts for `doctor`'s `host` object, beyond those it reads itself.
    pub fn info(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut m = serde_json::Map::new();
        m.insert("arch".into(), self.arch.into());
        m.insert("page_size".into(), self.page_size.into());
        if self.arch == "aarch64" {
            let mut kinds: Vec<String> = self
                .midr
                .iter()
                .filter_map(|(_, m)| m.map(|v| format!("{v:#x}")))
                .collect();
            kinds.sort();
            kinds.dedup();
            m.insert("midr".into(), kinds.join(",").into());
            m.insert("hwcap".into(), format!("{:#x}", self.hwcap).into());
            m.insert("hwcap2".into(), format!("{:#x}", self.hwcap2).into());
            m.insert("sve_vector_length".into(), self.sve_vl.into());
        }
        m
    }
}

/// The platform check: the architectures Patina is built for.
pub fn platform(f: &Facts) -> Check {
    (
        "platform",
        match f.arch {
            "x86_64" | "aarch64" => Ok(format!("Linux {}", f.arch)),
            a => Err((
                format!("Patina runs on Linux x86_64 and aarch64 only, and this is {a}"),
                String::new(),
            )),
        },
    )
}

/// This architecture's checks after the sandbox's own (`doctor`'s order).
pub fn checks(f: &Facts) -> Vec<Check> {
    match f.arch {
        "x86_64" => vec![(
            "rdtsc trap",
            f.counter_trap
                .clone()
                .map(|_| "PR_SET_TSC makes rdtsc fault".into())
                .map_err(|e| (e, crate::doctor::CONTAINER_FIX.into())),
        )],
        "aarch64" => vec![
            ("counter-timer trap", counter_timer(f)),
            ("page size", page_size(f)),
            ("address space", address_space(f)),
            ("one CPU model", one_model(f)),
            ("signal context", signal_context(f)),
            ("pointer authentication", pac(f)),
        ],
        _ => vec![],
    }
}

/// The first requirement this host fails, as the launcher's `error`.
pub fn refusal(f: &Facts) -> Result<(), String> {
    let all = std::iter::once(platform(f)).chain(checks(f));
    for (_, r) in all {
        if let Err((why, fix)) = r {
            let fix = if fix.is_empty() {
                String::new()
            } else {
                format!("; fix: {fix}")
            };
            return Err(format!(
                "this host cannot run patina: {why}{fix} (`patina doctor` checks every requirement)"
            ));
        }
    }
    Ok(())
}

fn counter_timer(f: &Facts) -> Result<String, (String, String)> {
    f.counter_trap
        .clone()
        .map(|_| "PR_SET_TSC makes the counter-timer registers fault".into())
        .map_err(|e| {
            (
                format!(
                    "this kernel ({}) cannot trap counter-timer reads (PR_SET_TSC: {e}): arm64 needs Linux 6.12 or newer",
                    f.kernel
                ),
                "upgrade the kernel to 6.12 or newer (Ubuntu 24.04: sudo apt-get install linux-generic-hwe-24.04, then reboot)".into(),
            )
        })
}

fn page_size(f: &Facts) -> Result<String, (String, String)> {
    if f.page_size == 4096 {
        return Ok("4096".into());
    }
    Err((
        format!(
            "page size {}: Patina needs 4096 on this architecture",
            f.page_size
        ),
        "a kernel built with 4 KiB pages (Asahi Linux and some distributions use 16 KiB or 64 KiB)"
            .into(),
    ))
}

fn address_space(f: &Facts) -> Result<String, (String, String)> {
    if f.va_bits >= VA_BITS_NEEDED {
        return Ok(format!("{}-bit or more user address space", f.va_bits));
    }
    Err((
        format!(
            "this kernel gives programs a {}-bit address space; Patina needs {VA_BITS_NEEDED} or more",
            f.va_bits
        ),
        "a kernel built with 48-bit virtual addresses (CONFIG_ARM64_VA_BITS_48)".into(),
    ))
}

/// `0-3,6`: CPU numbers as ranges.
fn ranges(cpus: &[usize]) -> String {
    let mut out: Vec<String> = vec![];
    let mut i = 0;
    while i < cpus.len() {
        let mut j = i;
        while j + 1 < cpus.len() && cpus[j + 1] == cpus[j] + 1 {
            j += 1;
        }
        out.push(if i == j {
            cpus[i].to_string()
        } else {
            format!("{}-{}", cpus[i], cpus[j])
        });
        i = j + 1;
    }
    out.join(",")
}

fn one_model(f: &Facts) -> Result<String, (String, String)> {
    if let Some((c, _)) = f.midr.iter().find(|(_, m)| m.is_none()) {
        return Err((
            format!("cannot read cpu {c}'s MIDR_EL1 (/sys/devices/system/cpu/cpu{c}/regs/identification/midr_el1)"),
            String::new(),
        ));
    }
    let mut kinds: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (c, m) in &f.midr {
        kinds.entry(m.unwrap_or(0)).or_default().push(*c);
    }
    match kinds.len() {
        0 => Err(("no allowed CPU".into(), String::new())),
        1 => {
            let (m, cpus) = kinds.iter().next().unwrap();
            Ok(format!("cpus {}: MIDR {m:#x}", ranges(cpus)))
        }
        _ => {
            let list: Vec<String> = kinds
                .iter()
                .map(|(m, cpus)| format!("cpus {} (MIDR {m:#x})", ranges(cpus)))
                .collect();
            let last = kinds.values().last().unwrap();
            Err((
                format!(
                    "the allowed CPUs are of {} kinds, and a program can see which one it runs on: {}",
                    kinds.len(),
                    list.join(", ")
                ),
                format!(
                    "pin with taskset to cores of one kind, for example taskset -c {} patina ...",
                    ranges(last)
                ),
            ))
        }
    }
}

fn signal_context(f: &Facts) -> Result<String, (String, String)> {
    let records: Vec<&str> = HWCAP2_FRAME_RECORDS
        .iter()
        .filter(|(b, _)| f.hwcap2 & b != 0)
        .map(|(_, n)| *n)
        .collect();
    if !records.is_empty() {
        return Err((
            format!(
                "this CPU has {}, whose signal-frame records Patina does not build",
                records.join(" and ")
            ),
            String::new(),
        ));
    }
    if f.sve_vl > SVE_VL_MAX {
        return Err((
            format!(
                "SVE vector length {} bytes: Patina's signal frames hold vectors of up to {SVE_VL_MAX}",
                f.sve_vl
            ),
            format!("echo {SVE_VL_MAX} | sudo tee /proc/sys/abi/sve_default_vector_length"),
        ));
    }
    let mut has = vec!["FP/SIMD"];
    if f.sve_vl > 0 {
        has.push("SVE");
    }
    if f.hwcap2 & HWCAP2_SME != 0 {
        has.push("SME (a run that uses streaming mode or ZA stops `signal-context`)");
    }
    Ok(format!("records: {}", has.join(", ")))
}

fn pac(f: &Facts) -> Result<String, (String, String)> {
    match &f.pac {
        Ok(true) => Ok("keys are disabled for programs under Patina".into()),
        Ok(false) => Ok("this CPU has none".into()),
        Err(e) => Err((
            format!(
                "the pointer-authentication keys cannot be disabled (PR_PAC_SET_ENABLED_KEYS: {e})"
            ),
            String::new(),
        )),
    }
}

/// The `MIDR_EL1` of `cpu`, from sysfs (`0x00000000410fd490`).
fn midr(cpu: usize) -> Option<u64> {
    let s = std::fs::read_to_string(format!(
        "/sys/devices/system/cpu/cpu{cpu}/regs/identification/midr_el1"
    ))
    .ok()?;
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()
}

/// The widest user address space of those Patina's layout and common kernels use: the
/// highest `n` in 39..=48 for which the page below `1 << n` can be reserved (or is mapped).
fn probe_va_bits() -> u32 {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let mut best = 0;
    for n in [39u32, 42, 47, 48] {
        let a = (1u64 << n) - 2 * page;
        let p = unsafe {
            libc::mmap(
                a as *mut libc::c_void,
                page as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                continue;
            }
        } else {
            unsafe { libc::munmap(p, page as usize) };
            if p as u64 != a {
                continue;
            }
        }
        best = n;
    }
    best
}

/// Run `f` in a forked child; its exit status 0 is success, else `f`'s nonzero code and
/// errno are reported.
pub fn in_child(f: fn() -> i32) -> Result<(), String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        let code = f();
        unsafe { libc::_exit(code) };
    }
    let mut st = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut st, 0) };
        if r == pid {
            break;
        }
        let e = std::io::Error::last_os_error();
        if r < 0 && e.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        // Reaped elsewhere (SIGCHLD ignored): the result is unknown, never a pass.
        return Err(format!("waitpid: {e}"));
    }
    if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0 {
        Ok(())
    } else if libc::WIFEXITED(st) {
        Err(format!(
            "errno {} ({})",
            libc::WEXITSTATUS(st),
            std::io::Error::from_raw_os_error(libc::WEXITSTATUS(st))
        ))
    } else {
        Err(format!("child died (status {st:#x})"))
    }
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(1)
        .clamp(1, 255)
}

fn tsc_child() -> i32 {
    if unsafe { libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV, 0, 0, 0) } != 0 {
        return errno();
    }
    0
}

/// In a child: the four keys disabled, as the runtime disables them at every image start.
fn pac_child() -> i32 {
    const PR_PAC_SET_ENABLED_KEYS: i32 = 60;
    const ALL_KEYS: libc::c_ulong = 0xf;
    if unsafe { libc::prctl(PR_PAC_SET_ENABLED_KEYS, ALL_KEYS, 0, 0, 0) } != 0 {
        return errno();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hosted arm64 runner's facts.
    fn runner() -> Facts {
        Facts {
            arch: "aarch64",
            kernel: "7.0.0-1017-azure".into(),
            page_size: 4096,
            va_bits: 48,
            counter_trap: Ok(()),
            pac: Ok(true),
            midr: (0..4).map(|c| (c, Some(0x410f_d490))).collect(),
            hwcap: HWCAP_SVE | HWCAP_PACA | HWCAP_PACG,
            hwcap2: 0,
            sve_vl: 16,
        }
    }

    /// The names of the failing checks.
    fn failing(f: &Facts) -> Vec<&'static str> {
        std::iter::once(platform(f))
            .chain(checks(f))
            .filter(|(_, r)| r.is_err())
            .map(|(n, _)| n)
            .collect()
    }

    #[test]
    fn runner_passes() {
        assert!(failing(&runner()).is_empty(), "{:?}", checks(&runner()));
        assert!(refusal(&runner()).is_ok());
    }

    #[test]
    fn each_refusal_names_its_check() {
        let cases: Vec<(&str, Facts)> = vec![
            (
                "platform",
                Facts {
                    arch: "riscv64",
                    ..runner()
                },
            ),
            (
                "page size",
                Facts {
                    page_size: 16384,
                    ..runner()
                },
            ),
            (
                "address space",
                Facts {
                    va_bits: 39,
                    ..runner()
                },
            ),
            (
                "counter-timer trap",
                Facts {
                    kernel: "6.8.0-48-generic".into(),
                    counter_trap: Err("errno 22 (Invalid argument)".into()),
                    ..runner()
                },
            ),
            (
                "one CPU model",
                Facts {
                    midr: vec![
                        (0, Some(0x410f_d034)),
                        (1, Some(0x410f_d034)),
                        (4, Some(0x410f_d082)),
                        (5, Some(0x410f_d082)),
                    ],
                    ..runner()
                },
            ),
            (
                "one CPU model",
                Facts {
                    midr: vec![(0, Some(0x410f_d490)), (1, None)],
                    ..runner()
                },
            ),
            (
                "signal context",
                Facts {
                    sve_vl: 128,
                    ..runner()
                },
            ),
            (
                "signal context",
                Facts {
                    hwcap2: 1 << 48,
                    ..runner()
                },
            ),
            (
                "pointer authentication",
                Facts {
                    pac: Err("errno 22 (Invalid argument)".into()),
                    ..runner()
                },
            ),
        ];
        for (name, f) in cases {
            assert_eq!(failing(&f), vec![name], "{f:?}");
            assert!(refusal(&f).is_err());
        }
    }

    #[test]
    fn accepted_variants() {
        // SME (the development VM: SME, BTI, no SVE), no PAC, an SVE length at the limit,
        // and a single kind of CPU out of order.
        for f in [
            Facts {
                hwcap: HWCAP_PACA,
                hwcap2: HWCAP2_SME,
                sve_vl: 0,
                ..runner()
            },
            Facts {
                pac: Ok(false),
                ..runner()
            },
            Facts {
                sve_vl: SVE_VL_MAX,
                ..runner()
            },
            Facts {
                midr: vec![(3, Some(1)), (1, Some(1))],
                ..runner()
            },
        ] {
            assert!(failing(&f).is_empty(), "{f:?}: {:?}", checks(&f));
        }
    }

    #[test]
    fn heterogeneous_fix_pins_one_kind() {
        let f = Facts {
            midr: vec![
                (0, Some(0x410f_d034)),
                (1, Some(0x410f_d034)),
                (4, Some(0x410f_d082)),
                (5, Some(0x410f_d082)),
            ],
            ..runner()
        };
        let Err((_, fix)) = one_model(&f) else {
            panic!("two kinds accepted")
        };
        assert!(fix.contains("taskset -c 4-5"), "{fix}");
        assert_eq!(ranges(&[0, 1, 2, 3, 6, 8, 9]), "0-3,6,8-9");
    }

    #[test]
    fn x86_checks_only_the_counter_trap() {
        let f = Facts {
            arch: "x86_64",
            page_size: 16384,
            va_bits: 39,
            ..runner()
        };
        assert!(failing(&f).is_empty());
        let f = Facts {
            counter_trap: Err("errno 22".into()),
            ..f
        };
        assert_eq!(failing(&f), vec!["rdtsc trap"]);
    }
}
