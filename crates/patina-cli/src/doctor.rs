//! `patina doctor`: try each host requirement for real and print one line each: `ok`, or
//! what failed and the command that fixes it. Exit 0 when the default path works, 2
//! otherwise. This is the definition of "this host is supported".

use crate::cli::{Args, Res};
use crate::host::{errno, in_child};
use serde_json::{json, Value};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

struct Check {
    name: &'static str,
    /// Needed by the default path (else only by an option, named in `name`).
    required: bool,
    result: Result<String, (String, String)>,
}

fn sysctl(name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/sys/{}", name.replace('.', "/")))
        .ok()
        .map(|s| s.trim().to_string())
}

fn on_path(exe: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(exe))
            .find(|f| f.is_file())
    })
}

fn bwrap_found() -> Result<String, (String, String)> {
    let Some(p) = on_path("bwrap") else {
        return Err((
            "bwrap is not on PATH".into(),
            "install the bubblewrap package (Debian, Ubuntu: sudo apt-get install bubblewrap)"
                .into(),
        ));
    };
    let v = Command::new(&p)
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    Ok(format!("{} ({v})", p.display()))
}

fn bwrap_sandbox() -> Result<String, (String, String)> {
    // As root, the user namespace the launcher makes (`launch::userns`).
    let userns = crate::launch::userns().map_err(|e| {
        let e = e.split(": `patina doctor`").next().unwrap_or_default();
        (e.to_string(), namespace_fix())
    })?;
    let ns = crate::launch::namespace_args(userns);
    let mut args: Vec<&str> = ns.iter().map(String::as_str).collect();
    args.extend([
        "--uid",
        "1000",
        "--gid",
        "1000",
        "--new-session",
        "--die-with-parent",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    for (l, t) in [
        ("/bin", "usr/bin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
    ] {
        args.extend(["--symlink", t, l]);
    }
    args.extend([
        "--proc", "/proc", "--dev", "/dev", "--size", "1048576", "--tmpfs", "/tmp", "true",
    ]);
    let mut cmd = Command::new("bwrap");
    cmd.args(&args).stdin(Stdio::null());
    if let Some(fd) = userns {
        use std::os::unix::process::CommandExt;
        // bwrap reads the namespace from the descriptor: kept across exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let out = cmd
        .output()
        .map_err(|e| (format!("bwrap: {e}"), "install bubblewrap".to_string()))?;
    if out.status.success() {
        return Ok("bwrap creates the sandbox (user, pid, net, mount namespaces; tmpfs)".into());
    }
    let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
    Err((format!("bwrap failed: {err}"), namespace_fix()))
}

/// What lets bwrap make its namespaces here.
fn namespace_fix() -> String {
    // A container's default profile denies them (seccomp, AppArmor) and masks parts of /proc,
    // which keeps a new /proc from being mounted.
    if ["/.dockerenv", "/run/.containerenv"]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        return "in a container: run it with --security-opt seccomp=unconfined \
                --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
                (or --privileged)"
            .into();
    }
    if sysctl("kernel.apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        "AppArmor restricts unprivileged user namespaces and bwrap has no profile here: \
         sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0, \
         or install an AppArmor profile for /usr/bin/bwrap (Ubuntu's apparmor package ships bwrap-userns-restrict)"
            .into()
    } else if sysctl("kernel.unprivileged_userns_clone").as_deref() == Some("0") {
        "sudo sysctl -w kernel.unprivileged_userns_clone=1".into()
    } else {
        "unprivileged user namespaces are unavailable".into()
    }
}

static TRAPPED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigsys(_: libc::c_int) {
    TRAPPED.store(true, Ordering::SeqCst);
}

/// A filter that traps `getppid` with SIGSYS, then a `getppid` that must be trapped.
fn seccomp_child() -> i32 {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return errno();
        }
        libc::signal(libc::SIGSYS, on_sigsys as *const () as libc::sighandler_t);
        let filter = [
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: libc::SYS_getppid as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_TRAP,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut _,
        };
        if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog) != 0 {
            return errno();
        }
        libc::syscall(libc::SYS_getppid);
        if TRAPPED.load(Ordering::SeqCst) {
            0
        } else {
            libc::ENOSYS
        }
    }
}

fn personality_child() -> i32 {
    unsafe {
        if libc::personality(libc::ADDR_NO_RANDOMIZE as libc::c_ulong) < 0 {
            return errno();
        }
        if libc::personality(0xffff_ffff) & libc::ADDR_NO_RANDOMIZE == 0 {
            return libc::EPERM;
        }
    }
    0
}

pub const CONTAINER_FIX: &str =
    "the process runs under a restrictive seccomp profile: in Docker, --security-opt seccomp=unconfined";

/// One real run of `/usr/bin/true` through this binary, in a scratch directory.
fn sandbox_run() -> Result<String, (String, String)> {
    let dir = std::env::temp_dir().join(format!("patina-doctor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let exe = std::env::current_exe().map_err(|e| (e.to_string(), String::new()))?;
    let out = Command::new(exe)
        .args(["run", "--timeout", "60", "--format", "json", "--out"])
        .arg(dir.join("run"))
        .args(["--", "/usr/bin/true"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| (e.to_string(), String::new()))?;
    let _ = std::fs::remove_dir_all(&dir);
    let r: Value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    if out.status.success() {
        return Ok(format!(
            "a run of /usr/bin/true is ok ({} ms)",
            r["wall_ms"]
        ));
    }
    let msg = r["message"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| String::from_utf8_lossy(&out.stderr).trim().to_string());
    Err((
        format!("a run of /usr/bin/true failed: {} {msg}", r["outcome"]),
        format!(
            "the runtime runs from a file under $XDG_CACHE_HOME/patina (default ~/.cache/patina); it must allow exec. {}",
            "Report anything else with this output."
        ),
    ))
}

fn fs_type(p: &std::path::Path) -> String {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return "unknown".into();
    }
    match st.f_type as u64 {
        0xEF53 => "ext4".into(),
        0x5846_5342 => "xfs".into(),
        0x9123_683E => "btrfs".into(),
        0x0102_1994 => "tmpfs".into(),
        0x794C_7630 => "overlay".into(),
        0x2FC1_2FC1 => "zfs".into(),
        0x6969 => "nfs".into(),
        t => format!("{t:#x}"),
    }
}

fn cpu() -> (String, String) {
    let info = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let field = |k: &str| {
        info.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    (field("vendor_id"), field("model name"))
}

pub fn doctor(args: &Args) -> Res<ExitCode> {
    let facts = crate::host::Facts::probe(None);
    let (name, result) = crate::host::platform(&facts);
    let mut checks = vec![Check {
        name,
        required: true,
        result,
    }];
    let bwrap = bwrap_found();
    let have_bwrap = bwrap.is_ok();
    checks.push(Check {
        name: "bwrap",
        required: true,
        result: bwrap,
    });
    checks.push(Check {
        name: "user namespaces",
        required: true,
        result: if have_bwrap {
            bwrap_sandbox()
        } else {
            Err((
                "not tried: no bwrap".into(),
                "install bubblewrap first".into(),
            ))
        },
    });
    let child = |f: fn() -> i32, ok: &str| -> Result<String, (String, String)> {
        in_child(f)
            .map(|_| ok.to_string())
            .map_err(|e| (e, CONTAINER_FIX.to_string()))
    };
    checks.push(Check {
        name: "seccomp",
        required: true,
        result: child(
            seccomp_child,
            "a SECCOMP_RET_TRAP filter traps a call with SIGSYS",
        ),
    });
    checks.push(Check {
        name: "personality",
        required: true,
        result: child(personality_child, "ADDR_NO_RANDOMIZE can be set"),
    });
    for (name, result) in crate::host::checks(&facts) {
        checks.push(Check {
            name,
            required: true,
            result,
        });
    }
    let ready = checks.iter().all(|c| c.result.is_ok());
    checks.push(Check {
        name: "sandbox run",
        required: true,
        result: if ready {
            sandbox_run()
        } else {
            Err((
                "not tried: a requirement above failed".into(),
                String::new(),
            ))
        },
    });
    let (name, result) = crate::host::spin_probes(&facts);
    checks.push(Check {
        name,
        required: false,
        result,
    });
    checks.push(Check {
        name: "branch counters (pmu, optional)",
        required: false,
        result: {
            use crate::launcher::pmu::Unavailable as U;
            crate::launcher::pmu::available()
                .map(|ev| format!("event {ev:#x} opens"))
                .map_err(|e| match e {
                    U::Arch => ("not supported on arm64".into(), String::new()),
                    U::Cpu(m) => (
                        format!("not supported on this CPU, {m} (supported: AMD Zen 5)"),
                        String::new(),
                    ),
                    U::Permission(m) => (
                        format!("supported, but needs CAP_PERFMON: {m}"),
                        "sudo setcap cap_perfmon+ep $(command -v patina)".into(),
                    ),
                    U::NoPmu(m) => (
                        format!("no PMU exposed (virtual machine?): {m}"),
                        "run on bare metal, or a VM that passes the PMU through".into(),
                    ),
                })
        },
    });
    // Counter preemption's broker reads a thread's pidfd; not asked on arm64 (no counters).
    if cfg!(target_arch = "x86_64") {
        let pidfd_thread =
            unsafe { libc::syscall(libc::SYS_pidfd_open, libc::gettid(), libc::O_EXCL) };
        checks.push(Check {
            name: "pidfd of a thread (pmu, optional)",
            required: false,
            result: if pidfd_thread >= 0 {
                unsafe { libc::close(pidfd_thread as i32) };
                Ok("pidfd_open(PIDFD_THREAD) works".into())
            } else {
                Err((
                    format!(
                        "pidfd_open(PIDFD_THREAD): {}",
                        std::io::Error::last_os_error()
                    ),
                    "kernel 6.9 or newer".into(),
                ))
            },
        });
    }

    let (vendor, model) = cpu();
    let out_dir = std::env::current_dir().unwrap_or_else(|_| "/".into());
    let mut host = json!({
        "kernel": sysctl("kernel.osrelease"),
        "cpu_vendor": vendor,
        "cpu_model": model,
        "fs_under_output": fs_type(&out_dir),
        "pipe_user_pages_soft": sysctl("fs.pipe-user-pages-soft"),
        "apparmor_restrict_unprivileged_userns": sysctl("kernel.apparmor_restrict_unprivileged_userns"),
    });
    host.as_object_mut().unwrap().extend(facts.info());
    let ok = checks.iter().all(|c| !c.required || c.result.is_ok());
    if args.json() {
        let cs: Vec<Value> = checks
            .iter()
            .map(|c| match &c.result {
                Ok(d) => json!({"name": c.name, "required": c.required, "ok": true, "detail": d}),
                Err((d, f)) => json!({"name": c.name, "required": c.required, "ok": false, "detail": d, "fix": f}),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"ok": ok, "checks": cs, "host": host})).unwrap()
        );
    } else {
        for c in &checks {
            match &c.result {
                Ok(d) => println!("ok    {:<34} {d}", c.name),
                Err((d, f)) => {
                    let tag = if c.required { "FAIL" } else { "off" };
                    println!("{tag:<5} {:<34} {d}", c.name);
                    if !f.is_empty() {
                        println!("      {:<34} fix: {f}", "");
                    }
                }
            }
        }
        for (k, v) in host.as_object().unwrap() {
            let v = v
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| v.to_string());
            println!("info  {k:<34} {v}");
        }
        println!(
            "{}",
            if ok {
                "this host can run patina"
            } else {
                "this host cannot run patina yet: see FAIL above"
            }
        );
    }
    Ok(ExitCode::from(if ok { 0 } else { 2 }))
}
