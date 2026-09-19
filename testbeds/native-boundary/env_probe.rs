// The deterministic environment is empty and guest-owned: std::env::vars (the
// direct environ path) sees nothing, interposed getenv hides every host/control
// variable, and guest mutation lands in the deterministic map only -- it never
// pulls in, or is shadowed by, a host value of the same name. The caller runs
// this with PATINA_ENV_CANARY_HOST set in the HOST environment, so the canary
// below collides with a real ambient variable.
fn main() {
    let leaked: Vec<String> = std::env::vars_os()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    if !leaked.is_empty() {
        eprintln!("environ leaked: {}", leaked.join(","));
        std::process::exit(60);
    }
    if std::env::var_os("HOME").is_some()
        || std::env::var_os("PATH").is_some()
        || std::env::var_os("PATINA_MODE").is_some()
    {
        std::process::exit(61);
    }

    unsafe { std::env::set_var("PATINA_ENV_CANARY_HOST", "guest-owned") };
    let scanned: Vec<String> = std::env::vars()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    if scanned != ["PATINA_ENV_CANARY_HOST=guest-owned"] {
        eprintln!("environ after set_var: {}", scanned.join(","));
        std::process::exit(62);
    }
    if std::env::var("PATINA_ENV_CANARY_HOST").as_deref() != Ok("guest-owned") {
        std::process::exit(63);
    }
    unsafe { std::env::remove_var("PATINA_ENV_CANARY_HOST") };
    if std::env::vars_os().next().is_some() || std::env::var_os("PATINA_ENV_CANARY_HOST").is_some()
    {
        std::process::exit(64);
    }
    println!("NATIVE_ENV_RESULT vars=0");
}
