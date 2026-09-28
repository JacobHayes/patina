// Class pairing: the live sys/keys_session oracle and native_workloads' full
// output/trace repeat/replay detector. No mock store or Patina-specific path.
#[cfg(target_os = "linux")]
fn main() {
    use keyring::{Entry, Error};
    let entry = Entry::new("patina-testbed", "password-user").unwrap();
    let initial = entry.get_password();
    if initial.is_ok() {
        println!("KEYRING_RESULT initial=present");
    }
    assert!(
        matches!(initial, Err(Error::NoEntry)),
        "initial credential must be absent: {initial:?}"
    );
    assert!(matches!(entry.delete_credential(), Err(Error::NoEntry)));
    assert!(matches!(entry.set_password(""), Err(Error::Invalid(_, _))));
    entry.set_password("first password").unwrap();
    assert_eq!(entry.get_password().unwrap(), "first password");
    entry.set_password("updated password").unwrap();
    std::thread::spawn(|| {
        let other = Entry::new("patina-testbed", "password-user").unwrap();
        assert_eq!(other.get_password().unwrap(), "updated password");
    })
    .join()
    .unwrap();
    entry.delete_credential().unwrap();
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    assert!(matches!(entry.delete_credential(), Err(Error::NoEntry)));
    entry.set_password("replacement password").unwrap();
    assert_eq!(entry.get_password().unwrap(), "replacement password");
    entry.delete_credential().unwrap();
    // The current split backend used by keyring 4.2, without that facade's
    // v1/cli feature bundles (which pull in other credential stores).
    keyring_core::set_default_store(linux_keyutils_keyring_store::Store::new().unwrap());
    let current = keyring_core::Entry::new("patina-testbed", "password-user").unwrap();
    assert!(matches!(
        current.get_password(),
        Err(keyring_core::Error::NoEntry)
    ));
    current.set_password("current backend password").unwrap();
    assert_eq!(current.get_password().unwrap(), "current backend password");
    current.delete_credential().unwrap();
    assert!(matches!(
        current.get_password(),
        Err(keyring_core::Error::NoEntry)
    ));
    println!(
        "KEYRING_RESULT empty,set,read,update,thread,delete,no-entry,recreate,current-backend"
    );
}

#[cfg(not(target_os = "linux"))]
fn main() {
    panic!("keyring-keyutils is a Linux-only testbed");
}
