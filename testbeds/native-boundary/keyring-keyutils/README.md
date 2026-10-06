# Linux keyutils credentials

A self-contained password lifecycle guest: initially absent, set/read, update,
read from another thread, delete/NoEntry, then recreate. No mock store, D-Bus,
Secret Service, host capture, or Patina-specific guest path.

## Source evidence and pins

The lockfile pins `keyring` 3.6.3 with **only** `linux-native`, plus the current
split backend `linux-keyutils-keyring-store` 1.0.0 / `keyring-core` 1.0.0. Both use
`linux-keyutils` 0.2.5. Both paths execute in this guest.

The current `keyring` facade (4.2.0) requires `v1` or `cli`, whose feature bundles
include other credential stores. Its own documentation directs backend-specific
applications to `keyring-core` plus the selected store instead. The guest uses
that supported interface for the current backend, and also tests 3.6.3's
single-crate Linux-only interface. Both fit the repository's Rust 1.99 toolchain;
the split keeps this guest focused on the Linux backend.

Published sources inspected:

- [keyring 3.6.3 keyutils.rs](https://docs.rs/crate/keyring/3.6.3/source/src/keyutils.rs)
- [keyring 4.2.0 lib.rs](https://docs.rs/crate/keyring/4.2.0/source/src/lib.rs)
- [linux-keyutils-keyring-store 1.0.0 cred.rs](https://docs.rs/crate/linux-keyutils-keyring-store/1.0.0/source/src/cred.rs)
- [linux-keyutils 0.2.5](https://docs.rs/crate/linux-keyutils/0.2.5/source/src/)

| Backend action | Actual kernel call |
|---|---|
| Construct | `keyctl(GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, create=0)` |
| Construct, optional persistent cache | `keyctl(GET_PERSISTENT, uid=UINT_MAX, KEY_SPEC_SESSION_KEYRING)`; the crate discards errors, but an unmodeled Patina operation must still stop |
| Set/update | `add_key("user", description, bytes, length, session_serial)`; a matching live key updates in place |
| Get/delete/credential existence | `keyctl(SEARCH, session_serial, "user", description, destination=0)` |
| Set/get | `keyctl(LINK, key_serial, persistent_serial)` when available; get also re-links to the session |
| Get | `keyctl(READ, key_serial, buffer, 65536)` |
| Delete | `keyctl(INVALIDATE, key_serial)` |

No backend calls to the user/user-session rings, `request_key`, explicit UPDATE,
JOIN_SESSION_KEYRING, UNLINK, REVOKE, SETPERM, DESCRIBE or SET_TIMEOUT. Those are library methods, not
calls made by this credential backend. No permission mask or timeout is supplied;
the kernel's default user-key mask is `3f010000`. Empty passwords are rejected
before a syscall. Missing, expired and revoked-key errors map to NoEntry.
AccessDenied maps to NoEntry in 3.6.3 and NoStorageAccess in the current store.
The 3.6.3 default description is `keyring-rs:user@service`; the current store uses
`keyring:user@service`.

## Model boundary

Per [SCOPE rule 1](../../../docs/SCOPE.md#rules-for-new-surface), this measured
call set motivates session and persistent keyrings, not a general key service.
Each run shares one deliberately empty `_ses` (virtual uid/gid, `3f030000`):
the login/service ring's shape without pam_keyinit's user-ring link or systemd's
invocation_id key. No per-thread session bookkeeping is needed. The current
user's persistent ring starts empty on first use (`_persistent.<uid>`,
INVALID_GID displayed as 65534, `1f030000`). Neither survives a run or consults
the host. General nested rings, all JOIN_SESSION_KEYRING calls (anonymous too),
UNLINK, SEARCH with a destination, user/user-session/thread rings, SETPERM and
SET_TIMEOUT remain named stops. The backend needs none of those operations.

Keys count once against their owner's quota, regardless of link count. Session
rings and their links count; persistent rings and their links are quota-exempt.
Invalidation removes every link, frees the key and reclaims quota before the
next call. This chooses the valid 6.8 interleaving where `key_invalidate`'s
`key_schedule_gc_links` worker runs immediately. A failed lookup with SysAdmin
granted stops at that capability's override. Revocation is unchanged: collection
after `gc_delay` remains a named stop, as do collection-dependent answers after
the last process-keyring holder exits and persistent expiry after three virtual
days (refreshed by successful GET_PERSISTENT).

## Verification

```sh
mise exec -- cargo test -p cargo-patina --test native_workloads keyutils_password
PATINA_REQUIRE_HOST_ORACLE=1 mise exec -- cargo test -p cargo-patina --test native_conformance sys_keys
```

The workload test audits without allowances, plants matching names in an isolated
host session when keyctl is available, then runs a stock native build which must
print `KEYRING_RESULT initial=present` on stdout and exit 101 on its initial
absence assertion. The harness checks this protocol, not panic text. The shim
build must still start empty. The test invalidates its canaries on success or
panic, including any persistent links made by the native backend. It checks
five seeds, byte-identical repeated records and flag-free replay.
A restricted host reports missing canary evidence; requiring the host oracle
makes that fatal. The guest lifecycle still runs without host keyctl support.

For scenarios declaring `Need::Keys`, the native harness joins a fresh anonymous
ring in the child's pre-exec hook, leaving the harness thread's credentials
untouched. This isolates both key scenarios from the ambient session;
`sys/keys_session` itself never joins or unlinks. It checks metadata,
shared access, search/request (unknown SEARCH type returns ENOKEY), update,
links, persistent recursion, invalidate/recreate and revoke. Native persistent
keys use process-unique names and are invalidated. A bounded loop allows native
collection to settle, then requires exactly ENOKEY from read and search; Patina
passes on the first attempt. Both key scenarios declare `Need::Keys`; a keyctl
denial is not a false pass.

Class pairing: the live kernel differential, default-deny strace containment,
and output/trace repeat/replay detectors. RED before the model: the real crate
aborted on the session-keyring stop. The canary red leg proves that host-state
visibility fails the guest's absence check.
Linux-only dependencies and test; macOS compiles but does not execute keyutils.
