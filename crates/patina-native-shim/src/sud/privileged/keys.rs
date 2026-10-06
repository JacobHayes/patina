//! The key retention service (security/keys/), as 6.8 answers a caller
//! keeping its own keys: `add_key`, `request_key` and the `keyctl`
//! operations on them.
//!
//! The guest starts with one empty session keyring: `_ses`, the virtual
//! credential's uid/gid, `KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ`. This
//! matches the shape, not the contents, of an Ubuntu login/service session:
//! pam_keyinit links the user keyring and systemd adds an invocation_id key.
//! Patina deliberately starts empty and shares one ring across the run.
//! Session joins are unmodeled. No host keyring or serial is ever consulted.
//!
//! Workload: Rust keyring's Linux keyutils backend gets the session and
//! persistent rings, adds `user` keys, searches, links, reads and invalidates
//! them (source/versions in testbeds/native-boundary/keyring-keyutils/README.md).
//! `GET_PERSISTENT` creates an initially empty per-run `_persistent.<uid>`
//! ring and links it to the destination. It has INVALID_GID and permission
//! `1f030000`; describe maps its gid to 65534. Its three-day expiry is reset
//! on each successful get; reaching expiry stops by name. This one subtree
//! is supported, not an arbitrary nested key service.
//!
//! A process keyring belongs to credentials, which are per thread: the
//! thread that makes one (`_pid`, the caller's ids, `KEY_POS_ALL |
//! KEY_USR_VIEW`, on demand) holds it, and so does every thread created
//! after, by it or by another holder (`copy_creds`). A thread that existed
//! before has none, and makes its own on demand. A thread possesses its
//! keyring and the keys linked there, and holds every permission their
//! masks grant a possessor; for any other key it holds only its owner's
//! (`key_task_permission`), which for a key made with the default mask is
//! view. When the last thread holding a keyring exits, the collector frees
//! it and its keys at a time the model does not know: naming them, or a
//! quota answer their charge decides, stops by name.
//!
//! Serials are the kernel's random ones in shape (31 bits, from 3), but
//! handed out in sequence from [`FIRST_SERIAL`], so a run is reproducible.
//! The user's quota (`kernel.keys.maxkeys`/`maxbytes`) counts the keys the
//! guest owns and their bytes (description, payload, 4 a link), including
//! the session ring and its user keys. The persistent ring and its links are
//! not charged (KEY_ALLOC_NOT_IN_QUOTA); its user keys still are. Invalidation
//! removes the key from every ring and frees its quota before the next call:
//! the permitted 6.8 interleaving where key_schedule_gc_links' worker runs
//! immediately. Revocation is different: a revoked key stays until
//! the collector would remove it (`kernel.keys.gc_delay` past its
//! revocation); the removal is not modeled, so any key call from then on,
//! however much later, stops by name. A key displaced by a new one of the
//! same description is gone at once (the kernel frees it once its last
//! reference drops); displacement from one ring never frees another ring's key.
//!
//! Where the model ends by name: other key types, arbitrary nested keyrings,
//! all session joins, UNLINK, SEARCH with a destination, thread/user/user-session
//! keyrings, request-key upcalls, revoking or invalidating a keyring, reading
//! multiple links (kernel hash order), collection after the last process-ring
//! holder exits, revoked-key collection and persistent expiry. The modeled
//! keyctl set is GET_KEYRING_ID, GET_PERSISTENT, SEARCH without a destination,
//! LINK, INVALIDATE, UPDATE, REVOKE, CHOWN, DESCRIBE, READ, CAPABILITIES.
//! SETPERM and SET_TIMEOUT are not called by the backend and remain named stops.
//! State is bounded by the user quota except for the exempt persistent links;
//! key operations scan only this run's keys. The session adds no thread lifecycle
//! bookkeeping. Other syscall paths are untouched. No trace events are added;
//! the state reconstructs identically on replay.

use super::{Answer, Unmodeled, refuse};
use crate::identity::Credential;
use crate::registry::{Capability, KERNEL_CONFIG};
use linux_raw_sys::errno;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_int;
use std::sync::{LazyLock, Mutex};

/// The first serial the model hands out.
const FIRST_SERIAL: i32 = 0x1000_0000;

const KEY_SPEC_THREAD_KEYRING: i32 = -1;
const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
const KEY_SPEC_USER_KEYRING: i32 = -4;
const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
const KEY_SPEC_GROUP_KEYRING: i32 = -6;

/// `KEY_POS_ALL | KEY_USR_VIEW`: the process keyring's mask, and a `user`
/// key's default (every possessor right, since the type reads and updates,
/// and view to its owner).
const DEFAULT_PERM: u32 = 0x3f01_0000;
/// `KEY_GRP_ALL`: the group's byte of a mask.
const GROUP_ALL: u32 = 0x3f00;

/// The permissions a lookup needs (`KEY_NEED_*`), as bits of a mask's byte.
const NEED_VIEW: u32 = 0x01;
const NEED_READ: u32 = 0x02;
const NEED_WRITE: u32 = 0x04;
const NEED_SEARCH: u32 = 0x08;
const NEED_LINK: u32 = 0x10;
const NEED_SETATTR: u32 = 0x20;
const SESSION_PERM: u32 = 0x3f03_0000;
const PERSISTENT_PERM: u32 = 0x1f03_0000;
const PERSISTENT_EXPIRY: u64 = 3 * 24 * 3600;

/// `add_key`'s payload ceiling, `KEY_MAX_DESC_SIZE`, and the type name's
/// buffer.
const MAX_PAYLOAD: u64 = 1024 * 1024 - 1;
const KEY_MAX_DESC_SIZE: usize = 4096;
const TYPE_BUFFER: usize = 32;
/// `user_preparse`'s ceiling on a payload.
const MAX_USER_PAYLOAD: usize = 32767;
/// `keyctl_update_key`'s and `request_key`'s callout ceilings.
const PAGE_SIZE: usize = 4096;
/// `KEYQUOTA_LINK_BYTES`: what a link in a keyring costs its owner.
const LINK_BYTES: usize = 4;

/// The `keyctl` operations: 6.8 defines 0 through 32.
const KEYCTL_GET_KEYRING_ID: i32 = 0;
const KEYCTL_UPDATE: i32 = 2;
const KEYCTL_REVOKE: i32 = 3;
const KEYCTL_CHOWN: i32 = 4;
const KEYCTL_DESCRIBE: i32 = 6;
const KEYCTL_LINK: i32 = 8;
const KEYCTL_SEARCH: i32 = 10;
const KEYCTL_READ: i32 = 11;
const KEYCTL_INVALIDATE: i32 = 21;
const KEYCTL_GET_PERSISTENT: i32 = 22;
const KEYCTL_CAPABILITIES: i32 = 31;
const KEYCTL_NAMES: [&str; 33] = [
    "KEYCTL_GET_KEYRING_ID",
    "KEYCTL_JOIN_SESSION_KEYRING",
    "KEYCTL_UPDATE",
    "KEYCTL_REVOKE",
    "KEYCTL_CHOWN",
    "KEYCTL_SETPERM",
    "KEYCTL_DESCRIBE",
    "KEYCTL_CLEAR",
    "KEYCTL_LINK",
    "KEYCTL_UNLINK",
    "KEYCTL_SEARCH",
    "KEYCTL_READ",
    "KEYCTL_INSTANTIATE",
    "KEYCTL_NEGATE",
    "KEYCTL_SET_REQKEY_KEYRING",
    "KEYCTL_SET_TIMEOUT",
    "KEYCTL_ASSUME_AUTHORITY",
    "KEYCTL_GET_SECURITY",
    "KEYCTL_SESSION_TO_PARENT",
    "KEYCTL_REJECT",
    "KEYCTL_INSTANTIATE_IOV",
    "KEYCTL_INVALIDATE",
    "KEYCTL_GET_PERSISTENT",
    "KEYCTL_DH_COMPUTE",
    "KEYCTL_PKEY_QUERY",
    "KEYCTL_PKEY_ENCRYPT",
    "KEYCTL_PKEY_DECRYPT",
    "KEYCTL_PKEY_SIGN",
    "KEYCTL_PKEY_VERIFY",
    "KEYCTL_RESTRICT_KEYRING",
    "KEYCTL_MOVE",
    "KEYCTL_CAPABILITIES",
    "KEYCTL_WATCH_KEY",
];

/// The key options of the pinned configuration that `KEYCTL_CAPABILITIES`
/// reports: `CONFIG_PERSISTENT_KEYRINGS`, `CONFIG_KEY_DH_OPERATIONS`,
/// `CONFIG_ASYMMETRIC_KEY_TYPE`, `CONFIG_BIG_KEYS` and
/// `CONFIG_KEY_NOTIFICATIONS`.
const PERSISTENT_KEYRINGS: bool = true;
const KEY_DH_OPERATIONS: bool = true;
const ASYMMETRIC_KEY_TYPE: bool = true;
const BIG_KEYS: bool = false;
const KEY_NOTIFICATIONS: bool = true;

/// `keyrings_capabilities` (keyctl.c): what the kernel's key service
/// supports, as `KEYCTL_CAPS0_*` and `KEYCTL_CAPS1_*` bits. The operations
/// it names are the kernel's, whether or not the model has them.
const CAPABILITIES: [u8; 2] = [
    0x01 // CAPABILITIES
        | flag(PERSISTENT_KEYRINGS, 0x02)
        | flag(KEY_DH_OPERATIONS, 0x04)
        | flag(ASYMMETRIC_KEY_TYPE, 0x08)
        | flag(BIG_KEYS, 0x10)
        | 0x20 // INVALIDATE
        | 0x40 // RESTRICT_KEYRING
        | 0x80, // MOVE
    0x01 // NS_KEYRING_NAME
        | 0x02 // NS_KEY_TAG
        | flag(KEY_NOTIFICATIONS, 0x04),
];

/// `bit` where a configuration option `on` sets it (`IS_ENABLED`).
const fn flag(on: bool, bit: u8) -> u8 {
    if on { bit } else { 0 }
}

/// The types the pinned kernel registers besides the two modeled ones:
/// its built-in key types (`CONFIG_ASYMMETRIC_KEY_TYPE`, `TRUSTED_KEYS`,
/// `ENCRYPTED_KEYS`, `SYSTEM_BLACKLIST_KEYRING`, `DNS_RESOLVER`,
/// `FS_ENCRYPTION`, and `logon`). A module's type exists only once the
/// module is loaded, which the virtual machine never does.
const UNMODELED_TYPES: &[&[u8]] = &[
    b"logon",
    b"asymmetric",
    b"trusted",
    b"encrypted",
    b"blacklist",
    b"dns_resolver",
    b"fscrypt-provisioning",
];

/// A key's type and payload.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Payload {
    /// A `user` key's data; empty once revoked.
    User(Vec<u8>),
    /// A keyring's links, as serials.
    Keyring(Vec<i32>),
}

struct Key {
    payload: Payload,
    description: Vec<u8>,
    uid: u32,
    gid: u32,
    perm: u32,
    /// When it was revoked, in virtual seconds.
    revoked_at: Option<u64>,
    /// Persistent keyrings and their links are KEY_ALLOC_NOT_IN_QUOTA.
    in_quota: bool,
}

impl Key {
    fn type_name(&self) -> &'static str {
        match self.payload {
            Payload::User(_) => "user",
            Payload::Keyring(_) => "keyring",
        }
    }

    /// The bytes it charges its owner's quota: its description and NUL,
    /// its data, 4 a link.
    fn quota_bytes(&self) -> usize {
        self.description.len()
            + 1
            + match &self.payload {
                Payload::User(data) => data.len(),
                Payload::Keyring(links) => LINK_BYTES * links.len(),
            }
    }
}

/// Where an operation stops short of its answer.
#[derive(Debug)]
enum Stop {
    Refuse(u32),
    End(Unmodeled),
}

impl From<u32> for Stop {
    fn from(code: u32) -> Self {
        Stop::Refuse(code)
    }
}

fn unmodeled(what: impl Into<String>) -> Stop {
    Stop::End(Unmodeled::Path(what.into()))
}

fn answer(outcome: Result<i64, Stop>) -> Answer {
    match outcome {
        Ok(value) => Ok(value),
        Err(Stop::Refuse(code)) => refuse(code),
        Err(Stop::End(end)) => Err(end),
    }
}

/// `key_task_permission`: the owner's permissions, else a group's the
/// caller shares (where the mask grants its group any), else others', and a
/// possessor's on top; whether they hold `need`.
fn permitted(key: &Key, credential: &Credential, possessed: bool, need: u32) -> bool {
    let mut granted = if key.uid == credential.uid {
        key.perm >> 16
    } else if key.perm & GROUP_ALL != 0
        && (key.gid == credential.gid || credential.groups.contains(&key.gid))
    {
        key.perm >> 8
    } else {
        key.perm
    };
    if possessed {
        granted |= key.perm >> 24;
    }
    granted & need == need
}

/// The guest's keys.
struct Keys {
    keys: BTreeMap<i32, Key>,
    /// Each thread's process keyring (`cred->process_keyring`), by thread
    /// id; a thread absent has none.
    holders: BTreeMap<c_int, i32>,
    /// The keyrings no thread holds any more, and the keys linked in them:
    /// the collector's, freed at a time the model does not know.
    collecting: BTreeSet<i32>,
    next_serial: i32,
    persistent: Option<(i32, u64)>,
}

/// Where the model ends at a keyring its last thread left.
const COLLECTING: &str = "key collection after the last process-keyring credential reference (the collector frees keys and links at a time the model does not know)";

static KEYS: LazyLock<Mutex<Keys>> = LazyLock::new(|| Mutex::new(Keys::new()));

/// The guest's string at `address` as `strncpy_from_user` into `max` bytes
/// reads it: `EFAULT` for a byte before its NUL that cannot be read, `None`
/// when no NUL comes within `max` bytes.
fn guest_string(address: u64, max: usize) -> Result<Option<Vec<u8>>, u32> {
    let mut string = Vec::new();
    let mut at = address as usize;
    while string.len() < max {
        let chunk = (4096 - at % 4096).min(max - string.len());
        let bytes = crate::uaccess::read_bytes(at, chunk).map_err(|_| errno::EFAULT)?;
        if let Some(end) = bytes.iter().position(|&byte| byte == 0) {
            string.extend_from_slice(&bytes[..end]);
            return Ok(Some(string));
        }
        string.extend_from_slice(&bytes);
        at += chunk;
    }
    Ok(None)
}

/// `strndup_user(address, max)`: `EFAULT`, or `EINVAL` for a string with no
/// NUL within `max` bytes.
fn guest_strndup(address: u64, max: usize) -> Result<Vec<u8>, u32> {
    guest_string(address, max)?.ok_or(errno::EINVAL)
}

/// `key_get_type_from_user`: `EFAULT`, `EINVAL` for an empty name or one
/// that fills the 32-byte buffer, `EPERM` for an internal (`.`) type.
fn type_from_user(address: u64) -> Result<Vec<u8>, u32> {
    match guest_string(address, TYPE_BUFFER)? {
        Some(name) if name.is_empty() => Err(errno::EINVAL),
        Some(name) if name[0] == b'.' => Err(errno::EPERM),
        Some(name) => Ok(name),
        None => Err(errno::EINVAL),
    }
}

/// What `key_type_lookup` finds for a type name.
enum KeyType {
    User,
    Keyring,
    Unmodeled,
    Unknown,
}

fn key_type(name: &[u8]) -> KeyType {
    match name {
        b"user" => KeyType::User,
        b"keyring" => KeyType::Keyring,
        _ if UNMODELED_TYPES.contains(&name) => KeyType::Unmodeled,
        _ => KeyType::Unknown,
    }
}

fn unmodeled_type(name: &[u8]) -> Stop {
    unmodeled(format!("the key type {:?}", String::from_utf8_lossy(name)))
}

/// Virtual seconds, as the collector reads the clock.
fn now_seconds() -> u64 {
    crate::with_context_raw(|context| context.monotonic_now_unrecorded()).unwrap_or(0)
        / 1_000_000_000
}

impl Keys {
    fn new() -> Self {
        let credential = crate::identity::credential();
        let mut keys = Self {
            keys: BTreeMap::new(),
            holders: BTreeMap::new(),
            collecting: BTreeSet::new(),
            next_serial: FIRST_SERIAL,
            persistent: None,
        };
        // Materialized on first use, but reserved before any guest allocation:
        // the initial session exists even for GET_KEYRING_ID(create=false).
        keys.allocate(Self::ring(credential, b"_ses".to_vec(), SESSION_PERM, true));
        keys
    }

    fn ring(credential: &Credential, description: Vec<u8>, perm: u32, in_quota: bool) -> Key {
        Key {
            payload: Payload::Keyring(Vec::new()),
            description,
            uid: credential.uid,
            gid: credential.gid,
            perm,
            revoked_at: None,
            in_quota,
        }
    }

    /// The model ends where the collector would remove a revoked key.
    fn collect(&self, now: u64) -> Result<(), Stop> {
        if self.persistent.is_some_and(|(_, expires)| now >= expires) {
            return Err(unmodeled("persistent keyring expiry and collection"));
        }
        let collectable = self.keys.values().any(|key| {
            key.revoked_at
                .is_some_and(|revoked| now >= revoked.saturating_add(KERNEL_CONFIG.keys_gc_delay))
        });
        if collectable {
            return Err(unmodeled(
                "collecting a revoked key past kernel.keys.gc_delay",
            ));
        }
        Ok(())
    }

    /// The user's quota: `EDQUOT` unless `bytes` more fit, and with
    /// `new_key` one more key. The keys the collector is freeing count
    /// until it runs: where they decide the answer, the model ends.
    fn charge(&self, new_key: bool, bytes: usize) -> Result<(), Stop> {
        let fits = |collected: bool| {
            let (count, used) = self
                .keys
                .iter()
                .filter(|(serial, key)| {
                    key.in_quota && (!collected || !self.collecting.contains(serial))
                })
                .fold((0, 0), |(count, used), (_, key)| {
                    (count + 1, used + key.quota_bytes())
                });
            (!new_key || count < KERNEL_CONFIG.keys_maxkeys as usize)
                && used + bytes <= KERNEL_CONFIG.keys_maxbytes as usize
        };
        match (fits(false), fits(true)) {
            (true, _) => Ok(()),
            (false, false) => Err(errno::EDQUOT.into()),
            (false, true) => Err(unmodeled(COLLECTING)),
        }
    }

    /// A new thread `child` of `parent` shares its creator's keyring.
    fn spawned(&mut self, parent: c_int, child: c_int) {
        if let Some(&ring) = self.holders.get(&parent) {
            self.holders.insert(child, ring);
        }
    }

    /// Thread `tid` exited, giving up its keyring; the last holder's going
    /// leaves it, and the keys linked in it, to the collector.
    fn exited(&mut self, tid: c_int) {
        if let Some(ring) = self.holders.remove(&tid) {
            self.release_ring(ring);
        }
    }

    fn release_ring(&mut self, ring: i32) {
        if self.holders.values().any(|&id| id == ring) {
            return;
        }
        self.collecting.insert(ring);
        if let Payload::Keyring(links) = &self.keys[&ring].payload {
            let uncertain: Vec<_> = links.iter().copied().filter(|&id| {
                self.persistent.map(|p| p.0) != Some(id) && !self.keys.iter().any(|(&other, key)| {
                    other != ring && !self.collecting.contains(&other)
                        && matches!(&key.payload, Payload::Keyring(links) if links.contains(&id))
                })
            }).collect();
            self.collecting.extend(uncertain);
        }
    }

    /// Whether thread `tid` possesses `serial`: its keyring, or a key
    /// linked there.
    fn possessed(&self, tid: c_int, serial: i32) -> bool {
        self.holders
            .get(&tid)
            .copied()
            .into_iter()
            .chain([FIRST_SERIAL])
            .any(|ring| self.reaches(ring, serial))
    }

    fn reaches(&self, ring: i32, serial: i32) -> bool {
        ring == serial
            || matches!(&self.keys[&ring].payload, Payload::Keyring(links)
            if links.iter().any(|&id| id == serial || self.reaches(id, serial)))
    }

    /// Drop an unreferenced user key; never delete a key still linked elsewhere.
    fn release_key(&mut self, serial: i32) {
        if matches!(self.keys[&serial].payload, Payload::User(_))
            && !self.keys.values().any(
                |key| matches!(&key.payload, Payload::Keyring(links) if links.contains(&serial)),
            )
        {
            self.keys.remove(&serial);
            self.collecting.remove(&serial);
        }
    }

    fn link(&mut self, serial: i32, ring: i32) -> Result<(), Stop> {
        let Payload::Keyring(links) = &self.keys[&ring].payload else {
            return Err(errno::ENOTDIR.into());
        };
        let key = &self.keys[&serial];
        let displaced = links.iter().copied().find(|id| {
            self.keys[id].type_name() == key.type_name()
                && self.keys[id].description == key.description
        });
        // __key_link_begin reserves quota before __key_link_check_live_key
        // checks cycles (and our boundary for unsupported nested rings).
        if displaced.is_none() && self.keys[&ring].in_quota {
            self.charge(false, LINK_BYTES)?;
        }
        if matches!(key.payload, Payload::Keyring(_)) {
            if serial == ring {
                return Err(errno::EDEADLK.into());
            }
            if self.persistent.map(|p| p.0) != Some(serial) {
                return Err(unmodeled(
                    "nested keyrings other than the persistent keyring",
                ));
            }
        }
        if displaced == Some(serial) {
            return Ok(());
        }
        let Payload::Keyring(links) = &mut self.keys.get_mut(&ring).unwrap().payload else {
            unreachable!()
        };
        links.retain(|id| Some(*id) != displaced);
        links.push(serial);
        if let Some(old) = displaced {
            self.release_key(old);
        }
        Ok(())
    }

    /// Choose immediate invalidation collection: remove every link before
    /// freeing the key and its quota. Revocation keeps its separate gc_delay.
    fn invalidate(&mut self, serial: i32) -> Result<(), Stop> {
        if matches!(self.keys[&serial].payload, Payload::Keyring(_)) {
            return Err(unmodeled("invalidating a keyring"));
        }
        for key in self.keys.values_mut() {
            if let Payload::Keyring(links) = &mut key.payload {
                links.retain(|&id| id != serial);
            }
        }
        self.release_key(serial);
        Ok(())
    }

    /// Breadth first at each ring, then its only modeled subtree (persistent).
    fn search(
        &self,
        credential: &Credential,
        ring: i32,
        description: &[u8],
        possessed: bool,
    ) -> Result<i32, Stop> {
        let Payload::Keyring(links) = &self.keys[&ring].payload else {
            return Err(errno::ENOTDIR.into());
        };
        if !permitted(&self.keys[&ring], credential, possessed, NEED_SEARCH) {
            return Err(errno::EACCES.into());
        }
        let mut error = errno::ENOKEY;
        if let Some(serial) = self.linked_user_key(ring, description, true) {
            let key = &self.keys[&serial];
            if key.revoked_at.is_some() {
                error = errno::EKEYREVOKED;
            } else if !permitted(key, credential, possessed, NEED_SEARCH) {
                error = errno::EACCES;
            } else {
                return Ok(serial);
            }
        }
        for &id in links {
            if matches!(self.keys[&id].payload, Payload::Keyring(_))
                && permitted(&self.keys[&id], credential, possessed, NEED_SEARCH)
            {
                match self.search(credential, id, description, possessed) {
                    Ok(serial) => return Ok(serial),
                    Err(Stop::Refuse(code)) if code != errno::ENOKEY => error = code,
                    Err(Stop::End(end)) => return Err(Stop::End(end)),
                    _ => {}
                }
            }
        }
        Err(error.into())
    }

    fn persistent(&mut self, credential: &Credential, ring: i32, now: u64) -> Result<i64, Stop> {
        if !matches!(self.keys[&ring].payload, Payload::Keyring(_)) {
            return Err(errno::ENOTDIR.into());
        }
        let serial = if let Some((id, _)) = self.persistent {
            id
        } else {
            let mut key = Self::ring(
                credential,
                format!("_persistent.{}", credential.uid).into_bytes(),
                PERSISTENT_PERM,
                false,
            );
            key.gid = u32::MAX; // INVALID_GID; DESCRIBE maps it to overflowgid.
            let id = self.allocate(key);
            // A failed link leaves the newly allocated register entry alive,
            // but only a successful GET_PERSISTENT sets its timeout.
            self.persistent = Some((id, u64::MAX));
            id
        };
        self.link(serial, ring)?;
        self.persistent = Some((serial, now.saturating_add(PERSISTENT_EXPIRY)));
        Ok(i64::from(serial))
    }

    fn allocate(&mut self, key: Key) -> i32 {
        let serial = self.next_serial;
        self.next_serial += 1;
        self.keys.insert(serial, key);
        serial
    }

    /// `lookup_user_key(id, create, need)` for thread `tid`: a special
    /// keyring id, or a key's serial (`EINVAL` below 1, `ENOKEY` for none),
    /// and whether the thread possesses it; unless the caller defers it, a
    /// revoked key is `EKEYREVOKED` (`key_validate`), then without the
    /// permission `need` (`key_task_permission`) `EACCES`. The thread's
    /// process keyring is made on demand, its own.
    fn lookup(
        &mut self,
        credential: &Credential,
        tid: c_int,
        id: i32,
        create: bool,
        need: Option<u32>,
    ) -> Result<(i32, bool), Stop> {
        let (serial, possessed) = match id {
            KEY_SPEC_THREAD_KEYRING if create => return Err(unmodeled("a thread keyring")),
            KEY_SPEC_THREAD_KEYRING => return Err(errno::ENOKEY.into()),
            KEY_SPEC_PROCESS_KEYRING => match self.holders.get(&tid) {
                Some(&serial) => (serial, true),
                None if create => {
                    let serial = self.allocate(Key {
                        payload: Payload::Keyring(Vec::new()),
                        description: b"_pid".to_vec(),
                        uid: credential.uid,
                        gid: credential.gid,
                        perm: DEFAULT_PERM,
                        revoked_at: None,
                        in_quota: true,
                    });
                    self.holders.insert(tid, serial);
                    (serial, true)
                }
                None => return Err(errno::ENOKEY.into()),
            },
            KEY_SPEC_SESSION_KEYRING => (FIRST_SERIAL, true),
            KEY_SPEC_USER_KEYRING | KEY_SPEC_USER_SESSION_KEYRING => {
                return Err(unmodeled("the user and user-session keyrings"));
            }
            KEY_SPEC_GROUP_KEYRING => return Err(errno::EINVAL.into()),
            // No request-key authorisation is ever assumed.
            -8..=-7 => return Err(errno::ENOKEY.into()),
            _ if id < 1 => return Err(errno::EINVAL.into()),
            _ if self.collecting.contains(&id) => return Err(unmodeled(COLLECTING)),
            _ if self.keys.contains_key(&id) => (id, self.possessed(tid, id)),
            _ => return Err(errno::ENOKEY.into()),
        };
        let key = &self.keys[&serial];
        if let Some(need) = need {
            if key.revoked_at.is_some() {
                return Err(errno::EKEYREVOKED.into());
            }
            if !permitted(key, credential, possessed, need) {
                return Err(errno::EACCES.into());
            }
        }
        Ok((serial, possessed))
    }

    /// The `user` key of `description` linked in `ring`: the live one, or
    /// with `revoked`, any.
    fn linked_user_key(&self, ring: i32, description: &[u8], revoked: bool) -> Option<i32> {
        let Payload::Keyring(links) = &self.keys[&ring].payload else {
            return None;
        };
        links.iter().copied().find(|serial| {
            let key = &self.keys[serial];
            matches!(key.payload, Payload::User(_))
                && key.description == description
                && (revoked || key.revoked_at.is_none())
        })
    }

    /// `__key_create_or_update` of a `user` key in `ring`: a live key of
    /// the same description is updated in place (its quota grows by the
    /// payload's growth); otherwise a new key is charged (a link, its
    /// description, its payload) and linked, displacing a revoked one of
    /// that description.
    fn create_or_update(
        &mut self,
        credential: &Credential,
        ring: i32,
        description: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<i64, Stop> {
        if let Some(serial) = self.linked_user_key(ring, &description, false) {
            self.update(serial, data)?;
            return Ok(i64::from(serial));
        }
        // A revoked key of the description gives up its link, not its quota:
        // that goes when the collector frees it, after this charge.
        let displaced = self.linked_user_key(ring, &description, true);
        let link = if displaced.is_some() || !self.keys[&ring].in_quota {
            0
        } else {
            LINK_BYTES
        };
        self.charge(true, link + description.len() + 1 + data.len())?;
        let serial = self.allocate(Key {
            payload: Payload::User(data),
            description,
            uid: credential.uid,
            gid: credential.gid,
            perm: DEFAULT_PERM,
            revoked_at: None,
            in_quota: true,
        });
        let Payload::Keyring(links) = &mut self.keys.get_mut(&ring).unwrap().payload else {
            unreachable!("the ring is a keyring");
        };
        links.retain(|&linked| Some(linked) != displaced);
        links.push(serial);
        if let Some(old) = displaced {
            self.release_key(old);
        }
        Ok(i64::from(serial))
    }

    /// `user_update`: the new payload, if the quota takes its growth.
    fn update(&mut self, serial: i32, data: Vec<u8>) -> Result<(), Stop> {
        let Payload::User(old) = &self.keys[&serial].payload else {
            return Err(errno::EOPNOTSUPP.into());
        };
        let growth = data.len().saturating_sub(old.len());
        if growth > 0 {
            self.charge(false, growth)?;
        }
        self.keys.get_mut(&serial).unwrap().payload = Payload::User(data);
        Ok(())
    }
}

mod operations;

#[cfg(test)]
mod tests;

#[cfg(test)]
use operations::keyctl_at;
pub(in crate::sud) use operations::{
    add_key, keyctl, keyring_exited, keyring_spawned, request_key,
};
