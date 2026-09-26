//! The key retention service (security/keys/), as 6.8 answers a caller
//! keeping its own keys: `add_key`, `request_key` and the `keyctl`
//! operations on them.
//!
//! The model is the guest's process keyrings and the `user` keys in them.
//! The guest starts with a session keyring, as a process Ubuntu starts has
//! one (`pam_keyinit`, systemd's `KeyringMode=`), but outside the model:
//! naming it, or the user keyrings, stops by name, and nothing the guest can
//! find is in it. Its search is still made, so a search that misses the
//! process keyring misses there too: `request_key` of a revoked key's
//! description is `ENOKEY` (the session keyring's miss outranks the revoked
//! key's `EKEYREVOKED` in `search_cred_keyrings_rcu`), and `ENOKEY` is what
//! it answers without callout information. There is no thread keyring, and
//! the pinned configuration registers no upcall.
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
//! guest owns and their bytes (description, payload, 4 a link); the session
//! keyring and anything in it are not counted. A revoked key stays until
//! the collector would remove it (`kernel.keys.gc_delay` past its
//! revocation); the removal is not modeled, so any key call from then on,
//! however much later, stops by name. A key displaced by a new one of the
//! same description is gone at once (the kernel frees it once its last
//! reference drops).
//!
//! Where the model ends by name: key types other than `user` and `keyring`,
//! a keyring inside a keyring, the thread, session and user keyrings,
//! `request_key`'s upcall, revoking a keyring, reading a keyring of more
//! than one key (its order is its associative array's), the collector, and
//! the `keyctl` operations besides `GET_KEYRING_ID`, `UPDATE`, `REVOKE`,
//! `CHOWN`, `DESCRIBE`, `READ` and `CAPABILITIES`.

use super::{Answer, Unmodeled, refuse};
use crate::identity::Credential;
use crate::registry::{Capability, KERNEL_CONFIG};
use linux_raw_sys::errno;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_int;
use std::sync::Mutex;

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
const NEED_SETATTR: u32 = 0x20;

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
const KEYCTL_READ: i32 = 11;
const KEYCTL_CAPABILITIES: i32 = 31;
const KEYCTL_LAST: i32 = 32;

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
}

/// Where the model ends at a keyring its last thread left.
const COLLECTING: &str = "a process keyring whose last thread exited, or a key in it (the collector frees them at a \
     time the model does not know)";

static KEYS: Mutex<Keys> = Mutex::new(Keys::new());

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
    const fn new() -> Self {
        Keys {
            keys: BTreeMap::new(),
            holders: BTreeMap::new(),
            collecting: BTreeSet::new(),
            next_serial: FIRST_SERIAL,
        }
    }

    /// The model ends where the collector would remove a revoked key.
    fn collect(&self, now: u64) -> Result<(), Stop> {
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
                .filter(|(serial, _)| !collected || !self.collecting.contains(serial))
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
        let Some(ring) = self.holders.remove(&tid) else {
            return;
        };
        if self.holders.values().any(|&held| held == ring) {
            return;
        }
        self.collecting.insert(ring);
        if let Payload::Keyring(links) = &self.keys[&ring].payload {
            self.collecting.extend(links.iter().copied());
        }
    }

    /// Whether thread `tid` possesses `serial`: its keyring, or a key
    /// linked there.
    fn possessed(&self, tid: c_int, serial: i32) -> bool {
        self.holders.get(&tid).is_some_and(|&ring| {
            ring == serial
                || matches!(&self.keys[&ring].payload, Payload::Keyring(links) if links.contains(&serial))
        })
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
                    });
                    self.holders.insert(tid, serial);
                    (serial, true)
                }
                None => return Err(errno::ENOKEY.into()),
            },
            KEY_SPEC_SESSION_KEYRING | KEY_SPEC_USER_KEYRING | KEY_SPEC_USER_SESSION_KEYRING => {
                return Err(unmodeled("the session and user keyrings"));
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
        let link = if displaced.is_some() { 0 } else { LINK_BYTES };
        self.charge(true, link + description.len() + 1 + data.len())?;
        if let Some(old) = displaced {
            self.keys.remove(&old);
        }
        let serial = self.allocate(Key {
            payload: Payload::User(data),
            description,
            uid: credential.uid,
            gid: credential.gid,
            perm: DEFAULT_PERM,
            revoked_at: None,
        });
        let Payload::Keyring(links) = &mut self.keys.get_mut(&ring).unwrap().payload else {
            unreachable!("the ring is a keyring");
        };
        links.retain(|&linked| Some(linked) != displaced);
        links.push(serial);
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

/// The calling thread's id, whose process keyring the key calls use.
fn caller_tid() -> c_int {
    crate::thread::deterministic_thread_id()
}

/// A new thread `child` of `parent` shares its creator's process keyring
/// (`copy_creds`).
pub(in crate::sud) fn keyring_spawned(parent: c_int, child: c_int) {
    KEYS.lock().unwrap().spawned(parent, child);
}

/// Thread `tid` exited, with its reference to its process keyring.
pub(in crate::sud) fn keyring_exited(tid: c_int) {
    KEYS.lock().unwrap().exited(tid);
}

/// `add_key(type, description, payload, plen, ringid)`.
pub(in crate::sud) fn add_key(credential: &Credential, a: &[u64; 6]) -> Answer {
    let now = now_seconds();
    answer(add_key_at(credential, caller_tid(), a, now))
}

fn add_key_at(credential: &Credential, tid: c_int, a: &[u64; 6], now: u64) -> Result<i64, Stop> {
    let plen = a[3];
    if plen > MAX_PAYLOAD {
        return Err(errno::EINVAL.into());
    }
    let type_name = type_from_user(a[0])?;
    let mut description = None;
    if a[1] != 0 {
        let text = guest_strndup(a[1], KEY_MAX_DESC_SIZE)?;
        if text.first() == Some(&b'.') && type_name.starts_with(b"keyring") {
            return Err(errno::EPERM.into());
        }
        description = Some(text).filter(|text| !text.is_empty());
    }
    let data = if plen != 0 {
        crate::uaccess::read_bytes(a[2] as usize, plen as usize).map_err(|_| errno::EFAULT)?
    } else {
        Vec::new()
    };
    let mut keys = KEYS.lock().unwrap();
    keys.collect(now)?;
    let (ring, _) = keys.lookup(credential, tid, a[4] as i32, true, Some(NEED_WRITE))?;
    let keyring_type = match key_type(&type_name) {
        KeyType::User => false,
        KeyType::Keyring => true,
        KeyType::Unmodeled => return Err(unmodeled_type(&type_name)),
        KeyType::Unknown => return Err(errno::ENODEV.into()),
    };
    if !matches!(keys.keys[&ring].payload, Payload::Keyring(_)) {
        return Err(errno::ENOTDIR.into());
    }
    // The type's `preparse`: a `user` key holds 1 to 32767 bytes, a keyring
    // none; both need a description.
    let preparsed = if keyring_type {
        plen == 0
    } else {
        (1..=MAX_USER_PAYLOAD).contains(&data.len())
    };
    let Some(description) = description.filter(|_| preparsed) else {
        return Err(errno::EINVAL.into());
    };
    if keyring_type {
        return Err(unmodeled("a keyring inside a keyring"));
    }
    keys.create_or_update(credential, ring, description, data)
}

/// `request_key(type, description, callout_info, dest_keyringid)`: the
/// strings, the destination (made on demand), the type (`ENOKEY` for one no
/// module registers), then a search of the calling thread's process
/// keyring for a live key, and of the session keyring, which holds none; a
/// miss without callout information is `ENOKEY`.
pub(in crate::sud) fn request_key(credential: &Credential, a: &[u64; 6]) -> Answer {
    let now = now_seconds();
    answer(request_key_at(credential, caller_tid(), a, now))
}

fn request_key_at(
    credential: &Credential,
    tid: c_int,
    a: &[u64; 6],
    now: u64,
) -> Result<i64, Stop> {
    let type_name = type_from_user(a[0])?;
    let description = guest_strndup(a[1], KEY_MAX_DESC_SIZE)?;
    let callout = if a[2] != 0 {
        Some(guest_strndup(a[2], PAGE_SIZE)?)
    } else {
        None
    };
    let mut keys = KEYS.lock().unwrap();
    keys.collect(now)?;
    let destination = match a[3] as i32 {
        0 => None,
        id => Some(keys.lookup(credential, tid, id, true, Some(NEED_WRITE))?.0),
    };
    match key_type(&type_name) {
        KeyType::User => {}
        KeyType::Keyring => return Err(unmodeled("request_key of a keyring")),
        KeyType::Unmodeled => return Err(unmodeled_type(&type_name)),
        KeyType::Unknown => return Err(errno::ENOKEY.into()),
    }
    let found = keys
        .holders
        .get(&tid)
        .and_then(|&ring| keys.linked_user_key(ring, &description, false));
    match (found, callout) {
        (Some(serial), _) => {
            // Linking it where it already is changes nothing; a destination
            // that is no keyring is `ENOTDIR`.
            let keyring = |serial: i32| matches!(keys.keys[&serial].payload, Payload::Keyring(_));
            if destination.is_some_and(|destination| !keyring(destination)) {
                return Err(errno::ENOTDIR.into());
            }
            Ok(i64::from(serial))
        }
        (None, None) => Err(errno::ENOKEY.into()),
        (None, Some(_)) => Err(unmodeled(
            "request_key's upcall to /sbin/request-key (it would run outside the simulation)",
        )),
    }
}

/// `keyctl(option, arg2, arg3, arg4, arg5)`, the operation an `int`.
pub(in crate::sud) fn keyctl(credential: &Credential, a: &[u64; 6]) -> Answer {
    let now = now_seconds();
    answer(keyctl_at(credential, caller_tid(), a, now))
}

fn keyctl_at(credential: &Credential, tid: c_int, a: &[u64; 6], now: u64) -> Result<i64, Stop> {
    let option = a[0] as i32;
    let id = a[1] as i32;
    match option {
        KEYCTL_GET_KEYRING_ID => {
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            keys.lookup(credential, tid, id, a[2] as i32 != 0, Some(NEED_SEARCH))
                .map(|(serial, _)| i64::from(serial))
        }
        KEYCTL_UPDATE => {
            let plen = a[3] as usize;
            if plen > PAGE_SIZE {
                return Err(errno::EINVAL.into());
            }
            let data = if plen != 0 {
                crate::uaccess::read_bytes(a[2] as usize, plen).map_err(|_| errno::EFAULT)?
            } else {
                Vec::new()
            };
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            let (serial, _) = keys.lookup(credential, tid, id, false, Some(NEED_WRITE))?;
            if !matches!(keys.keys[&serial].payload, Payload::User(_)) {
                return Err(errno::EOPNOTSUPP.into());
            }
            if data.is_empty() {
                return Err(errno::EINVAL.into());
            }
            keys.update(serial, data).map(|()| 0)
        }
        KEYCTL_REVOKE => {
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            // Write permission, or failing that, setattr.
            let (serial, _) = match keys.lookup(credential, tid, id, false, Some(NEED_WRITE)) {
                Err(Stop::Refuse(errno::EACCES)) => {
                    keys.lookup(credential, tid, id, false, Some(NEED_SETATTR))?
                }
                found => found?,
            };
            let key = keys.keys.get_mut(&serial).unwrap();
            if matches!(key.payload, Payload::Keyring(_)) {
                return Err(unmodeled("revoking a keyring"));
            }
            key.payload = Payload::User(Vec::new());
            key.revoked_at = Some(now);
            Ok(0)
        }
        KEYCTL_CHOWN => chown(credential, tid, id, a[2] as u32, a[3] as u32, now),
        KEYCTL_DESCRIBE => {
            let mut keys = KEYS.lock().unwrap();
            keys.collect(now)?;
            let (serial, _) = keys.lookup(credential, tid, id, false, Some(NEED_VIEW))?;
            let key = &keys.keys[&serial];
            let mut text = format!(
                "{};{};{};{:08x};",
                key.type_name(),
                key.uid as i32,
                key.gid as i32,
                key.perm
            )
            .into_bytes();
            text.extend_from_slice(&key.description);
            text.push(0);
            let (buffer, length) = (a[2] as usize, a[3] as u32 as usize);
            if buffer != 0
                && length >= text.len()
                && crate::uaccess::write_bytes(buffer, &text).is_err()
            {
                return Err(errno::EFAULT.into());
            }
            Ok(text.len() as i64)
        }
        KEYCTL_READ => read(credential, tid, id, a[2] as usize, a[3] as usize, now),
        KEYCTL_CAPABILITIES => capabilities(a[1] as usize, a[2] as usize),
        _ if (0..=KEYCTL_LAST).contains(&option) => {
            Err(unmodeled(format!("keyctl operation {option}")))
        }
        _ => Err(errno::EOPNOTSUPP.into()),
    }
}

/// `keyctl_chown_key`: -1 for both ids changes nothing, before the key is
/// looked up (made on demand); handing it to another user, or to a group
/// the caller is not in, needs `CAP_SYS_ADMIN` (`EACCES`).
fn chown(
    credential: &Credential,
    tid: c_int,
    id: i32,
    uid: u32,
    gid: u32,
    now: u64,
) -> Result<i64, Stop> {
    const UNCHANGED: u32 = u32::MAX;
    if uid == UNCHANGED && gid == UNCHANGED {
        return Ok(0);
    }
    let mut keys = KEYS.lock().unwrap();
    keys.collect(now)?;
    let (serial, _) = keys.lookup(credential, tid, id, true, Some(NEED_SETATTR))?;
    let key = keys.keys.get_mut(&serial).unwrap();
    let in_group = gid == credential.gid || credential.groups.contains(&gid);
    let privileged =
        (uid != UNCHANGED && uid != key.uid) || (gid != UNCHANGED && gid != key.gid && !in_group);
    if privileged {
        return Err(if credential.capable(Capability::SysAdmin) {
            Stop::End(Unmodeled::Granted(Capability::SysAdmin))
        } else {
            errno::EACCES.into()
        });
    }
    if gid != UNCHANGED {
        key.gid = gid;
    }
    Ok(0)
}

/// `keyctl_read_key`: any failure to find the key is `ENOKEY`; a key the
/// calling thread neither may read nor possesses is `EACCES`; a revoked key
/// reads `EKEYREVOKED`. The answer is the data's length, copied only when
/// it fits; a keyring's data is its links' serials, and a buffer of up to a
/// page must hold whole ones (`EINVAL`).
fn read(
    credential: &Credential,
    tid: c_int,
    id: i32,
    buffer: usize,
    length: usize,
    now: u64,
) -> Result<i64, Stop> {
    let mut keys = KEYS.lock().unwrap();
    keys.collect(now)?;
    let (serial, possessed) = keys
        .lookup(credential, tid, id, false, None)
        .map_err(|stop| match stop {
            Stop::Refuse(_) => Stop::Refuse(errno::ENOKEY),
            end => end,
        })?;
    let key = &keys.keys[&serial];
    if !possessed && !permitted(key, credential, false, NEED_READ) {
        return Err(errno::EACCES.into());
    }
    if key.revoked_at.is_some() {
        return Err(errno::EKEYREVOKED.into());
    }
    let copying = buffer != 0 && length != 0;
    let data: Vec<u8> = match &key.payload {
        Payload::User(data) => data.clone(),
        Payload::Keyring(_) if copying && length <= PAGE_SIZE && length % 4 != 0 => {
            return Err(errno::EINVAL.into());
        }
        Payload::Keyring(links) if copying && length >= 4 * links.len() && links.len() > 1 => {
            return Err(unmodeled(
                "reading a keyring of more than one key (its order is its associative array's)",
            ));
        }
        Payload::Keyring(links) => links
            .iter()
            .flat_map(|serial| serial.to_ne_bytes())
            .collect(),
    };
    if copying && length >= data.len() && crate::uaccess::write_bytes(buffer, &data).is_err() {
        return Err(errno::EFAULT.into());
    }
    Ok(data.len() as i64)
}

/// `keyctl_capabilities`: [`CAPABILITIES`], as much as fits, the rest of
/// the room cleared (`EFAULT` where a byte cannot be written); the answer
/// is its size.
fn capabilities(buffer: usize, length: usize) -> Result<i64, Stop> {
    let copied = length.min(CAPABILITIES.len());
    if crate::uaccess::write_bytes(buffer, &CAPABILITIES[..copied]).is_err() {
        return Err(errno::EFAULT.into());
    }
    // `clear_user` of the rest, a page at a time.
    let Some(end) = buffer.checked_add(length) else {
        return Err(errno::EFAULT.into());
    };
    let mut at = buffer + copied;
    while at < end {
        let chunk = (PAGE_SIZE - at % PAGE_SIZE).min(end - at);
        if crate::uaccess::write_bytes(at, &[0; PAGE_SIZE][..chunk]).is_err() {
            return Err(errno::EFAULT.into());
        }
        at += chunk;
    }
    Ok(CAPABILITIES.len() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::credential;

    /// The thread that makes the process keyring.
    const MAIN: c_int = 2;

    /// A model holding just `MAIN`'s process keyring, and its serial.
    fn with_process_keyring() -> (Keys, i32) {
        let mut keys = Keys::new();
        let Ok((ring, _)) = keys.lookup(
            credential(),
            MAIN,
            KEY_SPEC_PROCESS_KEYRING,
            true,
            Some(NEED_WRITE),
        ) else {
            panic!("the process keyring");
        };
        (keys, ring)
    }

    fn add(keys: &mut Keys, ring: i32, description: &[u8], data: &[u8]) -> Result<i32, u32> {
        match keys.create_or_update(credential(), ring, description.to_vec(), data.to_vec()) {
            Ok(serial) => Ok(serial as i32),
            Err(Stop::Refuse(code)) => Err(code),
            Err(Stop::End(end)) => panic!("{end:?}"),
        }
    }

    /// The quota holds `kernel.keys.maxkeys` keys (the process keyring
    /// among them) and `kernel.keys.maxbytes` bytes: the keyring's
    /// description and NUL, and each key's link, description, NUL and
    /// payload.
    #[test]
    fn the_quota_counts_keys_links_and_bytes() {
        let (mut keys, ring) = with_process_keyring();
        let fits =
            KERNEL_CONFIG.keys_maxbytes as usize - b"_pid\0".len() - LINK_BYTES - b"d\0".len();
        assert_eq!(
            add(&mut keys, ring, b"d", &vec![0; fits + 1]),
            Err(errno::EDQUOT)
        );
        assert!(add(&mut keys, ring, b"d", &vec![0; fits]).is_ok());

        let (mut keys, ring) = with_process_keyring();
        for index in 1..KERNEL_CONFIG.keys_maxkeys {
            assert!(add(&mut keys, ring, index.to_string().as_bytes(), b"v").is_ok());
        }
        assert_eq!(
            add(&mut keys, ring, b"one too many", b"v"),
            Err(errno::EDQUOT)
        );
    }

    /// A revoked key's description is free again: a new key displaces it
    /// at once, and its serial names nothing.
    #[test]
    fn a_new_key_displaces_a_revoked_one() {
        let (mut keys, ring) = with_process_keyring();
        let first = add(&mut keys, ring, b"d", b"v").unwrap();
        keys.keys.get_mut(&first).unwrap().revoked_at = Some(0);
        let second = add(&mut keys, ring, b"d", b"w").unwrap();
        assert_ne!(first, second);
        assert!(matches!(
            keys.lookup(credential(), MAIN, first, false, None),
            Err(Stop::Refuse(errno::ENOKEY))
        ));
        assert_eq!(keys.keys[&ring].payload, Payload::Keyring(vec![second]));
    }

    /// Past `kernel.keys.gc_delay` a revoked key would be collected: the
    /// model ends there, not before.
    #[test]
    fn the_collector_is_where_the_model_ends() {
        let (mut keys, ring) = with_process_keyring();
        let serial = add(&mut keys, ring, b"d", b"v").unwrap();
        keys.keys.get_mut(&serial).unwrap().revoked_at = Some(10);
        assert!(keys.collect(10 + KERNEL_CONFIG.keys_gc_delay - 1).is_ok());
        assert!(matches!(
            keys.collect(10 + KERNEL_CONFIG.keys_gc_delay),
            Err(Stop::End(_))
        ));
    }

    /// A keyring its last thread left is the collector's, and so are its
    /// keys: naming one ends the model, and so does a charge only their
    /// going would let fit; one that fits either way is answered.
    #[test]
    fn a_keyring_its_last_thread_left_is_the_collectors() {
        const WORKER: c_int = MAIN + 1;
        let (mut keys, ring) = with_process_keyring();
        keys.spawned(MAIN, WORKER);
        let key = add(&mut keys, ring, b"d", b"v").unwrap();
        keys.exited(MAIN);
        assert!(keys.lookup(credential(), WORKER, key, false, None).is_ok());
        keys.exited(WORKER);
        for serial in [ring, key] {
            assert!(matches!(
                keys.lookup(credential(), MAIN, serial, false, None),
                Err(Stop::End(_))
            ));
        }
        assert!(keys.charge(true, 1).is_ok());
        let freed_bytes = KERNEL_CONFIG.keys_maxbytes as usize - b"_pid\0".len();
        assert!(matches!(keys.charge(true, freed_bytes), Err(Stop::End(_))));
    }
}
