//! Name-resolution and absent-symbol rows.

use super::*;

impl Probe {
    // ---- name resolution -------------------------------------------------------

    /// `getaddrinfo(3)` (libc only: there is no kernel row under it) with
    /// hints of `family`, `socktype` and `flags`; every result is recorded
    /// and freed with `freeaddrinfo(3)`. Recorded as the `EAI_*` code in
    /// `fields.code` (the call's result is not an errno).
    pub fn getaddrinfo(
        &self,
        node: Option<&str>,
        service: Option<&str>,
        family: i32,
        socktype: i32,
        flags: i32,
    ) -> (i32, Vec<AddrInfo>) {
        let node_c = node.map(cstr);
        let service_c = service.map(cstr);
        // SAFETY: an all-zero addrinfo is valid hints.
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = family;
        hints.ai_socktype = socktype;
        hints.ai_flags = flags;
        let mut list: *mut libc::addrinfo = std::ptr::null_mut();
        // SAFETY: NUL-terminated strings or NULL, valid hints, an out-pointer.
        let code = unsafe {
            libc::getaddrinfo(
                node_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                service_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                &hints,
                &mut list,
            )
        };
        let mut results = Vec::new();
        if code == 0 {
            let mut at = list;
            while !at.is_null() && results.len() < 16 {
                // SAFETY: a node of the list getaddrinfo returned.
                let entry = unsafe { &*at };
                // SAFETY: an all-zero sockaddr_storage is a valid value; the
                // entry's address is `ai_addrlen` readable bytes.
                let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let len = (entry.ai_addrlen as usize).min(size_of::<libc::sockaddr_storage>());
                if !entry.ai_addr.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            entry.ai_addr as *const u8,
                            &mut storage as *mut _ as *mut u8,
                            len,
                        )
                    };
                }
                results.push(AddrInfo {
                    family: entry.ai_family,
                    socktype: entry.ai_socktype,
                    protocol: entry.ai_protocol,
                    addrlen: entry.ai_addrlen,
                    addr: SockAddr::decode(&storage, len as u32),
                    canonname: !entry.ai_canonname.is_null(),
                });
                at = entry.ai_next;
            }
            // SAFETY: the list getaddrinfo returned, freed once.
            unsafe { libc::freeaddrinfo(list) };
        }
        let mut builder = self
            .rec
            .event("getaddrinfo", 0)
            .arg("node", node.map_or(Value::Null, Value::from))
            .arg("service", service.map_or(Value::Null, Value::from))
            .arg("family", family_name(family))
            .arg("socktype", socktype)
            .arg("flags", flags)
            .field("code", eai_name(code))
            .field("results", results.len());
        for (index, info) in results.iter().enumerate() {
            builder = builder
                .field(&format!("family{index}"), family_name(info.family))
                .field(&format!("socktype{index}"), info.socktype)
                .field(&format!("protocol{index}"), info.protocol)
                .field(&format!("addrlen{index}"), info.addrlen)
                .field(&format!("canonname{index}"), info.canonname);
            builder = info.addr.record(builder, true, &format!("addr{index}"));
        }
        builder.emit();
        (code, results)
    }

    // ---- symbols the shim leaves undefined -----------------------------------

    /// Resolve `symbol` through `dlsym(RTLD_DEFAULT, …)` and record whether
    /// it resolved. The door of a symbol the registry lists `Absent`: the
    /// probe binary cannot import it (the pre-run audit would refuse the
    /// whole binary), so the libc vehicle reaches glibc's definition
    /// dynamically, and under patina `dlsym` answers only what the shim
    /// defines (c/posix/dlsym.c `__wrap_dlsym`).
    pub fn resolve(&self, symbol: &str) -> Option<*mut libc::c_void> {
        let c = cstr(symbol);
        // SAFETY: a NUL-terminated name looked up in the global scope.
        let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c.as_ptr()) };
        self.rec
            .event("dlsym", 0)
            .arg("symbol", symbol)
            .field("resolved", !address.is_null())
            .emit();
        (!address.is_null()).then_some(address)
    }
}
