/*
 * Network (SimNet): sockets, transfer, options, name resolution, interfaces.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

/*
 * Every socket call is the shared `patina_sock_*` entry the SUD rows call,
 * argument for argument: the entry copies guest memory in and out itself and
 * answers the kernel's result (`-errno` on failure), so the two doors cannot
 * differ. An `int` length travels as the kernel reads it, sign and all.
 */
static ssize_t sock_result(int64_t rc) {
#ifdef __linux__
    patina_signal_deliver();
#endif
    if (rc < 0) {
        errno = (int)-rc;
        return -1;
    }
    return (ssize_t)rc;
}

int socket(int domain, int type, int protocol) {
    return (int)sock_result(patina_sock_socket(domain, type, protocol));
}

int socketpair(int domain, int type, int protocol, int sv[2]) {
    return (int)sock_result(patina_sock_socketpair(domain, type, protocol, (uintptr_t)sv));
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    return (int)sock_result(patina_sock_bind(fd, (uintptr_t)addr, (int32_t)len));
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    PATINA_CANCEL_POINT("connect");
    return (int)sock_result(patina_sock_connect(fd, (uintptr_t)addr, (int32_t)len));
}

int listen(int fd, int backlog) {
    return (int)sock_result(patina_sock_listen(fd, backlog));
}

int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    PATINA_CANCEL_POINT("accept");
    return (int)sock_result(patina_sock_accept(fd, (uintptr_t)addr, (uintptr_t)len, 0));
}

#ifdef __linux__
int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    PATINA_CANCEL_POINT("accept4");
    return (int)sock_result(patina_sock_accept(fd, (uintptr_t)addr, (uintptr_t)len, flags));
}
#endif

int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    return (int)sock_result(patina_sock_name(fd, (uintptr_t)addr, (uintptr_t)len, 0));
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    return (int)sock_result(patina_sock_name(fd, (uintptr_t)addr, (uintptr_t)len, 1));
}

int shutdown(int fd, int how) {
    return (int)sock_result(patina_sock_shutdown(fd, how));
}

int setsockopt(int fd, int level, int optname, const void *value, socklen_t len) {
    return (int)sock_result(
        patina_sock_setsockopt(fd, level, optname, (uintptr_t)value, (int32_t)len));
}

int getsockopt(int fd, int level, int optname, void *value, socklen_t *len) {
    return (int)sock_result(
        patina_sock_getsockopt(fd, level, optname, (uintptr_t)value, (uintptr_t)len));
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t alen) {
    PATINA_CANCEL_POINT("sendto");
    return sock_result(patina_sock_sendto(fd, (uintptr_t)buf, len, flags, (uintptr_t)addr,
                                          (int32_t)alen));
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    PATINA_CANCEL_POINT("send");
    return sock_result(patina_sock_sendto(fd, (uintptr_t)buf, len, flags, 0, 0));
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *addr, socklen_t *alen) {
    PATINA_CANCEL_POINT("recvfrom");
    return sock_result(patina_sock_recvfrom(fd, (uintptr_t)buf, len, flags, (uintptr_t)addr,
                                            (uintptr_t)alen));
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    PATINA_CANCEL_POINT("recv");
    return sock_result(patina_sock_recvfrom(fd, (uintptr_t)buf, len, flags, 0, 0));
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    PATINA_CANCEL_POINT("sendmsg");
    return sock_result(patina_sock_sendmsg(fd, (uintptr_t)msg, flags));
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    PATINA_CANCEL_POINT("recvmsg");
    return sock_result(patina_sock_recvmsg(fd, (uintptr_t)msg, flags));
}

#ifdef __linux__
int sendmmsg(int fd, struct mmsghdr *vec, unsigned int vlen, int flags) {
    PATINA_CANCEL_POINT("sendmmsg");
    return (int)sock_result(patina_sock_sendmmsg(fd, (uintptr_t)vec, vlen, flags));
}

int recvmmsg(int fd, struct mmsghdr *vec, unsigned int vlen, int flags,
             struct timespec *timeout) {
    PATINA_CANCEL_POINT("recvmmsg");
    return (int)sock_result(
        patina_sock_recvmmsg(fd, (uintptr_t)vec, vlen, flags, (uintptr_t)timeout));
}

/*
 * glibc's `_FORTIFY_SOURCE` spellings of recv/recvfrom (debug/recv_chk.c,
 * recvfrom_chk.c): the plain call, once the size the compiler knew for the
 * buffer holds the length asked for (`__chk_fail` otherwise).
 */
static ssize_t patina_recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags) {
    if (len > buflen) patina_chk_fail();
    return sock_result(patina_sock_recvfrom(fd, (uintptr_t)buf, len, flags, 0, 0));
}

static ssize_t patina_recvfrom_chk(int fd, void *buf, size_t len, size_t buflen, int flags,
                                   struct sockaddr *addr, socklen_t *alen) {
    if (len > buflen) patina_chk_fail();
    return sock_result(patina_sock_recvfrom(fd, (uintptr_t)buf, len, flags, (uintptr_t)addr,
                                            (uintptr_t)alen));
}

ssize_t __recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags) {
    PATINA_CANCEL_POINT("__recv_chk");
    return patina_recv_chk(fd, buf, len, buflen, flags);
}

ssize_t __recvfrom_chk(int fd, void *buf, size_t len, size_t buflen, int flags,
                       struct sockaddr *addr, socklen_t *alen) {
    PATINA_CANCEL_POINT("__recvfrom_chk");
    return patina_recvfrom_chk(fd, buf, len, buflen, flags, addr, alen);
}
#endif

/*
 * Name resolution over numeric hosts and the run's deterministic host table
 * (patina_dns_resolve, IPv4): nothing reads /etc/hosts, /etc/services,
 * /etc/gai.conf or the network. The answers follow glibc's
 * (sysdeps/posix/getaddrinfo.c):
 *
 *  - a hints family other than AF_UNSPEC/AF_INET/AF_INET6 is EAI_FAMILY;
 *  - the socket types come from glibc's `gaih_inet_typeproto` table: with
 *    neither a type nor a protocol hinted, one result each for SOCK_STREAM
 *    (IPPROTO_TCP), SOCK_DGRAM (IPPROTO_UDP) and SOCK_RAW (protocol 0);
 *    otherwise the first entry both fit (none: EAI_SOCKTYPE with a type
 *    hinted, else EAI_SERVICE), and SOCK_RAW with a service is EAI_SERVICE;
 *  - only numeric services resolve (there is no service registry): a name
 *    is EAI_NONAME under AI_NUMERICSERV, EAI_SERVICE otherwise;
 *  - a NULL host is the wildcard address under AI_PASSIVE, loopback without
 *    it; for AF_UNSPEC both families, in the order glibc's RFC 3484 sort
 *    leaves them on a host with IPv4 and IPv6 loopback (passive: IPv4 first;
 *    otherwise ::1 first);
 *  - a numeric host (patina_net_numeric_host: inet_aton or inet_pton) of
 *    another family than the one hinted is EAI_ADDRFAMILY (IPv4 under
 *    AF_INET6 with AI_V4MAPPED answers the mapped address); a name under
 *    AI_NUMERICHOST is EAI_NONAME;
 *  - a name resolves to the host table's single IPv4 address (an injected
 *    resolver timeout is EAI_AGAIN, an unknown name EAI_NONAME); AF_INET6
 *    finds no address for it unless AI_V4MAPPED maps it;
 *  - AI_CANONNAME names the host as given (the table has no aliases);
 *    AI_ADDRCONFIG keeps a family only when a non-loopback interface of the
 *    virtual table carries an address of it.
 *
 * The list is allocated node by node and freeaddrinfo frees it.
 */
struct patina_gai_type {
    int socktype;
    int protocol;
    int any_protocol; /* the hinted protocol stands (SOCK_RAW) */
    int no_service;   /* a service is EAI_SERVICE (SOCK_RAW) */
};

static const struct patina_gai_type patina_gai_types[] = {
    {SOCK_STREAM, IPPROTO_TCP, 0, 0},
    {SOCK_DGRAM, IPPROTO_UDP, 0, 0},
#ifdef __linux__
    {SOCK_DCCP, IPPROTO_DCCP, 0, 1},
    {SOCK_DGRAM, IPPROTO_UDPLITE, 0, 0},
    {SOCK_STREAM, IPPROTO_SCTP, 0, 0},
    {SOCK_SEQPACKET, IPPROTO_SCTP, 0, 0},
#endif
    {SOCK_RAW, 0, 1, 1},
};

#define PATINA_GAI_TYPES (sizeof patina_gai_types / sizeof patina_gai_types[0])

struct patina_gai_address {
    int family;
    unsigned char bytes[16];
    uint32_t scope;
};

static int patina_gai_family_configured(int family) {
    struct patina_interface interface;
    for (uint32_t at = 0; patina_net_interface(at, &interface) == 0; ++at) {
        if (interface.flags & IFF_LOOPBACK) continue;
        if (family == AF_INET) return 1;
        if (interface.has_ipv6) return 1;
    }
    return 0;
}

static struct addrinfo *patina_gai_node(const struct patina_gai_address *address,
                                        uint16_t port, int socktype, int protocol,
                                        const char *canonical) {
    struct addrinfo *node = calloc(1, sizeof *node);
    if (node == NULL) return NULL;
    node->ai_family = address->family;
    node->ai_socktype = socktype;
    node->ai_protocol = protocol;
    if (address->family == AF_INET) {
        struct sockaddr_in *in = calloc(1, sizeof *in);
        if (in == NULL) {
            free(node);
            return NULL;
        }
#ifdef __APPLE__
        in->sin_len = sizeof *in;
#endif
        in->sin_family = AF_INET;
        in->sin_port = htons(port);
        memcpy(&in->sin_addr, address->bytes, 4);
        node->ai_addr = (struct sockaddr *)in;
        node->ai_addrlen = sizeof *in;
    } else {
        struct sockaddr_in6 *in6 = calloc(1, sizeof *in6);
        if (in6 == NULL) {
            free(node);
            return NULL;
        }
#ifdef __APPLE__
        in6->sin6_len = sizeof *in6;
#endif
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons(port);
        memcpy(&in6->sin6_addr, address->bytes, 16);
        in6->sin6_scope_id = address->scope;
        node->ai_addr = (struct sockaddr *)in6;
        node->ai_addrlen = sizeof *in6;
    }
    if (canonical != NULL) {
        size_t size = strlen(canonical) + 1;
        node->ai_canonname = malloc(size);
        if (node->ai_canonname != NULL) memcpy(node->ai_canonname, canonical, size);
        if (node->ai_canonname == NULL) {
            free(node->ai_addr);
            free(node);
            return NULL;
        }
    }
    return node;
}

void freeaddrinfo(struct addrinfo *res) {
    while (res != NULL) {
        struct addrinfo *next = res->ai_next;
        free(res->ai_addr);
        free(res->ai_canonname);
        free(res);
        res = next;
    }
}

/* The numeric service, or -1 for a name. Digits only: a locale-independent
 * parse (and no strtol import in the one translation unit every guest
 * links). */
static int patina_gai_port(const char *service) {
    if (*service == '\0') return -1;
    unsigned long parsed = 0;
    for (const char *digit = service; *digit != '\0'; ++digit) {
        if (*digit < '0' || *digit > '9') return -1;
        parsed = parsed * 10u + (unsigned long)(*digit - '0');
        if (parsed > 65535u) return -1;
    }
    return (int)parsed;
}

static void patina_gai_v4mapped(struct patina_gai_address *address) {
    unsigned char v4[4];
    memcpy(v4, address->bytes, 4);
    memset(address->bytes, 0, 10);
    address->bytes[10] = 0xff;
    address->bytes[11] = 0xff;
    memcpy(address->bytes + 12, v4, 4);
    address->family = AF_INET6;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    static const struct addrinfo no_hints = {0};
    if (hints == NULL) hints = &no_hints;
    int family = hints->ai_family;
    int flags = hints->ai_flags;
#ifdef __linux__
    const int known_flags = AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_ADDRCONFIG |
                            AI_V4MAPPED | AI_NUMERICSERV | AI_ALL | AI_IDN | AI_CANONIDN |
                            0x100 | 0x200;
    if (flags & ~known_flags) return EAI_BADFLAGS;
#endif
    if ((flags & AI_CANONNAME) && node == NULL) return EAI_BADFLAGS;
    if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) return EAI_FAMILY;
    if (node == NULL && service == NULL) return EAI_NONAME;

    /* The socket types. */
    const struct patina_gai_type *only = NULL;
    if (hints->ai_socktype != 0 || hints->ai_protocol != 0) {
        for (size_t at = 0; at < PATINA_GAI_TYPES && only == NULL; ++at) {
            const struct patina_gai_type *type = &patina_gai_types[at];
            if (hints->ai_socktype != 0 && hints->ai_socktype != type->socktype) continue;
            if (hints->ai_protocol != 0 && !type->any_protocol &&
                hints->ai_protocol != type->protocol) {
                continue;
            }
            only = type;
        }
        if (only == NULL) return hints->ai_socktype != 0 ? EAI_SOCKTYPE : EAI_SERVICE;
        if (service != NULL && only->no_service) return EAI_SERVICE;
    }

    uint16_t port = 0;
    if (service != NULL) {
        int parsed = patina_gai_port(service);
        if (parsed < 0) return (flags & AI_NUMERICSERV) ? EAI_NONAME : EAI_SERVICE;
        port = (uint16_t)parsed;
    }

    /* The addresses, in answer order. */
    struct patina_gai_address addresses[2];
    size_t count = 0;
    if (node == NULL) {
        static const unsigned char loopback4[4] = {127, 0, 0, 1};
        struct patina_gai_address four = {.family = AF_INET};
        struct patina_gai_address six = {.family = AF_INET6};
        if (!(flags & AI_PASSIVE)) {
            memcpy(four.bytes, loopback4, 4);
            six.bytes[15] = 1;
        }
        int passive = (flags & AI_PASSIVE) != 0;
        if (family != AF_INET && !passive) addresses[count++] = six;
        if (family != AF_INET6) addresses[count++] = four;
        if (family != AF_INET && passive) addresses[count++] = six;
    } else {
        struct patina_gai_address address = {0};
        address.family = patina_net_numeric_host(node, address.bytes, &address.scope);
        if (address.family == 0) {
            if (flags & AI_NUMERICHOST) return EAI_NONAME;
            uint32_t ip = 0;
            if (patina_dns_resolve(node, &ip) != 0) {
                return (patina_errno() == EINTR) ? EAI_AGAIN : EAI_NONAME;
            }
            uint32_t wire = htonl(ip);
            address.family = AF_INET;
            memcpy(address.bytes, &wire, 4);
            if (family == AF_INET6) {
                if (!(flags & AI_V4MAPPED)) return EAI_NONAME;
                patina_gai_v4mapped(&address);
            }
        } else if (family != AF_UNSPEC && family != address.family) {
            if (family == AF_INET6 && (flags & AI_V4MAPPED)) {
                patina_gai_v4mapped(&address);
            } else {
#ifdef EAI_ADDRFAMILY
                return EAI_ADDRFAMILY;
#else
                return EAI_NONAME;
#endif
            }
        }
        addresses[count++] = address;
    }
    if (flags & AI_ADDRCONFIG) {
        size_t kept = 0;
        for (size_t at = 0; at < count; ++at) {
            if (patina_gai_family_configured(addresses[at].family)) {
                addresses[kept++] = addresses[at];
            }
        }
        count = kept;
        if (count == 0) return EAI_NONAME;
    }

    struct addrinfo *head = NULL;
    struct addrinfo **tail = &head;
    const char *canonical = (flags & AI_CANONNAME) ? node : NULL;
    for (size_t at = 0; at < count; ++at) {
        for (size_t type = 0; type < PATINA_GAI_TYPES; ++type) {
            const struct patina_gai_type *entry = &patina_gai_types[type];
            int socktype;
            int protocol;
            if (only != NULL) {
                if (entry != only) continue;
                socktype = only->socktype;
                protocol = only->any_protocol ? hints->ai_protocol : only->protocol;
            } else {
                /* The default types: TCP, UDP and raw. */
                if (entry->protocol != IPPROTO_TCP && entry->protocol != IPPROTO_UDP &&
                    entry->socktype != SOCK_RAW) {
                    continue;
                }
                socktype = entry->socktype;
                protocol = entry->protocol;
            }
            struct addrinfo *made =
                patina_gai_node(&addresses[at], port, socktype, protocol, canonical);
            if (made == NULL) {
                freeaddrinfo(head);
                return EAI_MEMORY;
            }
            canonical = NULL;
            *tail = made;
            tail = &made->ai_next;
        }
    }
    *res = head;
    return 0;
}

/*
 * The virtual interface table (patina_net_interface: `lo`, `eth0`), the one
 * the socket ioctls and rtnetlink answer from. An unknown name is glibc's
 * SIOCGIFINDEX answer, ENODEV, or Darwin's ENXIO.
 */
unsigned int if_nametoindex(const char *ifname) {
    struct patina_interface interface;
    for (uint32_t at = 0; patina_net_interface(at, &interface) == 0; ++at) {
        if (strncmp(interface.name, ifname, sizeof interface.name) == 0) return interface.index;
    }
#ifdef __linux__
    errno = ENODEV;
#else
    errno = ENXIO;
#endif
    return 0;
}

#ifdef __linux__
/*
 * getifaddrs/freeifaddrs, as glibc builds the list from its RTM_GETLINK and
 * RTM_GETADDR dumps (sysdeps/unix/sysv/linux/ifaddrs.c): one AF_PACKET entry
 * per interface (a sockaddr_ll with its link address, the broadcast link
 * address, and the link statistics in `ifa_data`), then each interface's
 * IPv4 address (with its netmask and, on a broadcast link, broadcast
 * address), then each IPv6 address (with its prefix as the netmask). The
 * whole list is one allocation, as glibc's is: freeifaddrs frees it.
 */
struct patina_ifaddrs_entry {
    struct ifaddrs ifa;
    union {
        struct sockaddr_ll ll;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } addr, netmask, broadcast;
    char name[IF_NAMESIZE];
    struct rtnl_link_stats stats;
};

static void patina_ifaddrs_prefix(unsigned char *mask, size_t len, unsigned prefix) {
    for (size_t at = 0; at < len; ++at) {
        unsigned bits = prefix > 8 ? 8 : prefix;
        mask[at] = (unsigned char)(0xff00u >> bits);
        prefix -= bits;
    }
}

static int patina_getifaddrs(struct ifaddrs **out) {
    struct patina_interface interfaces[8];
    size_t count = 0;
    size_t entries = 0;
    while (count < sizeof interfaces / sizeof interfaces[0] &&
           patina_net_interface((uint32_t)count, &interfaces[count]) == 0) {
        entries += 2 + (interfaces[count].has_ipv6 ? 1 : 0);
        ++count;
    }
    struct patina_ifaddrs_entry *list = calloc(entries, sizeof *list);
    if (list == NULL) {
        errno = ENOMEM;
        return -1;
    }
    size_t at = 0;
    for (int pass = 0; pass < 3; ++pass) {
        for (size_t index = 0; index < count; ++index) {
            const struct patina_interface *interface = &interfaces[index];
            if (pass == 2 && !interface->has_ipv6) continue;
            struct patina_ifaddrs_entry *entry = &list[at];
            memcpy(entry->name, interface->name, IF_NAMESIZE);
            entry->name[IF_NAMESIZE - 1] = '\0';
            entry->ifa.ifa_name = entry->name;
            entry->ifa.ifa_flags = interface->flags;
            entry->ifa.ifa_addr = (struct sockaddr *)&entry->addr;
            if (pass == 0) {
                struct sockaddr_ll *ll = &entry->addr.ll;
                ll->sll_family = AF_PACKET;
                ll->sll_ifindex = (int)interface->index;
                ll->sll_hatype = interface->hardware_type;
                ll->sll_halen = 6;
                memcpy(ll->sll_addr, interface->hardware_address, 6);
                entry->broadcast.ll = *ll;
                memcpy(entry->broadcast.ll.sll_addr, interface->broadcast_hardware_address, 6);
                entry->ifa.ifa_broadaddr = (struct sockaddr *)&entry->broadcast;
                entry->ifa.ifa_data = &entry->stats;
            } else if (pass == 1) {
                entry->addr.in.sin_family = AF_INET;
                memcpy(&entry->addr.in.sin_addr, interface->ipv4, 4);
                entry->netmask.in.sin_family = AF_INET;
                memcpy(&entry->netmask.in.sin_addr, interface->ipv4_netmask, 4);
                entry->ifa.ifa_netmask = (struct sockaddr *)&entry->netmask;
                if (interface->flags & IFF_BROADCAST) {
                    entry->broadcast.in.sin_family = AF_INET;
                    memcpy(&entry->broadcast.in.sin_addr, interface->ipv4_broadcast, 4);
                    entry->ifa.ifa_broadaddr = (struct sockaddr *)&entry->broadcast;
                }
            } else {
                entry->addr.in6.sin6_family = AF_INET6;
                memcpy(&entry->addr.in6.sin6_addr, interface->ipv6, 16);
                entry->netmask.in6.sin6_family = AF_INET6;
                patina_ifaddrs_prefix(entry->netmask.in6.sin6_addr.s6_addr, 16,
                                      interface->ipv6_prefix);
                entry->ifa.ifa_netmask = (struct sockaddr *)&entry->netmask;
            }
            if (at > 0) list[at - 1].ifa.ifa_next = &entry->ifa;
            ++at;
        }
    }
    *out = &list[0].ifa;
    return 0;
}

static void patina_freeifaddrs(struct ifaddrs *list) {
    free(list);
}

int getifaddrs(struct ifaddrs **out) {
    return patina_getifaddrs(out);
}

void freeifaddrs(struct ifaddrs *list) {
    patina_freeifaddrs(list);
}
#endif
