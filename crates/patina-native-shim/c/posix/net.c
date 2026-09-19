/*
 * Network (SimNet): sockets, transfer, options, DNS, socketpair.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

/*
 * Virtual AF_INET/SOCK_DGRAM datagram sockets over SimNet. Only IPv4 datagrams
 * are supported; TCP (SOCK_STREAM), IPv6, and name resolution are denied
 * fail-closed. Sockets are fully virtual: no host network symbol is called.
 */
static int patina_parse_sockaddr(const struct sockaddr *addr, socklen_t len,
                                 uint32_t *ip, uint16_t *port) {
    if (addr == NULL || addr->sa_family != AF_INET ||
        len < (socklen_t)sizeof(struct sockaddr_in)) {
        return -1;
    }
    const struct sockaddr_in *in = (const struct sockaddr_in *)(const void *)addr;
    *ip = ntohl(in->sin_addr.s_addr);
    *port = ntohs(in->sin_port);
    return 0;
}

static void patina_fill_sockaddr(struct sockaddr *addr, socklen_t *len,
                                 uint32_t ip, uint16_t port) {
    if (addr == NULL || len == NULL) return;
    struct sockaddr_in in;
    memset(&in, 0, sizeof in);
    in.sin_family = AF_INET;
    in.sin_addr.s_addr = htonl(ip);
    in.sin_port = htons(port);
    socklen_t copy = *len < (socklen_t)sizeof in ? *len : (socklen_t)sizeof in;
    memcpy(addr, &in, copy);
    *len = (socklen_t)sizeof in;
}

int socket(int domain, int type, int protocol) {
    if (domain != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    int nonblocking = 0;
    int cloexec = 0;
    int base = type;
#ifdef SOCK_NONBLOCK
    if (base & SOCK_NONBLOCK) {
        nonblocking = 1;
        base &= ~SOCK_NONBLOCK;
    }
#endif
#ifdef SOCK_CLOEXEC
    if (base & SOCK_CLOEXEC) {
        cloexec = 1;
        base &= ~SOCK_CLOEXEC;
    }
#endif
    int stream = 0;
    if (base == SOCK_DGRAM) {
        if (protocol != 0 && protocol != IPPROTO_UDP) {
            errno = EPROTONOSUPPORT;
            return -1;
        }
        stream = 0;
    } else if (base == SOCK_STREAM) {
        if (protocol != 0 && protocol != IPPROTO_TCP) {
            errno = EPROTONOSUPPORT;
            return -1;
        }
        stream = 1;
    } else {
        errno = EPROTOTYPE;
        return -1;
    }
    int fd = patina_net_socket(stream, nonblocking, cloexec);
    if (fd < 0) errno = patina_errno();
    return fd;
}

/* The kind checks the socket family needs before the class entries: a number
 * that names nothing is EBADF, one that names anything but a socket or a
 * socketpair endpoint is ENOTSOCK. Returns 1 for a pipe/socketpair endpoint
 * (whose send/recv are the pipe transfer), 0 for a socket, -1 with errno. */
static int patina_socket_or_pair(int fd) {
    int kind = patina_fd_kind(fd);
    if (kind < 0) {
        errno = EBADF;
        return -1;
    }
    if (kind == PATINA_FD_PIPE) return 1;
    if (kind != PATINA_FD_SOCKET) {
        errno = ENOTSOCK;
        return -1;
    }
    return 0;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    uint32_t ip;
    uint16_t port;
    if (patina_parse_sockaddr(addr, len, &ip, &port) != 0) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return fail_int(patina_net_bind(fd, ip, port));
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    uint32_t ip;
    uint16_t port;
    if (patina_parse_sockaddr(addr, len, &ip, &port) != 0) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    int kind = patina_net_kind(fd);
    if (kind == 3) {
        errno = EISCONN;
        return -1;
    }
    if (kind == 1) return fail_int(patina_net_tcp_connect(fd, ip, port));
    if (kind == 2) {
        errno = EOPNOTSUPP;
        return -1;
    }
    /* A datagram socket, or not a socket at all: the entry answers
     * EBADF/ENOTSOCK from the descriptor table. */
    return fail_int(patina_net_connect(fd, ip, port));
}

static int patina_stream_flags_supported(int flags) {
#ifdef MSG_NOSIGNAL
    flags &= ~MSG_NOSIGNAL;
#endif
    return flags == 0;
}

/* A socketpair endpoint is a connected AF_UNIX stream, so the message-based
 * socket I/O (send/recv/sendto/recvfrom) is the same in-process byte channel as
 * write/read — tokio's UnixStream reaches the fd through send/recv, not
 * write/read. An addressed sendto/recvfrom on a connected pair is EISCONN. */
ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *addr, socklen_t alen) {
    int pair = patina_socket_or_pair(fd);
    if (pair < 0) return -1;
    if (pair) {
        if (addr != NULL) {
            errno = EISCONN;
            return -1;
        }
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_pipe_write(fd, buf, len, flags));
    }
    int kind = patina_net_kind(fd);
    if (kind == 3) {
        if (addr != NULL) {
            errno = EISCONN;
            return -1;
        }
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_net_stream_send(fd, buf, len, flags));
    }
    if (addr != NULL) {
        uint32_t ip;
        uint16_t port;
        if (patina_parse_sockaddr(addr, alen, &ip, &port) != 0) {
            errno = EAFNOSUPPORT;
            return -1;
        }
        return fail_size(patina_net_sendto(fd, buf, len, ip, port));
    }
    return fail_size(patina_net_send(fd, buf, len));
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    int pair = patina_socket_or_pair(fd);
    if (pair < 0) return -1;
    if (pair) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_pipe_write(fd, buf, len, flags));
    }
    int kind = patina_net_kind(fd);
    if (kind == 3) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_net_stream_send(fd, buf, len, flags));
    }
    return fail_size(patina_net_send(fd, buf, len));
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *addr, socklen_t *alen) {
    int pair = patina_socket_or_pair(fd);
    if (pair < 0) return -1;
    if (pair) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        (void)addr;
        (void)alen;
        return fail_size(patina_pipe_read(fd, buf, len));
    }
    int kind = patina_net_kind(fd);
    if (kind == 3) {
        if (addr != NULL) {
            errno = EISCONN;
            return -1;
        }
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_net_stream_recv(fd, buf, len));
    }
    uint32_t ip = 0;
    uint16_t port = 0;
    ssize_t result = fail_size(patina_net_recvfrom(fd, buf, len, &ip, &port));
    if (result >= 0) patina_fill_sockaddr(addr, alen, ip, port);
    return result;
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    int pair = patina_socket_or_pair(fd);
    if (pair < 0) return -1;
    if (pair) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_pipe_read(fd, buf, len));
    }
    int kind = patina_net_kind(fd);
    if (kind == 3) {
        if (!patina_stream_flags_supported(flags)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        return fail_size(patina_net_stream_recv(fd, buf, len));
    }
    return fail_size(patina_net_recv(fd, buf, len));
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
    uint32_t ip;
    uint16_t port;
    if (patina_net_getsockname(fd, &ip, &port) != 0) {
        errno = patina_errno();
        return -1;
    }
    patina_fill_sockaddr(addr, len, ip, port);
    return 0;
}

static int patina_zero_timeval(const void *value, socklen_t len) {
    if (value == NULL || len < (socklen_t)sizeof(struct timeval)) return 0;
    const struct timeval *time = (const struct timeval *)value;
    return time->tv_sec == 0 && time->tv_usec == 0;
}

static int patina_linger_off(const void *value, socklen_t len) {
    if (value == NULL || len < (socklen_t)sizeof(struct linger)) return 0;
    const struct linger *linger = (const struct linger *)value;
    return linger->l_onoff == 0;
}

/* Virtual sockets allow only deterministic no-op option writes. */
int setsockopt(int fd, int level, int optname, const void *value, socklen_t len) {
    /* A socketpair endpoint is a socket for the option calls: the same
     * deterministic no-op answers. */
    if (patina_socket_or_pair(fd) < 0) return -1;
    if (level == SOL_SOCKET) {
        switch (optname) {
            case SO_REUSEADDR:
#ifdef SO_REUSEPORT
            case SO_REUSEPORT:
#endif
#ifdef SO_NOSIGPIPE
            case SO_NOSIGPIPE:
#endif
            case SO_KEEPALIVE:
            case SO_BROADCAST:
                return 0;
            case SO_LINGER:
                if (patina_linger_off(value, len)) return 0;
                break;
            case SO_RCVTIMEO:
                /* Deterministic receive timeout: store the timeval (in virtual
                 * nanoseconds) on the socket so a blocking recv is bounded by the
                 * virtual clock. A zero timeval is POSIX "no timeout" and clears
                 * it. */
                if (value != NULL && len >= (socklen_t)sizeof(struct timeval)) {
                    const struct timeval *rcv = (const struct timeval *)value;
                    uint64_t nanos = (uint64_t)rcv->tv_sec * 1000000000ull +
                                     (uint64_t)rcv->tv_usec * 1000ull;
                    if (patina_net_set_read_timeout(fd, nanos) != 0) {
                        errno = patina_errno();
                        return -1;
                    }
                    return 0;
                }
                break;
            case SO_SNDTIMEO:
                /* Send timeouts are moot: virtual datagram/stream sends never
                 * block, so only the no-op zero timeval is accepted. */
                if (patina_zero_timeval(value, len)) return 0;
                break;
            default:
                break;
        }
    }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY) return 0;
    errno = ENOPROTOOPT;
    return -1;
}

int getsockopt(int fd, int level, int optname, void *value, socklen_t *len) {
    (void)level;
    (void)optname;
    if (patina_socket_or_pair(fd) < 0) return -1;
    if (value != NULL && len != NULL) memset(value, 0, *len);
    return 0;
}

int listen(int fd, int backlog) {
    return fail_int(patina_net_listen(fd, backlog));
}

static int patina_accept_impl(int fd, struct sockaddr *addr, socklen_t *len, int nonblocking,
                              int cloexec) {
    uint32_t ip = 0;
    uint16_t port = 0;
    int accepted = patina_net_accept(fd, &ip, &port, nonblocking, cloexec);
    if (accepted < 0) {
        errno = patina_errno();
        return -1;
    }
    patina_fill_sockaddr(addr, len, ip, port);
    return accepted;
}

int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    return patina_accept_impl(fd, addr, len, 0, 0);
}

#ifdef __linux__
int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    int allowed = SOCK_CLOEXEC;
#ifdef SOCK_NONBLOCK
    allowed |= SOCK_NONBLOCK;
#endif
    if ((flags & ~allowed) != 0) {
        errno = EINVAL;
        return -1;
    }
    int nonblocking = 0;
#ifdef SOCK_NONBLOCK
    nonblocking = (flags & SOCK_NONBLOCK) != 0;
#endif
    return patina_accept_impl(fd, addr, len, nonblocking, (flags & SOCK_CLOEXEC) != 0);
}

#endif

int shutdown(int fd, int how) {
    int patina_how;
    if (how == SHUT_RD) patina_how = 0;
    else if (how == SHUT_WR) patina_how = 1;
    else if (how == SHUT_RDWR) patina_how = 2;
    else {
        errno = EINVAL;
        return -1;
    }
    return fail_int(patina_net_shutdown(fd, patina_how));
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    uint32_t ip;
    uint16_t port;
    if (patina_net_getpeername(fd, &ip, &port) != 0) {
        errno = patina_errno();
        return -1;
    }
    patina_fill_sockaddr(addr, len, ip, port);
    return 0;
}

/*
 * DNS: forward lookup is modeled against the run's deterministic host table.
 * IPv6 stays out of scope, and so do gethostbyname/getnameinfo — nothing modern
 * uses them for forward resolution, so they are left undefined and the pre-run
 * audit keeps denying them rather than growing vocabulary no guest consumes.
 *
 * Only a single A record is ever returned: SimNet's address space is IPv4
 * `ip:port`, so a multi-address answer would offer the guest choices that cannot
 * differ. The result is heap-allocated and freeaddrinfo really frees it.
 */

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    if (res == NULL) return EAI_FAIL;
    if (hints != NULL && hints->ai_family == AF_INET6) return EAI_FAMILY;
    /* A null node is a service-only lookup: it names the loopback address. */
    const char *name = (node == NULL) ? "localhost" : node;

    uint16_t port = 0;
    if (service != NULL) {
        /* Only numeric services resolve: a /etc/services lookup would be a host
         * dependency, and the virtual network has no service registry.
         *
         * Parsed by hand rather than with strtol. The original reason was the
         * audit: glibc resolves strtol to __isoc23_strtol, an import the
         * default-deny gate refused, and every native guest would have inherited
         * it because this translation unit is always linked. That reason is GONE —
         * the audit now normalizes the __isocNN_ generation alias onto the base
         * symbol and strtol is known-safe — but the parser stays, because the
         * remaining reason stands on its own: a digits-only parse is
         * locale-independent, where strtol's is not. */
        if (*service == '\0') return EAI_SERVICE;
        unsigned long parsed = 0;
        for (const char *digit = service; *digit != '\0'; ++digit) {
            if (*digit < '0' || *digit > '9') return EAI_SERVICE;
            parsed = parsed * 10u + (unsigned long)(*digit - '0');
            if (parsed > 65535u) return EAI_SERVICE;
        }
        port = (uint16_t)parsed;
    }

    uint32_t ip = 0;
    if (patina_dns_resolve(name, &ip) != 0) {
        /* An injected resolver timeout is transient (EAI_AGAIN, the retry the
         * guest is supposed to have); anything else is a name that does not
         * resolve. */
        return (patina_errno() == EINTR) ? EAI_AGAIN : EAI_NONAME;
    }

    struct addrinfo *out = calloc(1, sizeof(struct addrinfo));
    struct sockaddr_in *addr = calloc(1, sizeof(struct sockaddr_in));
    if (out == NULL || addr == NULL) {
        free(out);
        free(addr);
        return EAI_MEMORY;
    }
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = htonl(ip);
    out->ai_family = AF_INET;
    out->ai_socktype = (hints != NULL && hints->ai_socktype != 0) ? hints->ai_socktype : SOCK_STREAM;
    out->ai_protocol = (hints != NULL) ? hints->ai_protocol : 0;
    out->ai_addrlen = sizeof(struct sockaddr_in);
    out->ai_addr = (struct sockaddr *)addr;
    out->ai_canonname = NULL;
    out->ai_next = NULL;
    *res = out;
    return 0;
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

int socketpair(int domain, int type, int protocol, int sv[2]) {
    if (sv == NULL) {
        errno = EFAULT;
        return -1;
    }
    /* AF_LOCAL is the same constant as AF_UNIX; only a Unix-domain STREAM pair is
     * a deterministic in-process duplex. Anything else fails closed. */
    if (domain != AF_UNIX) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    int nonblocking = 0;
    int cloexec = 0;
    int base = type;
#ifdef SOCK_NONBLOCK
    if (base & SOCK_NONBLOCK) {
        nonblocking = 1;
        base &= ~SOCK_NONBLOCK;
    }
#endif
#ifdef SOCK_CLOEXEC
    if (base & SOCK_CLOEXEC) {
        cloexec = 1;
        base &= ~SOCK_CLOEXEC;
    }
#endif
    if (base != SOCK_STREAM) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (protocol != 0) {
        errno = EPROTONOSUPPORT;
        return -1;
    }
    {
        int rc = patina_socketpair(&sv[0], &sv[1], nonblocking, cloexec);
        return fail_int(rc);
    }
}

#ifdef __linux__
/*
 * recvmsg/sendmsg are the ancillary/scatter-gather message variants; std links
 * them but Patina's deterministic net layer models only sendto/recvfrom (routed
 * through patina_net_*). No supported guest uses the msg variants, so fail closed
 * softly with ENOSYS rather than aborting: the symbols leave the import table and
 * a caller cannot send or receive undeterministically.
 */
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    (void)sockfd;
    (void)msg;
    (void)flags;
    errno = ENOSYS;
    return -1;
}
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    (void)sockfd;
    (void)msg;
    (void)flags;
    errno = ENOSYS;
    return -1;
}

#endif

/*
 * `if_nametoindex`: the interface-index lookup a host networking utility stack
 * (hyper-util) links dormant. No network interfaces are modeled, so every name
 * is "no such interface": return 0 (never a valid index) with errno ENXIO.
 * hyper-util reads the 0 as an absent scope id and proceeds.
 */
unsigned int if_nametoindex(const char *ifname) {
    (void)ifname;
    errno = ENXIO;
    return 0;
}
