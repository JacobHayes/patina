/*
 * Readiness: poll, epoll/eventfd (Linux), kqueue/kevent (Darwin).
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

int poll(struct pollfd *descriptors, nfds_t count, int timeout) {
    if (count != 0) {
        if (timeout != 0) {
            errno = ENOSYS;
            return -1;
        }
        for (nfds_t index = 0; index < count; ++index) {
            if (descriptors[index].events != 0) {
                errno = ENOSYS;
                return -1;
            }
            descriptors[index].revents = 0;
        }
        return 0;
    }
    if (timeout > 0) {
        struct timespec duration = {
            .tv_sec = (time_t)(timeout / 1000),
            .tv_nsec = (long)(timeout % 1000) * 1000000L,
        };
        if (nanosleep(&duration, NULL) != 0) return -1;
    }
    return 0;
}

#ifdef __APPLE__
/*
 * kqueue / kevent / kevent64 (macOS readiness reactor). The Rust reactor owns
 * the knote registry, readiness, deterministic ordering, and the multi-fd
 * fan-in park (see the "kqueue / kevent readiness reactor" section in the Rust
 * shim); these interposers only marshal the platform struct kevent/kevent64_s
 * changelists and eventlists to and from the platform-neutral patina_kevent and
 * decode the timeout into the reactor's blocking mode. Being strong defs, the
 * guest's kqueue/kevent/kevent64 bind here and the libc symbols drop off the
 * import table, so the pre-run wait-multiplex gate clears with no allowance.
 *
 * `struct patina_kevent` is laid out to match `struct kevent` field for field,
 * so a kevent eventlist is marshalled by a direct reinterpret. kevent64_s carries
 * an `ext[2]` tail struct kevent lacks, so its eventlist is widened field by field.
 */
_Static_assert(sizeof(struct patina_kevent) == sizeof(struct kevent),
               "patina_kevent must match struct kevent size");
_Static_assert(offsetof(struct patina_kevent, ident) == offsetof(struct kevent, ident),
               "patina_kevent.ident offset");
_Static_assert(offsetof(struct patina_kevent, filter) == offsetof(struct kevent, filter),
               "patina_kevent.filter offset");
_Static_assert(offsetof(struct patina_kevent, flags) == offsetof(struct kevent, flags),
               "patina_kevent.flags offset");
_Static_assert(offsetof(struct patina_kevent, fflags) == offsetof(struct kevent, fflags),
               "patina_kevent.fflags offset");
_Static_assert(offsetof(struct patina_kevent, data) == offsetof(struct kevent, data),
               "patina_kevent.data offset");
_Static_assert(offsetof(struct patina_kevent, udata) == offsetof(struct kevent, udata),
               "patina_kevent.udata offset");

int kqueue(void) {
    int fd = patina_kqueue();
    if (fd < 0) errno = patina_errno();
    return fd;
}

/*
 * Decode the kevent timeout into the reactor's (mode, nanos): NULL blocks until
 * ready, a zero timespec is a non-blocking poll, and a positive one is a
 * relative virtual-clock deadline.
 */
static int patina_kevent_mode(const struct timespec *timeout, uint64_t *nanos) {
    *nanos = 0;
    if (timeout == NULL) return 1;
    if (timeout->tv_sec == 0 && timeout->tv_nsec == 0) return 0;
    *nanos = (uint64_t)timeout->tv_sec * UINT64_C(1000000000) + (uint64_t)timeout->tv_nsec;
    return 2;
}

int kevent(int kq, const struct kevent *changelist, int nchanges, struct kevent *eventlist,
           int nevents, const struct timespec *timeout) {
    if (patina_kqueue_is_kq(kq) == 0) {
        errno = EBADF;
        return -1;
    }
    if ((nchanges > 0 && changelist == NULL) ||
        (timeout != NULL && (timeout->tv_sec < 0 || timeout->tv_nsec < 0))) {
        errno = EINVAL;
        return -1;
    }
    /* Apply the changelist. A change carrying EV_RECEIPT (mio sets it on every
     * register), or one that fails, yields an EV_ERROR receipt whose data is the
     * errno (0 on success) — the standard bulk-change protocol mio reads back. */
    int nout = 0;
    for (int index = 0; index < nchanges; ++index) {
        const struct kevent *change = &changelist[index];
        int rc = patina_kqueue_apply(kq, (uint64_t)change->ident, change->filter, change->flags,
                                     change->fflags, (int64_t)change->data,
                                     (uintptr_t)change->udata);
        if ((change->flags & EV_RECEIPT) || rc != 0) {
            if (eventlist != NULL && nout < nevents) {
                /* eventlist may alias changelist (mio reuses the buffer); copy
                 * the change's identity out before overwriting the slot. */
                uintptr_t ident = change->ident;
                int16_t filter = change->filter;
                void *udata = change->udata;
                struct kevent *event = &eventlist[nout++];
                event->ident = ident;
                event->filter = filter;
                event->flags = EV_ERROR;
                event->fflags = 0;
                event->data = rc;
                event->udata = udata;
            } else if (rc != 0) {
                errno = rc;
                return -1;
            }
        }
    }
    if (nout > 0) return nout;
    uint64_t nanos;
    int mode = patina_kevent_mode(timeout, &nanos);
    int count = patina_kevent_gather(kq, (struct patina_kevent *)eventlist,
                                     nevents < 0 ? 0 : nevents, mode, nanos);
    if (count < 0) {
        errno = patina_errno();
        return -1;
    }
    return count;
}

int kevent64(int kq, const struct kevent64_s *changelist, int nchanges,
             struct kevent64_s *eventlist, int nevents, unsigned int flags,
             const struct timespec *timeout) {
    (void)flags; /* KEVENT_FLAG_* immediacy is governed by `timeout` here. */
    if (patina_kqueue_is_kq(kq) == 0) {
        errno = EBADF;
        return -1;
    }
    if ((nchanges > 0 && changelist == NULL) ||
        (timeout != NULL && (timeout->tv_sec < 0 || timeout->tv_nsec < 0))) {
        errno = EINVAL;
        return -1;
    }
    int nout = 0;
    for (int index = 0; index < nchanges; ++index) {
        const struct kevent64_s *change = &changelist[index];
        int rc = patina_kqueue_apply(kq, change->ident, change->filter, change->flags,
                                     change->fflags, (int64_t)change->data,
                                     (uintptr_t)change->udata);
        if ((change->flags & EV_RECEIPT) || rc != 0) {
            if (eventlist != NULL && nout < nevents) {
                uint64_t ident = change->ident;
                uint64_t udata = change->udata;
                int16_t filter = change->filter;
                struct kevent64_s *event = &eventlist[nout++];
                event->ident = ident;
                event->filter = filter;
                event->flags = EV_ERROR;
                event->fflags = 0;
                event->data = rc;
                event->udata = udata;
                event->ext[0] = 0;
                event->ext[1] = 0;
            } else if (rc != 0) {
                errno = rc;
                return -1;
            }
        }
    }
    if (nout > 0) return nout;
    uint64_t nanos;
    int mode = patina_kevent_mode(timeout, &nanos);
    int capacity = nevents < 0 ? 0 : nevents;
    struct patina_kevent *scratch = NULL;
    if (capacity > 0) {
        scratch = calloc((size_t)capacity, sizeof *scratch);
        if (scratch == NULL) {
            errno = ENOMEM;
            return -1;
        }
    }
    int count = patina_kevent_gather(kq, scratch, capacity, mode, nanos);
    if (count < 0) {
        free(scratch);
        errno = patina_errno();
        return -1;
    }
    for (int index = 0; index < count; ++index) {
        struct kevent64_s *event = &eventlist[index];
        event->ident = scratch[index].ident;
        event->filter = scratch[index].filter;
        event->flags = scratch[index].flags;
        event->fflags = scratch[index].fflags;
        event->data = scratch[index].data;
        event->udata = (uint64_t)(uintptr_t)scratch[index].udata;
        event->ext[0] = 0;
        event->ext[1] = 0;
    }
    free(scratch);
    return count;
}

#endif

#ifdef __linux__
/*
 * epoll / eventfd readiness reactor (Linux) — the mirror of the kqueue block
 * above. The Rust reactor owns the interest registry, readiness, deterministic
 * ordering, and the multi-fd fan-in park (see the "epoll readiness reactor"
 * section in the Rust shim); these interposers are deliberately thin because
 * patina_epoll_create1 / patina_epoll_ctl / patina_epoll_wait / patina_eventfd
 * are already syscall-shaped for the future syscall-user-dispatch SIGSYS
 * dispatcher. Being strong defs, the guest's epoll and eventfd references bind
 * here and the libc symbols drop off the import table, so the pre-run
 * wait-multiplex / shared-memory-ipc gates clear with no allowance.
 *
 * The Rust side reads and writes `struct epoll_event` with the kernel ABI
 * layout (packed on x86_64, natural alignment elsewhere); pin the platform
 * struct against that expectation.
 */
_Static_assert(offsetof(struct epoll_event, events) == 0, "epoll_event.events offset");
#ifdef __x86_64__
_Static_assert(sizeof(struct epoll_event) == 12, "epoll_event packed size");
_Static_assert(offsetof(struct epoll_event, data) == 4, "epoll_event.data offset");
#else
_Static_assert(sizeof(struct epoll_event) == 16, "epoll_event natural size");
_Static_assert(offsetof(struct epoll_event, data) == 8, "epoll_event.data offset");
#endif

int epoll_create1(int flags) {
    return fail_int(patina_epoll_create1(flags));
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    return fail_int(patina_epoll_ctl(epfd, op, fd, event));
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    return fail_int(patina_epoll_wait(epfd, events, maxevents, timeout));
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout,
                const sigset_t *sigmask) {
    /* Patina delivers no ambient signals, so a NULL mask is the plain wait. A
     * real mask swap has no deterministic meaning; fail closed loudly. */
    if (sigmask != NULL)
        return patina_posix_deny("patina: epoll_pwait with a signal mask is not modeled; failing closed\n");
    return fail_int(patina_epoll_wait(epfd, events, maxevents, timeout));
}

int eventfd(unsigned int initval, int flags) {
    return fail_int(patina_eventfd(initval, flags));
}
#endif
