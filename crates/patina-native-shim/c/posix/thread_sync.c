/*
 * Threads and synchronization: pthread lifecycle, mutex/cond/rwlock, once.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

/*
 * pthread_atfork: registers handlers to run around fork(). The whole fork/exec
 * process surface is a deterministic-runtime non-goal (denied by the audit, and
 * a managed guest never forks), so a registered handler could never actually
 * run. Rust std / libc startup nonetheless *reference* this symbol (e.g. thread
 * and once machinery pull it in), and left as a host import it taints the run's
 * determinism claim even though it is a pure no-op here. Interpose it with a
 * strong definition that ignores the registration and returns success: the guest
 * reference binds here and the libc symbol drops off the import table, so the
 * pre-run gate has nothing to flag. Ignoring the handlers is sound precisely
 * because the process-class surface that would invoke them is never reached.
 */
int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void)) {
    (void)prepare;
    (void)parent;
    (void)child;
    return 0;
}

/*
 * Managed threads and pthread synchronization. These interposers route the
 * guest's pthread usage (including Rust std::thread, Mutex, and Condvar)
 * through Patina's deterministic scheduler. pthread objects are identified by
 * their storage address; the created pthread_t is the real host handle so the
 * uninterposed pthread_self, pthread_equal, and *_np helpers remain consistent.
 *
 * pthread returns error numbers directly rather than through errno.
 */
/*
 * The strong interposer that owns thread creation on both platforms: every
 * guest/std `pthread_create` binds here and is routed through Patina's
 * deterministic scheduler. The shim reaches the *real* host creator through a
 * distinct, non-interposed vehicle so it never recurses into this definition —
 * on macOS `pthread_create_suspended_np` plus a mach `thread_resume`, on Linux
 * the genuine glibc `pthread_create` resolved through `dlsym(RTLD_NEXT, ...)`,
 * the same host-alias primitive that reaches the real `read`/`write`/`sem_*`.
 * See the shim's `spawn_host_thread`. (glibc ships `__wrap_pthread_create` in
 * libgcc's split-stack support on x86, so the shim must NOT use `--wrap` here.)
 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    return patina_thread_create((void **)thread, (const void *)attr, start_routine, arg);
}

int pthread_join(pthread_t thread, void **retval) {
    return patina_thread_join((void *)thread, retval);
}

int pthread_detach(pthread_t thread) {
    return patina_thread_detach((void *)thread);
}

#ifdef __linux__
/*
 * A managed thread's host start routine. glibc's start_thread calls it, and it
 * calls the guest routine, so the frames a forced unwind (pthread_exit) crosses
 * between the guest's and start_thread are this one and the guest's: the
 * unwind runs the guest's cleanup handlers, glibc longjmps into start_thread,
 * which runs the destructors, and the thread completes from its destructor
 * pass as a returning one does. The model's halves are Rust calls that return
 * before the guest routine runs and after it returned.
 */
void *patina_thread_body(void *start) {
    void *arg;
    patina_start_routine routine = patina_thread_prelude(start, &arg);
    void *value = routine(arg);
    patina_thread_returned(value);
    return value;
}

/*
 * The model takes the value and answers glibc's own pthread_exit, called here
 * in C once no Rust frame is left on the stack: its forced unwind could not
 * cross one.
 */
void pthread_exit(void *retval) {
    patina_host_pthread_exit_fn host_exit = patina_thread_exiting(retval);
    host_exit(retval);
}
#else
void pthread_exit(void *retval) {
    patina_thread_exit(retval);
    __builtin_unreachable();
}
#endif

#ifdef __linux__
/* A thread's name (`comm`) is modeled per thread: the executable's by default,
 * inherited by a new thread, and changed by these and `prctl(PR_SET_NAME)`. */
int pthread_getname_np(pthread_t thread, char *name, size_t len) {
    return patina_thread_getname((uintptr_t)thread, name, len);
}

int pthread_setname_np(pthread_t thread, const char *name) {
    return patina_thread_setname((uintptr_t)thread, name);
}

#endif

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    return patina_mutex_init((void *)mutex, (const void *)attr);
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    return patina_mutex_lock((void *)mutex);
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    return patina_mutex_trylock((void *)mutex);
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    return patina_mutex_unlock((void *)mutex);
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    return patina_mutex_destroy((void *)mutex);
}

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    return patina_cond_init((void *)cond, (const void *)attr);
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    return patina_cond_wait((void *)cond, (void *)mutex);
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                           const struct timespec *abstime) {
    return patina_cond_timedwait((void *)cond, (void *)mutex, (const void *)abstime);
}

#ifdef __APPLE__
/* Rust std lowers `Condvar::wait_timeout` on Darwin to this relative-deadline
 * variant. Convert the relative wait to an absolute deadline against the
 * interposed virtual CLOCK_REALTIME (the file-local clock_gettime above) and
 * take the ordinary timed-wait path, so timeouts stay on the virtual-clock
 * timer queue. */
int pthread_cond_timedwait_relative_np(pthread_cond_t *cond, pthread_mutex_t *mutex,
                                       const struct timespec *reltime) {
    if (reltime == NULL || reltime->tv_sec < 0 || reltime->tv_nsec < 0 ||
        reltime->tv_nsec >= 1000000000L) {
        return EINVAL;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return errno;
    uint64_t now_nanos =
        (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    uint64_t rel_nanos =
        (uint64_t)reltime->tv_sec * UINT64_C(1000000000) + (uint64_t)reltime->tv_nsec;
    if (rel_nanos > UINT64_MAX - now_nanos) return EINVAL;
    uint64_t deadline = now_nanos + rel_nanos;
    struct timespec abstime = {
        .tv_sec = (time_t)(deadline / UINT64_C(1000000000)),
        .tv_nsec = (long)(deadline % UINT64_C(1000000000)),
    };
    return patina_cond_timedwait((void *)cond, (void *)mutex, (const void *)&abstime);
}

#endif

int pthread_cond_signal(pthread_cond_t *cond) {
    return patina_cond_signal((void *)cond);
}

int pthread_cond_broadcast(pthread_cond_t *cond) {
    return patina_cond_broadcast((void *)cond);
}

int pthread_cond_destroy(pthread_cond_t *cond) {
    return patina_cond_destroy((void *)cond);
}

/*
 * pthread synchronization Patina does not model deterministically is denied
 * (fail-closed) rather than allowed to fall through to the host, where it would
 * block a real thread outside the scheduler. (pthread_barrier_* and
 * pthread_spin_* do not exist on Darwin and are left to a future Linux layer.)
 */
int pthread_cancel(pthread_t thread) {
    (void)thread;
    return ENOSYS;
}

/*
 * pthread_rwlock_* routes reader/writer contention through the deterministic
 * scheduler (the lock's kind from the attribute or static initializer, as
 * glibc keeps three: readers preferred by default, writer-to-writer hand-over
 * for PREFER_WRITER_NP, which PREFER_WRITER_NONRECURSIVE_NP adds new readers
 * waiting behind a waiting writer to; FIFO among writers; blocked readers
 * woken together). Rust std::sync::RwLock uses the queue-based parking
 * RwLock on the supported toolchains and does not reach these symbols, so this
 * is for C guests (and any std that lowers to pthread).
 */
int pthread_rwlock_init(pthread_rwlock_t *lock, const pthread_rwlockattr_t *attr) {
    return patina_rwlock_init((void *)lock, (const void *)attr);
}

int pthread_rwlock_destroy(pthread_rwlock_t *lock) {
    return patina_rwlock_destroy((void *)lock);
}

int pthread_rwlock_rdlock(pthread_rwlock_t *lock) {
    return patina_rwlock_rdlock((void *)lock);
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *lock) {
    return patina_rwlock_tryrdlock((void *)lock);
}

int pthread_rwlock_wrlock(pthread_rwlock_t *lock) {
    return patina_rwlock_wrlock((void *)lock);
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *lock) {
    return patina_rwlock_trywrlock((void *)lock);
}

int pthread_rwlock_unlock(pthread_rwlock_t *lock) {
    return patina_rwlock_unlock((void *)lock);
}

/*
 * pthread_once: run `init_routine` exactly once across all managed threads,
 * concurrent callers blocking until the first completes (aws-lc's lazy library
 * init reaches it). The pthread_once_t storage layout is not portable (glibc's
 * is a bare zeroed int; Darwin's carries a nonzero signature word), so state is
 * tracked in a shim-side registry keyed on the control-block ADDRESS — the
 * os_unfair_lock lazy-registration convention — guarded by a deterministic
 * mutex + condvar that route through the scheduler (the interposed pthread_mutex
 * and pthread_cond families above). This is deadlock-free and deterministic under the cooperative
 * scheduler: exactly one thread transitions the entry to "running", runs the
 * init with the guard released, then wakes any waiters. A strong def, so the
 * symbol drops off the import table.
 */
struct patina_once_entry {
    pthread_once_t *key;
    int state; /* 0 = fresh, 1 = running, 2 = done */
    struct patina_once_entry *next;
};
static struct patina_once_entry *patina_once_registry;
static pthread_mutex_t patina_once_guard = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t patina_once_cond = PTHREAD_COND_INITIALIZER;

#ifdef __linux__
/*
 * An init routine that never returns (it calls pthread_exit, or a
 * cancellation acts in it) leaves the control fresh again and wakes the
 * callers waiting on it, one of which then runs the init: glibc's
 * clear_once_control, a cleanup record around the routine (nptl
 * pthread_once.c), run as the unwind leaves this frame.
 */
static void patina_once_reset(void *arg) {
    struct patina_once_entry *entry = arg;
    pthread_mutex_lock(&patina_once_guard);
    entry->state = 0;
    pthread_cond_broadcast(&patina_once_cond);
    pthread_mutex_unlock(&patina_once_guard);
}
#endif

int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    /* Both parameters are declared nonnull by libc (a NULL compare is -Werror
     * under gcc), so the contract is trusted — the gethostname precedent. */
    pthread_mutex_lock(&patina_once_guard);
    struct patina_once_entry *entry = patina_once_registry;
    while (entry != NULL && entry->key != once_control) {
        entry = entry->next;
    }
    if (entry == NULL) {
        entry = malloc(sizeof *entry);
        if (entry == NULL) {
            pthread_mutex_unlock(&patina_once_guard);
            return ENOMEM;
        }
        entry->key = once_control;
        entry->state = 0;
        entry->next = patina_once_registry;
        patina_once_registry = entry;
    }
    while (entry->state == 1) {
        pthread_cond_wait(&patina_once_cond, &patina_once_guard);
    }
    if (entry->state == 2) {
        pthread_mutex_unlock(&patina_once_guard);
        return 0;
    }
    entry->state = 1;
    pthread_mutex_unlock(&patina_once_guard);
#ifdef __linux__
    struct _pthread_cleanup_buffer reset;
    patina_cleanup_push(&reset, patina_once_reset, entry);
    init_routine();
    patina_cleanup_pop(&reset, 0);
#else
    init_routine();
#endif
    pthread_mutex_lock(&patina_once_guard);
    entry->state = 2;
    pthread_cond_broadcast(&patina_once_cond);
    pthread_mutex_unlock(&patina_once_guard);
    return 0;
}

#if defined(__linux__) && defined(__x86_64__)
/*
 * The x86_64 thread-pointer rows' glibc wrappers (glibc declares neither in a
 * header). Both enter the one model (`src/sud/thread_pointer.rs`), which
 * refuses by name whatever would move the thread pointer. `modify_ldt`'s row
 * answers an int in a zero-extended register, errors included, and glibc's
 * wrapper hands that int back as it is (-22 for EINVAL, errno untouched):
 * `signal_result` does the same, since such a value is never negative.
 */
int arch_prctl(int code, unsigned long addr) {
    return signal_result(patina_sud_dispatch(SYS_arch_prctl, (uint64_t)(int64_t)code,
        (uint64_t)addr, 0, 0, 0, 0, 0));
}
int modify_ldt(int func, void *ptr, unsigned long bytecount) {
    return signal_result(patina_sud_dispatch(SYS_modify_ldt, (uint64_t)(int64_t)func,
        (uintptr_t)ptr, (uint64_t)bytecount, 0, 0, 0, 0));
}
#endif
