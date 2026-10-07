/*
 * Threads: the frames glibc's forced unwind (pthread_exit, an acting
 * cancellation) crosses, and pthread_once's guest call on both platforms. The
 * pthread adapters, pthread_once's state and the other Darwin doors are Rust
 * (src/posix/thread_sync.rs); these C bodies call its returning helpers before
 * anything can leave nonlocally.
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

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

void pthread_exit(void *retval) {
    patina_exit_thread(retval);
}

/*
 * Cancellation (src/thread/cancel.rs): the model keeps each thread's state and
 * requests, and a negative answer means the caller acts on a cancellation now,
 * glibc's pthread_exit(PTHREAD_CANCELED), from C.
 */
int pthread_cancel(pthread_t thread) {
    int rc = patina_thread_cancel((uintptr_t)thread);
    if (rc < 0) patina_act_on_cancel();
    return rc;
}

int pthread_setcancelstate(int state, int *oldstate) {
    int rc = patina_cancel_setstate(state, oldstate);
    if (rc < 0) patina_act_on_cancel();
    return rc;
}

int pthread_setcanceltype(int type, int *oldtype) {
    int rc = patina_cancel_settype(type, oldtype);
    if (rc < 0) patina_act_on_cancel();
    return rc;
}

void pthread_testcancel(void) {
    if (patina_cancel_test()) patina_act_on_cancel();
}

#endif

/* The Rust once state (src/posix/thread_sync.rs): a claimed entry, or NULL
 * once done; then done, or (Linux) fresh again when the routine never
 * returns. */
extern int patina_once_begin(pthread_once_t *once_control, void **entry);
extern void patina_once_done(void *entry);
#ifdef __linux__
extern void patina_once_reset(void *entry);
#endif

/*
 * pthread_once calls the guest's init routine from C on both platforms, with
 * every Rust helper returned. Linux keeps the cleanup record around it: a
 * routine that never returns (pthread_exit, or a cancellation acting in it)
 * leaves the control fresh again as the unwind leaves this frame, glibc's
 * clear_once_control (nptl pthread_once.c). Darwin's pthread_exit and
 * cancellation fail closed, so no forced unwind reaches the routine there.
 */
int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    void *entry;
    int rc = patina_once_begin(once_control, &entry);
    if (rc != 0 || entry == NULL) return rc;
#ifdef __linux__
    struct _pthread_cleanup_buffer reset;
    patina_cleanup_push(&reset, patina_once_reset, entry);
#endif
    init_routine();
#ifdef __linux__
    patina_cleanup_pop(&reset, 0);
#endif
    patina_once_done(entry);
    return 0;
}
