/*
 * Environment: the scrubbed host environment, the control-plane snapshot, and
 * the modeled getenv/setenv/unsetenv/clearenv map (putenv fails closed).
 *
 * This file is one family slice of the native shim's single C translation unit:
 * `c/patina_posix.c` #includes every slice under `c/posix/` in a fixed order, so the
 * slices share one set of headers, one set of static helpers, and one object
 * (`patina_posix.o`). It is not compiled on its own. The registry in
 * `src/registry/` maps every public symbol defined here to the syscall rows it
 * serves; a new interposer needs a symbol row (the object scan fails otherwise).
 */

extern char **environ;

/* Snapshot of the PATINA_* control plane, captured before the ambient host
 * environment is scrubbed. Public getenv/secure_getenv read only Patina's
 * deterministic guest map after startup (NULL before startup and when unset);
 * shim-internal startup reads use patina_control_getenv. */
static char **patina_control_plane = NULL;
/* Capture runs exactly once. After the deterministic array is published,
 * patina_environ_base() no longer sees the ambient host entries, so a second
 * capture would snapshot the guest's own PATINA_-prefixed values instead. */
static int patina_control_plane_captured = 0;
/* The AMBIENT host array, remembered at capture time. Everything after startup
 * must scrub through this rather than through patina_environ_base(): publishing
 * repoints the environ global at the deterministic array, and `main`'s third
 * `envp` parameter keeps pointing at the original. */
static char **patina_host_environ = NULL;

static char **patina_environ_base(void) {
#ifdef __APPLE__
    return *_NSGetEnviron();
#else
    return environ;
#endif
}

static void patina_capture_control_plane(void) {
    if (patina_control_plane_captured) return;
    patina_control_plane_captured = 1;
    char **base = patina_environ_base();
    patina_host_environ = base;
    if (base == NULL) return;
    size_t kept = 0;
    for (char **entry = base; *entry != NULL; ++entry) {
        if (strncmp(*entry, "PATINA_", 7) == 0) kept += 1;
    }
    char **snapshot = calloc(kept + 1, sizeof *snapshot);
    if (snapshot == NULL) {
        static const char message[] =
            "patina: failed to capture the PATINA_* control plane before scrubbing the environment\n";
        write(2, message, sizeof message - 1);
        abort();
    }
    size_t index = 0;
    for (char **entry = base; *entry != NULL; ++entry) {
        if (strncmp(*entry, "PATINA_", 7) == 0) {
            snapshot[index++] = *entry;
            patina_control_set_entry(*entry);
        }
    }
    snapshot[index] = NULL;
    patina_control_plane = snapshot;
}

/* Empty the AMBIENT host array in place, so nothing holding a pointer to it can
 * still read the host environment — notably `main`'s third `envp` parameter,
 * which keeps pointing at the original array after publishing repoints environ.
 * This must go through patina_host_environ, NOT patina_environ_base(): by the
 * time this runs, a supervised startup has already installed the runtime and
 * published the deterministic array, so environ_base() would return that one and
 * this would wipe the guest's own environment while leaving the host's intact.
 * The entry strings stay alive; the control-plane snapshot borrows them. */
static void patina_scrub_environ(void) {
    if (patina_host_environ == NULL) return;
    patina_host_environ[0] = NULL;
}

/* Publish a deterministic environ array built by the Rust layer from the guest
 * env map. Direct environ readers — the Linux `environ` global, Darwin
 * `_NSGetEnviron`, std::env::vars — then see exactly what the getenv interposer
 * answers, before and after any guest setenv/unsetenv. Storage is owned (and
 * deliberately leaked) by the Rust side; this only repoints the global, which is
 * what a libc setenv does when it grows the array. */
static void patina_environ_install(char **next) {
#ifdef __APPLE__
    *_NSGetEnviron() = next;
#else
    environ = next;
#endif
}

const char *patina_control_getenv(const char *name) {
    if (name == NULL || strncmp(name, "PATINA_", 7) != 0) return NULL;
    patina_capture_control_plane();
    size_t length = strlen(name);
    for (char **entry = patina_control_plane; entry != NULL && *entry != NULL; ++entry) {
        if (strncmp(*entry, name, length) == 0 && (*entry)[length] == '=') {
            return *entry + length + 1;
        }
    }
    return NULL;
}

char *getenv(const char *name) {
    patina_note_boundary_symbol("getenv");
    return patina_getenv(name);
}

/* Guest-driven mutation is deterministic, so it is modeled rather than refused:
 * these update the runtime's guest env map and republish environ, keeping the
 * getenv interposer and direct environ walkers in agreement. Host libc is never
 * reached, so the scrubbed ambient environment stays scrubbed. */
int setenv(const char *name, const char *value, int overwrite) {
    patina_note_boundary_symbol("setenv");
    return fail_int(patina_setenv(name, value, overwrite));
}

int unsetenv(const char *name) {
    patina_note_boundary_symbol("unsetenv");
    return fail_int(patina_unsetenv(name));
}

#ifndef __APPLE__
/* glibc/musl only; Darwin libc has no clearenv. Interposed for the same reason
 * as unsetenv: left alone it would empty the published array behind the map's
 * back, so getenv and environ would disagree for the rest of the run. */
int clearenv(void) {
    patina_note_boundary_symbol("clearenv");
    return fail_int(patina_clearenv());
}

#endif

/* putenv is the one env mutator that stays fail-closed. Its entry remains
 * ALIASED to caller-owned memory: POSIX lets a later write through the caller's
 * buffer change the environment, and forbids the implementation from copying or
 * freeing the string. Patina's environment is an owned deterministic map, so
 * honoring that aliasing would mean tracking guest memory the runtime does not
 * own — an unmodeled effect whose divergence would surface as a silently stale
 * value rather than an error. Refuse loudly and name the modeled path. */
int putenv(char *string) {
    (void)string;
    return patina_posix_deny("patina: putenv is not modeled because its entry stays aliased to caller-owned memory; use setenv (modeled and deterministic); failing closed\n");
}

#ifdef __linux__
/* `secure_getenv`, like the interposed `getenv`, reads only the deterministic
 * guest environment map. */
char *secure_getenv(const char *name) {
    patina_note_boundary_symbol("secure_getenv");
    return patina_getenv(name);
}
#endif
