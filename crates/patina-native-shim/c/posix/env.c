/*
 * Environment: the scrubbed host environment, the control-plane snapshot, and
 * glibc's getenv/setenv/unsetenv/putenv/clearenv over the process's `environ`.
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
        (void)patina_stdio_write(2, message, sizeof message - 1);
        patina_host_abort();
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

/* Point `environ` at `next`: the startup array the Rust layer built from the
 * run's `--env` map (patina_publish_environ), or one the mutators below grew
 * (NULL for clearenv), as a libc setenv repoints the global when it grows the
 * array. */
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

/*
 * The environment functions are glibc's (stdlib/getenv.c, stdlib/setenv.c,
 * stdlib/putenv.c; glibc 2.39), over whatever array `environ` names — the
 * startup array the runtime published, one the guest's own `setenv` grew, or
 * one the program assigned itself:
 *
 * - `getenv` answers a pointer into the first entry of the name, just past
 *   its `=` (the entry's own bytes, never a copy);
 * - `setenv` overwrites an existing entry in place with a fresh `name=value`
 *   string, or appends a new name at the end, growing the array it allocated
 *   last (or a copy of one it did not allocate);
 * - `unsetenv` removes every entry of the name from the array in place;
 * - `putenv` inserts the caller's own string, so a later write through it
 *   changes the environment, and a string without `=` removes the name;
 * - `clearenv` frees the array `setenv` allocated and leaves `environ` NULL.
 *
 * Replaced entry strings are never freed (a guest may still hold a `getenv`
 * answer into one), as glibc keeps them. The mutators serialize on one lock,
 * glibc's `envlock`, a scheduler mutex (none after `main` returns:
 * patina_internal_lock); `getenv` takes none, as glibc's does not. The environment is process memory: nothing here is recorded, and replay
 * reproduces it by re-executing the guest. The runtime gates both sides: a
 * lookup before the startup constructor finishes answers NULL rather than read
 * the ambient host environment (patina_env_read_gate), and a mutation needs an
 * installed runtime (patina_env_write_gate).
 */
static pthread_mutex_t patina_env_lock = PTHREAD_MUTEX_INITIALIZER;
/* The array the mutators allocated last (glibc's `last_environ`). */
static char **patina_env_allocated = NULL;

static char **patina_env_array(void) {
#ifdef __APPLE__
    return *_NSGetEnviron();
#else
    return environ;
#endif
}

static int patina_env_name_invalid(const char *name) {
    return name == NULL || *name == '\0' || strchr(name, '=') != NULL;
}

/* The slot of the first entry of the `length`-byte name, or the array's
 * terminating slot (NULL when the array is), counting the entries before it. */
static char **patina_env_find(char **array, const char *name, size_t length, size_t *before) {
    size_t count = 0;
    char **entry = array;
    if (entry != NULL) {
        for (; *entry != NULL; ++entry, ++count) {
            if (strncmp(*entry, name, length) == 0 && (*entry)[length] == '=') break;
        }
    }
    *before = count;
    return entry;
}

char *getenv(const char *name) {
    patina_note_boundary_symbol("getenv");
    if (!patina_env_read_gate()) return NULL;
    char **array = patina_env_array();
    if (array == NULL || name[0] == '\0') return NULL;
    size_t length = strlen(name);
    size_t before;
    char **entry = patina_env_find(array, name, length, &before);
    return *entry == NULL ? NULL : *entry + length + 1;
}

/* glibc's `__add_to_environ`: `combined` is a caller's `name=value` string to
 * insert itself (putenv), otherwise `name=value` is built from `value`. */
static int patina_env_add(const char *name, const char *value, char *combined, int replace) {
    size_t length = strlen(name);
    int held = patina_internal_lock(&patina_env_lock);
    char **array = patina_env_array();
    size_t size;
    char **entry = patina_env_find(array, name, length, &size);
    int result = 0;
    if (entry == NULL || *entry == NULL) {
        char **grown = realloc(patina_env_allocated, (size + 2) * sizeof *grown);
        if (grown == NULL) {
            errno = ENOMEM;
            result = -1;
            goto out;
        }
        if (array != patina_env_allocated) memcpy(grown, array, size * sizeof *grown);
        grown[size] = NULL;
        grown[size + 1] = NULL;
        entry = grown + size;
        patina_env_allocated = grown;
        patina_environ_install(grown);
    }
    if (*entry == NULL || replace) {
        char *string = combined;
        if (string == NULL) {
            size_t bytes = strlen(value) + 1;
            string = malloc(length + 1 + bytes);
            if (string == NULL) {
                errno = ENOMEM;
                result = -1;
                goto out;
            }
            memcpy(string, name, length);
            string[length] = '=';
            memcpy(string + length + 1, value, bytes);
        }
        *entry = string;
    }
out:
    patina_internal_unlock(&patina_env_lock, held);
    return result;
}

/* glibc's `unsetenv` body, for a validated name. */
static void patina_env_remove(const char *name, size_t length) {
    int held = patina_internal_lock(&patina_env_lock);
    char **entry = patina_env_array();
    if (entry != NULL) {
        while (*entry != NULL) {
            if (strncmp(*entry, name, length) == 0 && (*entry)[length] == '=') {
                char **shift = entry;
                do shift[0] = shift[1];
                while (*shift++ != NULL);
            } else {
                ++entry;
            }
        }
    }
    patina_internal_unlock(&patina_env_lock, held);
}

int setenv(const char *name, const char *value, int overwrite) {
    patina_note_boundary_symbol("setenv");
    if (patina_env_name_invalid(name)) {
        errno = EINVAL;
        return -1;
    }
    if (patina_env_write_gate() != 0) return fail_int(-1);
    return patina_env_add(name, value, NULL, overwrite);
}

int unsetenv(const char *name) {
    patina_note_boundary_symbol("unsetenv");
    if (patina_env_name_invalid(name)) {
        errno = EINVAL;
        return -1;
    }
    if (patina_env_write_gate() != 0) return fail_int(-1);
    patina_env_remove(name, strlen(name));
    return 0;
}

#ifndef __APPLE__
/* glibc/musl only; Darwin libc has no clearenv. */
int clearenv(void) {
    patina_note_boundary_symbol("clearenv");
    if (patina_env_write_gate() != 0) return fail_int(-1);
    int held = patina_internal_lock(&patina_env_lock);
    char **array = patina_env_array();
    if (array != NULL && array == patina_env_allocated) {
        free(array);
        patina_env_allocated = NULL;
    }
    patina_environ_install(NULL);
    patina_internal_unlock(&patina_env_lock, held);
    return 0;
}

#endif

/* The environment keeps `string` itself, so the caller's later writes through
 * it are the environment's (POSIX forbids copying or freeing it). */
int putenv(char *string) {
    patina_note_boundary_symbol("putenv");
    if (patina_env_write_gate() != 0) return fail_int(-1);
    const char *end = strchr(string, '=');
    if (end == NULL) {
        patina_env_remove(string, strlen(string));
        return 0;
    }
    size_t length = (size_t)(end - string);
    char *name = malloc(length + 1);
    if (name == NULL) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(name, string, length);
    name[length] = '\0';
    int result = patina_env_add(name, NULL, string, 1);
    free(name);
    return result;
}

#ifdef __linux__
/* The kernel sets no `AT_SECURE` for the virtual process (its real and
 * effective ids agree), so `secure_getenv` answers as `getenv` does. */
char *secure_getenv(const char *name) {
    patina_note_boundary_symbol("secure_getenv");
    if (!patina_env_read_gate()) return NULL;
    char **array = patina_env_array();
    if (array == NULL || name[0] == '\0') return NULL;
    size_t length = strlen(name);
    size_t before;
    char **entry = patina_env_find(array, name, length, &before);
    return *entry == NULL ? NULL : *entry + length + 1;
}
#endif
