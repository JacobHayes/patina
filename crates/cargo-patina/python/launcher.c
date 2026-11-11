/* The Patina Python launcher: CPython, linked statically below the shim,
 * importing every module from the blobs `patina build --python` froze
 * (python/freeze.py) and running the application's main module, as
 * `python -m` runs one.
 *
 * The interpreter is isolated: no environment variable, user site or search
 * path reaches it, so the frozen modules are the whole of what it imports,
 * the application's shadowing the standard library's. UTF-8 mode fixes the
 * text encoding, whatever the locale. The application's sources go into
 * `linecache`, so a traceback shows their lines. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* Provided by the patina-dst-native-shim staticlib. */
extern void patina_note_metered_runtime(void);
/* The SDK's binding (python/sdk_module.c). */
PyMODINIT_FUNC PyInit__patina(void);

static const char MAGIC[16] = "PATINAPYFROZEN2";

struct reader {
    const unsigned char *at;
    const unsigned char *end;
};

static void corrupt(void) {
    fprintf(stderr, "patina: the frozen Python modules are corrupt; rebuild with patina build --python\n");
    exit(70);
}

static uint32_t take_u32(struct reader *r) {
    if (r->end - r->at < 4) corrupt();
    const unsigned char *p = r->at;
    r->at += 4;
    return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24;
}

static const unsigned char *take(struct reader *r, uint32_t length) {
    if ((size_t)(r->end - r->at) < length) corrupt();
    const unsigned char *p = r->at;
    r->at += length;
    return p;
}

static char *take_string(struct reader *r) {
    uint32_t length = take_u32(r);
    const unsigned char *bytes = take(r, length);
    char *text = malloc(length + 1);
    if (text == NULL) corrupt();
    memcpy(text, bytes, length);
    text[length] = 0;
    return text;
}

struct blob {
    char *main;
    uint32_t modules;
    struct reader module_entries;
    uint32_t sources;
    struct reader source_entries;
};

static struct blob open_blob(const unsigned char *bytes, size_t length) {
    struct reader r = {bytes, bytes + length};
    if (memcmp(take(&r, sizeof MAGIC), MAGIC, sizeof MAGIC) != 0) corrupt();
    struct blob blob;
    blob.main = take_string(&r);
    blob.modules = take_u32(&r);
    blob.module_entries = r;
    for (uint32_t i = 0; i < blob.modules; i++) {
        take(&r, take_u32(&r));
        take(&r, 1);
        take(&r, take_u32(&r));
    }
    blob.sources = take_u32(&r);
    blob.source_entries = r;
    return blob;
}

static void fill_modules(struct blob *blob, struct _frozen *table) {
    struct reader r = blob->module_entries;
    for (uint32_t i = 0; i < blob->modules; i++) {
        table[i].name = take_string(&r);
        table[i].is_package = *take(&r, 1);
        uint32_t size = take_u32(&r);
        table[i].code = take(&r, size);
        table[i].size = (int)size;
    }
}

/* linecache.cache[filename] = (size, None, lines, filename): a None mtime
 * is an entry `checkcache` keeps. */
static int cache_sources(struct blob *blob) {
    PyObject *linecache = PyImport_ImportModule("linecache");
    if (linecache == NULL) return -1;
    PyObject *cache = PyObject_GetAttrString(linecache, "cache");
    Py_DECREF(linecache);
    if (cache == NULL) return -1;
    struct reader r = blob->source_entries;
    int result = 0;
    for (uint32_t i = 0; i < blob->sources && result == 0; i++) {
        uint32_t name_length = take_u32(&r);
        const char *name = (const char *)take(&r, name_length);
        uint32_t source_length = take_u32(&r);
        const char *source = (const char *)take(&r, source_length);
        PyObject *filename = PyUnicode_DecodeFSDefaultAndSize(name, name_length);
        PyObject *text = PyUnicode_DecodeUTF8(source, source_length, "replace");
        PyObject *lines = text ? PyUnicode_Splitlines(text, 1) : NULL;
        PyObject *entry = (filename && lines)
            ? Py_BuildValue("(nOOO)", (Py_ssize_t)source_length, Py_None, lines, filename)
            : NULL;
        if (entry == NULL || PyObject_SetItem(cache, filename, entry) < 0) result = -1;
        Py_XDECREF(entry);
        Py_XDECREF(lines);
        Py_XDECREF(text);
        Py_XDECREF(filename);
    }
    Py_DECREF(cache);
    return result;
}

/* Run the main module as `python -m` does, `sys.argv` left as the program
 * was given it: a directory application's `__main__` as `python DIR` runs
 * it, a script's module under its own name. */
static int run_main(const char *name) {
    PyObject *runpy = PyImport_ImportModule("runpy");
    if (runpy == NULL) return -1;
    PyObject *result = PyObject_CallMethod(runpy, "_run_module_as_main", "si", name, 0);
    Py_DECREF(runpy);
    if (result == NULL) return -1;
    Py_DECREF(result);
    return 0;
}

int patina_python_main(int argc, char **argv, const unsigned char *app, size_t app_length,
                       const unsigned char *stdlib, size_t stdlib_length) {
    /* Every thread runs metered interpreter code (python/meter.c). */
    patina_note_metered_runtime();
    struct blob application = open_blob(app, app_length);
    struct blob library = open_blob(stdlib, stdlib_length);
    /* The application's modules first: the first entry of a name wins. */
    struct _frozen *table = calloc((size_t)application.modules + library.modules + 1, sizeof *table);
    if (table == NULL) corrupt();
    fill_modules(&application, table);
    fill_modules(&library, table + application.modules);
    PyImport_FrozenModules = table;
    if (PyImport_AppendInittab("_patina", PyInit__patina) < 0) {
        fprintf(stderr, "patina: the SDK module _patina could not be registered\n");
        exit(70);
    }

    PyPreConfig preconfig;
    PyPreConfig_InitIsolatedConfig(&preconfig);
    preconfig.utf8_mode = 1;
    PyStatus status = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(status)) Py_ExitStatusException(status);

    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.pathconfig_warnings = 0;
    config.module_search_paths_set = 1;
    status = PyConfig_SetBytesArgv(&config, argc, argv);
    if (PyStatus_Exception(status)) goto fail;
    status = Py_InitializeFromConfig(&config);
    if (PyStatus_Exception(status)) goto fail;
    PyConfig_Clear(&config);
    int code = 0, interrupted = 0;
    if (cache_sources(&application) < 0 || run_main(application.main) < 0) {
        /* A SystemExit exits here, with its code, as the interpreter's own
         * main does. */
        interrupted = PyErr_ExceptionMatches(PyExc_KeyboardInterrupt);
        PyErr_Print();
        code = 1;
    }
    /* The exit status as Py_RunMain decides it: a failed finalization is
     * 120, and an unhandled KeyboardInterrupt ends the process by SIGINT
     * (130 should the signal not end it). */
    if (Py_FinalizeEx() < 0) code = 120;
    if (interrupted) {
        signal(SIGINT, SIG_DFL);
        kill(getpid(), SIGINT);
        code = 130;
    }
    return code;
fail:
    PyConfig_Clear(&config);
    if (PyStatus_IsExit(status)) return status.exitcode;
    Py_ExitStatusException(status);
}
