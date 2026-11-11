/* `_patina`: the Python SDK's binding to the native shim, a builtin module
 * every Python guest's interpreter has (the launcher registers it before the
 * interpreter starts). The `patina` package (python/sdk/patina) is the API;
 * this is its thin lowering to the shim's SDK entries
 * (crates/patina-native-shim/include/patina_native.h), so a site or verdict
 * means what it means in the Rust and Go SDKs. Labels and sites are str,
 * passed as UTF-8. Outside a Patina run the shim's entries are themselves
 * inert. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>

int32_t patina_is_simulated(void);
int32_t patina_buggify(const uint8_t *label, size_t label_len, const uint8_t *site,
                       size_t site_len, int32_t prob_permille);
int32_t patina_buggify_delay(const uint8_t *label, size_t label_len, const uint8_t *site,
                             size_t site_len);
int64_t patina_buggify_knob(const uint8_t *label, size_t label_len, const uint8_t *site,
                            size_t site_len, int64_t default_value, int64_t lo, int64_t hi);
int32_t patina_declare_site(uint8_t kind, const uint8_t *label, size_t label_len,
                            const uint8_t *site, size_t site_len);
int32_t patina_always(int32_t condition, const uint8_t *label, size_t label_len,
                      const uint8_t *site, size_t site_len);
int32_t patina_sometimes(int32_t condition, const uint8_t *label, size_t label_len,
                         const uint8_t *site, size_t site_len);
int32_t patina_reachable(const uint8_t *label, size_t label_len, const uint8_t *site,
                         size_t site_len);
uint64_t patina_rng(void);
intptr_t patina_param(const uint8_t *key, size_t key_len, uint8_t *out, size_t out_cap);
int32_t patina_lifecycle_setup_complete(void);
int32_t patina_lifecycle_event(const uint8_t *label, size_t label_len);
int32_t patina_verdict(uint32_t kind, const uint8_t *label, size_t label_len,
                       const uint8_t *detail, size_t detail_len);

#define U8(p) ((const uint8_t *)(p))

/* A shim answer below zero is a refusal: an oracle the shim did not take
 * checks nothing, so it is an error, never a quiet no-op. */
static PyObject *checked(long answer, const char *what) {
    if (answer < 0) {
        return PyErr_Format(PyExc_RuntimeError, "patina: the shim refused %s", what);
    }
    return PyLong_FromLong(answer);
}

static PyObject *is_simulated(PyObject *self, PyObject *args) {
    (void)self, (void)args;
    return PyBool_FromLong(patina_is_simulated() != 0);
}

static PyObject *declare_site(PyObject *self, PyObject *args) {
    (void)self;
    unsigned char kind;
    const char *label, *site;
    Py_ssize_t label_len, site_len;
    if (!PyArg_ParseTuple(args, "bs#s#", &kind, &label, &label_len, &site, &site_len)) return NULL;
    return checked(patina_declare_site(kind, U8(label), label_len, U8(site), site_len),
                   "a site declaration");
}

/* always, sometimes: (condition, label, site). */
static PyObject *check(PyObject *args, int32_t (*entry)(int32_t, const uint8_t *, size_t,
                                                        const uint8_t *, size_t),
                       const char *what) {
    int condition;
    const char *label, *site;
    Py_ssize_t label_len, site_len;
    if (!PyArg_ParseTuple(args, "ps#s#", &condition, &label, &label_len, &site, &site_len))
        return NULL;
    return checked(entry(condition, U8(label), label_len, U8(site), site_len), what);
}

static PyObject *always(PyObject *self, PyObject *args) {
    (void)self;
    return check(args, patina_always, "an Always check");
}

static PyObject *sometimes(PyObject *self, PyObject *args) {
    (void)self;
    return check(args, patina_sometimes, "a Sometimes check");
}

static PyObject *reachable(PyObject *self, PyObject *args) {
    (void)self;
    const char *label, *site;
    Py_ssize_t label_len, site_len;
    if (!PyArg_ParseTuple(args, "s#s#", &label, &label_len, &site, &site_len)) return NULL;
    return checked(patina_reachable(U8(label), label_len, U8(site), site_len),
                   "a Reachable mark");
}

static PyObject *buggify(PyObject *self, PyObject *args) {
    (void)self;
    const char *label, *site;
    Py_ssize_t label_len, site_len;
    int permille;
    if (!PyArg_ParseTuple(args, "s#s#i", &label, &label_len, &site, &site_len, &permille))
        return NULL;
    return checked(patina_buggify(U8(label), label_len, U8(site), site_len, permille),
                   "a Buggify evaluation");
}

static PyObject *buggify_delay(PyObject *self, PyObject *args) {
    (void)self;
    const char *label, *site;
    Py_ssize_t label_len, site_len;
    if (!PyArg_ParseTuple(args, "s#s#", &label, &label_len, &site, &site_len)) return NULL;
    return checked(patina_buggify_delay(U8(label), label_len, U8(site), site_len),
                   "a BuggifyDelay evaluation");
}

static PyObject *buggify_knob(PyObject *self, PyObject *args) {
    (void)self;
    const char *label, *site;
    Py_ssize_t label_len, site_len;
    long long value, low, high;
    if (!PyArg_ParseTuple(args, "s#s#LLL", &label, &label_len, &site, &site_len, &value, &low,
                          &high))
        return NULL;
    return PyLong_FromLongLong(
        patina_buggify_knob(U8(label), label_len, U8(site), site_len, value, low, high));
}

static PyObject *rng(PyObject *self, PyObject *args) {
    (void)self, (void)args;
    return PyLong_FromUnsignedLongLong(patina_rng());
}

/* The run parameter's value as bytes, or None when the run has none. */
static PyObject *param(PyObject *self, PyObject *args) {
    (void)self;
    const char *key;
    Py_ssize_t key_len;
    if (!PyArg_ParseTuple(args, "s#", &key, &key_len)) return NULL;
    uint8_t probe[256];
    intptr_t length = patina_param(U8(key), key_len, probe, sizeof probe);
    if (length < 0) Py_RETURN_NONE;
    if ((size_t)length <= sizeof probe) return PyBytes_FromStringAndSize((char *)probe, length);
    PyObject *value = PyBytes_FromStringAndSize(NULL, length);
    if (value == NULL) return NULL;
    if (patina_param(U8(key), key_len, (uint8_t *)PyBytes_AS_STRING(value), length) != length) {
        Py_DECREF(value);
        return PyErr_Format(PyExc_RuntimeError, "patina: run parameter %s changed size", key);
    }
    return value;
}

static PyObject *setup_complete(PyObject *self, PyObject *args) {
    (void)self, (void)args;
    return checked(patina_lifecycle_setup_complete(), "the setup-complete marker");
}

static PyObject *lifecycle_event(PyObject *self, PyObject *args) {
    (void)self;
    const char *label;
    Py_ssize_t label_len;
    if (!PyArg_ParseTuple(args, "s#", &label, &label_len)) return NULL;
    return checked(patina_lifecycle_event(U8(label), label_len), "a lifecycle event");
}

static PyObject *verdict(PyObject *self, PyObject *args) {
    (void)self;
    unsigned int kind;
    const char *label, *detail;
    Py_ssize_t label_len, detail_len;
    if (!PyArg_ParseTuple(args, "Is#s#", &kind, &label, &label_len, &detail, &detail_len))
        return NULL;
    return checked(patina_verdict(kind, U8(label), label_len, U8(detail), detail_len),
                   "a verdict");
}

static PyMethodDef methods[] = {
    {"is_simulated", is_simulated, METH_NOARGS, NULL},
    {"declare_site", declare_site, METH_VARARGS, NULL},
    {"always", always, METH_VARARGS, NULL},
    {"sometimes", sometimes, METH_VARARGS, NULL},
    {"reachable", reachable, METH_VARARGS, NULL},
    {"buggify", buggify, METH_VARARGS, NULL},
    {"buggify_delay", buggify_delay, METH_VARARGS, NULL},
    {"buggify_knob", buggify_knob, METH_VARARGS, NULL},
    {"rng", rng, METH_NOARGS, NULL},
    {"param", param, METH_VARARGS, NULL},
    {"setup_complete", setup_complete, METH_NOARGS, NULL},
    {"lifecycle_event", lifecycle_event, METH_VARARGS, NULL},
    {"verdict", verdict, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_patina", "The Patina SDK's binding to the native shim.", -1,
    methods, NULL, NULL, NULL, NULL,
};

PyMODINIT_FUNC PyInit__patina(void) { return PyModule_Create(&module); }
