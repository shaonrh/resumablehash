/*********************************************************************
* Filename:   _hash_ext.c
* License:    Unlicense (public domain)
* Details:    Python C extension module exporting resumable hash types
*             for SHA-256, SHA-384, and SHA-512. Uses DEFINE_HASH_TYPE
*             macro to generate Python type boilerplate for each algorithm.
*********************************************************************/

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "sha256.h"
#include "sha512.h"

/*
 * Serialized state header format (8 bytes):
 *   [0-1] Magic: 0x52 0x48 ("RH")
 *   [2]   Algorithm ID (see RH_ALG_* constants)
 *   [3]   Format version (currently 0x01)
 *   [4-7] Reserved (zero)
 *
 * Total serialized size = 8 + sizeof(CTX_T)
 */
#define RH_MAGIC_0      0x52
#define RH_MAGIC_1      0x48
#define RH_VERSION      0x01
#define RH_HEADER_SIZE  8

#define RH_ALG_SHA256   0x01
#define RH_ALG_SHA384   0x02
#define RH_ALG_SHA512   0x03

/* State serialization uses raw struct memcpy and is only portable across
 * machines with the same architecture, compiler, and struct layout.
 * Currently only x86_64 Linux is supported. If cross-platform state
 * portability is needed, implement field-by-field serialization with
 * explicit byte order (bump RH_VERSION to 0x02). */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#warning "resumablehash state serialization assumes little-endian byte order"
#endif

/* Maximum valid algorithm ID -- update when adding new algorithms. */
#define RH_ALG_MAX      RH_ALG_SHA512

/* File-scope algorithm name table, indexed by algorithm ID. */
static const char *rh_alg_names[] = {
    "unknown",  /* 0x00 -- invalid/placeholder */
    "sha256",   /* 0x01 -- RH_ALG_SHA256 */
    "sha384",   /* 0x02 -- RH_ALG_SHA384 */
    "sha512",   /* 0x03 -- RH_ALG_SHA512 */
};

/*
 * Validate and build the serialized state header.
 * Returns a new PyBytes object with header + raw context, or NULL on error.
 */
static PyObject *
rh_getstate_impl(void *ctx, size_t ctx_size, unsigned char alg_id)
{
    PyObject *result = PyBytes_FromStringAndSize(NULL,
        RH_HEADER_SIZE + (Py_ssize_t)ctx_size);
    if (result == NULL) return NULL;
    char *buf = PyBytes_AS_STRING(result);
    buf[0] = RH_MAGIC_0;
    buf[1] = RH_MAGIC_1;
    buf[2] = (char)alg_id;
    buf[3] = RH_VERSION;
    memset(buf + 4, 0, 4);  /* reserved */
    memcpy(buf + RH_HEADER_SIZE, ctx, ctx_size);
    return result;
}

/*
 * Validate a serialized state buffer and copy it into the context.
 * Returns 0 on success, -1 on error (with Python exception set).
 */
static int
rh_setstate_impl(void *ctx, size_t ctx_size, unsigned char alg_id,
                 const char *name_str, PyObject *state)
{
    char *buf;
    Py_ssize_t len;
    if (PyBytes_AsStringAndSize(state, &buf, &len) < 0)
        return -1;
    Py_ssize_t expected = RH_HEADER_SIZE + (Py_ssize_t)ctx_size;
    if (len != expected) {
        PyErr_Format(PyExc_ValueError,
            "Invalid state length: expected %zd, got %zd",
            expected, len);
        return -1;
    }
    if ((unsigned char)buf[0] != RH_MAGIC_0 ||
        (unsigned char)buf[1] != RH_MAGIC_1) {
        PyErr_SetString(PyExc_ValueError,
            "Invalid state: missing resumablehash header");
        return -1;
    }
    if ((unsigned char)buf[3] != RH_VERSION) {
        PyErr_Format(PyExc_ValueError,
            "Unsupported state format version %d (expected %d)",
            (unsigned char)buf[3], RH_VERSION);
        return -1;
    }
    if ((unsigned char)buf[2] != alg_id) {
        unsigned char got_id = (unsigned char)buf[2];
        const char *got = (got_id >= 1 && got_id <= RH_ALG_MAX)
                          ? rh_alg_names[got_id] : "unknown";
        PyErr_Format(PyExc_ValueError,
            "State was serialized from %s, cannot restore into %s",
            got, name_str);
        return -1;
    }
    memcpy(ctx, buf + RH_HEADER_SIZE, ctx_size);
    return 0;
}

/*
 * DEFINE_HASH_TYPE generates a complete Python type for one hash algorithm.
 *
 * Parameters:
 *   PYNAME     - C identifier prefix (sha256, sha384, sha512)
 *   CTX_T      - context struct type (SHA256_CTX or SHA512_CTX)
 *   DSIZE      - digest size in bytes (32, 48, 64)
 *   BSIZE      - block size in bytes (64, 128)
 *   INIT_FN    - C init function
 *   UPDATE_FN  - C update function
 *   FINAL_FN   - C final function
 *   NAME_STR   - Python-visible name string
 *   ALG_ID     - algorithm identifier (RH_ALG_SHA256, etc.)
 *
 * To add a new algorithm:
 *   1. Define a new RH_ALG_* constant above
 *   2. Update RH_ALG_MAX
 *   3. Add the name to rh_alg_names[]
 *   4. Add a DEFINE_HASH_TYPE invocation at the bottom of this file
 *   5. Register the type in PyInit__hash_ext()
 *   6. Export from src/resumablehash/__init__.py
 */
#define DEFINE_HASH_TYPE(PYNAME, CTX_T, DSIZE, BSIZE, INIT_FN, UPDATE_FN, FINAL_FN, NAME_STR, ALG_ID) \
                                                                              \
typedef struct {                                                              \
    PyObject_HEAD                                                             \
    CTX_T ctx;                                                                \
} py_##PYNAME##Object;                                                        \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwds)      \
{                                                                             \
    py_##PYNAME##Object *self;                                                \
    self = (py_##PYNAME##Object *)type->tp_alloc(type, 0);                    \
    if (self != NULL) {                                                       \
        INIT_FN(&self->ctx);                                                  \
        Py_buffer buf;                                                        \
        buf.buf = NULL;                                                       \
        if (!PyArg_ParseTuple(args, "|y*", &buf)) {                           \
            Py_DECREF(self);                                                  \
            return NULL;                                                      \
        }                                                                     \
        if (buf.buf != NULL) {                                                \
            UPDATE_FN(&self->ctx, (const unsigned char *)buf.buf,             \
                      (size_t)buf.len);                                       \
            PyBuffer_Release(&buf);                                           \
        }                                                                     \
    }                                                                         \
    return (PyObject *)self;                                                   \
}                                                                             \
                                                                              \
static void                                                                   \
py_##PYNAME##_dealloc(py_##PYNAME##Object *self)                              \
{                                                                             \
    Py_TYPE(self)->tp_free((PyObject *)self);                                  \
}                                                                             \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_update(py_##PYNAME##Object *self, PyObject *args)               \
{                                                                             \
    Py_buffer buf;                                                            \
    if (!PyArg_ParseTuple(args, "y*", &buf))                                  \
        return NULL;                                                          \
    UPDATE_FN(&self->ctx, (const unsigned char *)buf.buf, (size_t)buf.len);   \
    PyBuffer_Release(&buf);                                                   \
    Py_RETURN_NONE;                                                           \
}                                                                             \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_digest(py_##PYNAME##Object *self, PyObject *Py_UNUSED(ignored)) \
{                                                                             \
    unsigned char hash[DSIZE];                                                \
    CTX_T temp = self->ctx;                                                   \
    FINAL_FN(&temp, hash);                                                    \
    return Py_BuildValue("y#", hash, DSIZE);                                  \
}                                                                             \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_hexdigest(py_##PYNAME##Object *self, PyObject *Py_UNUSED(ignored)) \
{                                                                             \
    unsigned char hash[DSIZE];                                                \
    char hex_output[DSIZE * 2 + 1];                                           \
    CTX_T temp = self->ctx;                                                   \
    FINAL_FN(&temp, hash);                                                    \
    for (int i = 0; i < DSIZE; i++)                                           \
        snprintf(hex_output + (i * 2), 3, "%02x", hash[i]);                       \
    hex_output[DSIZE * 2] = '\0';                                             \
    return Py_BuildValue("s", hex_output);                                     \
}                                                                             \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_getstate(py_##PYNAME##Object *self, PyObject *Py_UNUSED(ignored)) \
{                                                                             \
    return rh_getstate_impl(&self->ctx, sizeof(CTX_T), ALG_ID);               \
}                                                                             \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_setstate(py_##PYNAME##Object *self, PyObject *state)            \
{                                                                             \
    if (rh_setstate_impl(&self->ctx, sizeof(CTX_T), ALG_ID, NAME_STR,        \
                         state) < 0)                                          \
        return NULL;                                                          \
    /* Validate datalen to prevent heap corruption from crafted state. */     \
    /* datalen is the index into ctx.data[], must be < block size. */         \
    if (self->ctx.datalen >= BSIZE) {                                         \
        PyErr_Format(PyExc_ValueError,                                        \
            "Invalid state: datalen=%zu exceeds block size %d",               \
            (size_t)self->ctx.datalen, BSIZE);                                \
        INIT_FN(&self->ctx);                                                  \
        return NULL;                                                          \
    }                                                                         \
    Py_RETURN_NONE;                                                           \
}                                                                             \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_copy(py_##PYNAME##Object *self, PyObject *Py_UNUSED(ignored))   \
{                                                                             \
    py_##PYNAME##Object *new_obj = PyObject_New(py_##PYNAME##Object, Py_TYPE(self)); \
    if (new_obj == NULL)                                                      \
        return NULL;                                                          \
    memcpy(&new_obj->ctx, &self->ctx, sizeof(CTX_T));                         \
    return (PyObject *)new_obj;                                                \
}                                                                             \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_get_digest_size(py_##PYNAME##Object *self, void *closure)       \
{                                                                             \
    return PyLong_FromLong(DSIZE);                                            \
}                                                                             \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_get_block_size(py_##PYNAME##Object *self, void *closure)        \
{                                                                             \
    return PyLong_FromLong(BSIZE);                                            \
}                                                                             \
                                                                              \
static PyObject *                                                             \
py_##PYNAME##_get_name(py_##PYNAME##Object *self, void *closure)              \
{                                                                             \
    return PyUnicode_FromString(NAME_STR);                                     \
}                                                                             \
                                                                              \
static PyGetSetDef py_##PYNAME##_getsetters[] = {                             \
    {"digest_size", (getter)py_##PYNAME##_get_digest_size, NULL,              \
        "digest size", NULL},                                                 \
    {"block_size", (getter)py_##PYNAME##_get_block_size, NULL,                \
        "block size", NULL},                                                  \
    {"name", (getter)py_##PYNAME##_get_name, NULL,                            \
        "hash name", NULL},                                                   \
    {NULL}                                                                    \
};                                                                            \
                                                                              \
static PyMethodDef py_##PYNAME##_methods[] = {                                \
    {"update", (PyCFunction)py_##PYNAME##_update, METH_VARARGS,               \
        "Update the hash with data"},                                         \
    {"digest", (PyCFunction)py_##PYNAME##_digest, METH_NOARGS,                \
        "Return the binary digest"},                                          \
    {"hexdigest", (PyCFunction)py_##PYNAME##_hexdigest, METH_NOARGS,          \
        "Return the hexadecimal digest"},                                     \
    {"__getstate__", (PyCFunction)py_##PYNAME##_getstate, METH_NOARGS,        \
        "Return internal state for pickling"},                                \
    {"__setstate__", (PyCFunction)py_##PYNAME##_setstate, METH_O,             \
        "Restore internal state from pickled data"},                          \
    {"copy", (PyCFunction)py_##PYNAME##_copy, METH_NOARGS,                    \
        "Return a copy of the hash object"},                                  \
    {NULL, NULL, 0, NULL}                                                     \
};                                                                            \
                                                                              \
static PyTypeObject py_##PYNAME##Type = {                                     \
    PyVarObject_HEAD_INIT(NULL, 0)                                            \
    .tp_name = "resumablehash." NAME_STR,                                      \
    .tp_doc = "Resumable " NAME_STR " hash objects",                          \
    .tp_basicsize = sizeof(py_##PYNAME##Object),                              \
    .tp_itemsize = 0,                                                         \
    .tp_flags = Py_TPFLAGS_DEFAULT,                                           \
    .tp_new = py_##PYNAME##_tp_new,                                           \
    .tp_dealloc = (destructor)py_##PYNAME##_dealloc,                          \
    .tp_methods = py_##PYNAME##_methods,                                      \
    .tp_getset = py_##PYNAME##_getsetters,                                    \
};

/* --- Instantiate all three types --- */

DEFINE_HASH_TYPE(sha256, SHA256_CTX, 32,  64,  sha256_init, sha256_update, sha256_final, "sha256", RH_ALG_SHA256)
DEFINE_HASH_TYPE(sha384, SHA512_CTX, 48,  128, sha384_init, sha512_update, sha384_final, "sha384", RH_ALG_SHA384)
DEFINE_HASH_TYPE(sha512, SHA512_CTX, 64,  128, sha512_init, sha512_update, sha512_final, "sha512", RH_ALG_SHA512)

/* --- Module definition --- */

static PyModuleDef hashmodule = {
    PyModuleDef_HEAD_INIT,
    "_hash_ext",
    "Resumable SHA-2 hash implementations (SHA-256, SHA-384, SHA-512)",
    -1,
    NULL, NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC
PyInit__hash_ext(void)
{
    PyObject *m;

    if (PyType_Ready(&py_sha256Type) < 0) return NULL;
    if (PyType_Ready(&py_sha384Type) < 0) return NULL;
    if (PyType_Ready(&py_sha512Type) < 0) return NULL;

    m = PyModule_Create(&hashmodule);
    if (m == NULL) return NULL;

    Py_INCREF(&py_sha256Type);
    if (PyModule_AddObject(m, "sha256", (PyObject *)&py_sha256Type) < 0) {
        Py_DECREF(&py_sha256Type);
        Py_DECREF(m);
        return NULL;
    }

    Py_INCREF(&py_sha384Type);
    if (PyModule_AddObject(m, "sha384", (PyObject *)&py_sha384Type) < 0) {
        Py_DECREF(&py_sha384Type);
        Py_DECREF(m);
        return NULL;
    }

    Py_INCREF(&py_sha512Type);
    if (PyModule_AddObject(m, "sha512", (PyObject *)&py_sha512Type) < 0) {
        Py_DECREF(&py_sha512Type);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}
