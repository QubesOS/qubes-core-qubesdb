/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2013  Marek Marczykowski <marmarek@invisiblethingslab.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <Python.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <qubesdb-client.h>

/** @file
 * Python interface to the Qubes DB (qdb).
 */

/* Needed for Python versions earlier than 2.3. */
#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC DL_EXPORT(void)
#endif

#define PKG "qubesdb"
#define CLS "QubesDB"

static PyObject *qdb_error;
static PyObject *qdb_disconnected_error;

/** Python wrapper round an Qubes DB handle.
 */
typedef struct QdbHandle {
    PyObject_HEAD;
    qdb_handle_t qdb;
} QdbHandle;

static void qdb_set_error(int value)
{
    errno = value;
    PyErr_SetFromErrno(qdb_error);
}

static inline qdb_handle_t qdbhandle(QdbHandle *self)
{
    qdb_handle_t qdb = self->qdb;
    if (!qdb)
        qdb_set_error(EINVAL);
    return qdb;
}

static PyObject *none(bool result);

static int parse_handle_path(QdbHandle *self, PyObject *args,
                                  qdb_handle_t *qdb,
                                  char **path);


#define qdbpy_read_doc "\n"                              \
	"Read data from a path.\n"                      \
	" path [string]:        path\n"	\
	"\n"                                            \
	"Returns: [string] data read.\n"                \
	"         None if key doesn't exist.\n"         \
	"Raises qubesdb.Error on error.\n"               \
	"\n"

static PyObject *qdbpy_read(QdbHandle *self, PyObject *args)
{
    qdb_handle_t qdb;
    char *path;

    char *value;
    unsigned int value_len;

    if (!parse_handle_path(self, args, &qdb, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    value = qdb_read(qdb, path, &value_len);
    Py_END_ALLOW_THREADS
    if (value) {
#if PY_VERSION_HEX >= 0x03000000
        PyObject *val = PyBytes_FromStringAndSize(value, value_len);
#else
        PyObject *val = PyString_FromStringAndSize(value, value_len);
#endif
        free(value);
        return val;
    }
    else {
        return none(errno == ENOENT);
    }
}


#define qdbpy_write_doc "\n"					\
	"Write data to a path.\n"				\
	" path   [string] : path to write to\n."	\
	" data   [string] : data to write.\n"			\
	"\n"							\
	"Returns None on success.\n"				\
	"Raises qubesdb.Error on error.\n"			\
	"\n"

static PyObject *qdbpy_write(QdbHandle *self, PyObject *args)
{
    static char *arg_spec = "ss#";
    qdb_handle_t qdb = qdbhandle(self);
    char *path;
    char *data;
    int data_len;
    bool result;

    if (!qdb)
        return NULL;
    if (!PyArg_ParseTuple(args, arg_spec, &path, &data, &data_len))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = qdb_write(qdb, path, data, data_len);
    Py_END_ALLOW_THREADS

    return none(result);
}


#define qdbpy_list_doc "\n"					\
	"List a directory.\n"					\
	" path [string]:        path prefix to list.\n"                \
	"\n"							\
	"Returns: [string array] list of full paths matching given prefix.\n"	\
	"         None if key doesn't exist.\n"			\
	"Raises qubesdb.Error on error.\n"			\
	"\n"

static PyObject *qdbpy_list(QdbHandle *self, PyObject *args)
{
    qdb_handle_t qdb;
    char *path;

    char **list;
    unsigned int list_len;

    if (!parse_handle_path(self, args, &qdb, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    list = qdb_list(qdb, path, &list_len);
    Py_END_ALLOW_THREADS

    if (list) {
        int i;
        PyObject *val = PyList_New(list_len);
        for (i = 0; i < list_len; i++) {
#if PY_VERSION_HEX >= 0x03000000
            PyList_SetItem(val, i, PyUnicode_FromString(list[i]));
#else
            PyList_SetItem(val, i, PyString_FromString(list[i]));
#endif
            free(list[i]);
        }
        free(list);
        return val;
    }
    else {
        return none(errno == ENOENT);
    }
}

#define qdbpy_multiread_doc "\n"					\
	"Read all entries matching given path.\n"					\
	" path [string]:        path prefix to read.\n"                \
	"\n"							\
	"Returns: [string dict] dict of entries. Keys are full paths matching given prefix.\n"	\
	"Raises qubesdb.Error on error.\n"			\
	"\n"

static PyObject *qdbpy_multiread(QdbHandle *self, PyObject *args)
{
    qdb_handle_t qdb;
    char *path;

    char **values;
    unsigned int list_len;
    unsigned int *values_len;

    if (!parse_handle_path(self, args, &qdb, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    values = qdb_multiread(qdb, path, &values_len, &list_len);
    Py_END_ALLOW_THREADS

    if (values) {
        int i;
        PyObject *val = PyDict_New();
        for (i = 0; i < list_len; i++) {
            PyDict_SetItemString(val,
                    values[2*i],
#if PY_VERSION_HEX >= 0x03000000
                    PyBytes_FromStringAndSize(values[2*i+1], values_len[i]));
#else
                    PyString_FromStringAndSize(values[2*i+1], values_len[i]));
#endif
            free(values[2*i]);
            free(values[2*i+1]);
        }
        free(values);
        free(values_len);
        return val;
    }
    else {
        return none(errno == ENOENT);
    }
}

#define qdbpy_rm_doc "\n"                                \
	"Remove a path.\n"                              \
	" path [string] : path to remove\n"             \
	"\n"                                            \
	"Returns None on success.\n"                    \
	"Raises qubesdb.Error on error.\n"               \
	"\n"

static PyObject *qdbpy_rm(QdbHandle *self, PyObject *args)
{
    qdb_handle_t qdb;
    char *path;

    bool result;

    if (!parse_handle_path(self, args, &qdb, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = qdb_rm(qdb, path);
    Py_END_ALLOW_THREADS

    return none(result || errno == ENOENT);
}

#define qdbpy_watch_doc "\n"						\
	"Watch a path, get notifications when it changes.\n"		\
	" path     [string] : xenstore path.\n"				\
	"\n"								\
	"Returns None on success.\n"					\
	"Raises qubesdb.Error on error.\n"				\
	"\n"

static PyObject *qdbpy_watch(QdbHandle *self, PyObject *args)
{
    qdb_handle_t qdb;
    char *path;
    int result;

    if (!parse_handle_path(self, args, &qdb, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = qdb_watch(qdb, path);
    Py_END_ALLOW_THREADS

    return none(result);
}


#define qdbpy_read_watch_doc "\n"				\
	"Read a watch notification.\n"				\
	"\n"							\
	"Returns: path.\n"			\
	"Raises qubesdb.Error on error.\n"			\
	"\n"

static PyObject *qdbpy_read_watch(QdbHandle *self, PyObject *args)
{
    qdb_handle_t qdb = qdbhandle(self);
    PyObject *val = NULL;
    char *watch_path;

    if (!qdb)
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    watch_path = qdb_read_watch(qdb);
    Py_END_ALLOW_THREADS
    if (!watch_path) {
        return none(0);
    }
    /* Create string object. */
#if PY_VERSION_HEX >= 0x03000000
    val = PyUnicode_FromString(watch_path);
#else
    val = PyString_FromString(watch_path);
#endif
    free(watch_path);
    return val;
}

#define qdbpy_unwatch_doc "\n"				\
	"Stop watching a path.\n"			\
	" path  [string] : path.\n"		\
	"\n"						\
	"Returns None on success.\n"			\
	"Raises qubesdb.Error on error.\n"		\
	"\n"

static PyObject *qdbpy_unwatch(QdbHandle *self, PyObject *args)
{
    qdb_handle_t qdb;
    char *path;
    int result;

    if (!parse_handle_path(self, args, &qdb, &path))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    result = qdb_unwatch(qdb, path);
    Py_END_ALLOW_THREADS

    return none(result);
}

#define qdbpy_watch_fd_doc "\n"			\
	"Returns file descriptor to receive watches from Qubes DB.\n"	\
	"You can monitor this FD with select/poll for reads, then call read_watch()\n" \
	"\n"					\
	"Returns FD on success.\n"		\
	"Raises qubesdb.Error on error.\n"	\
	"\n"

static PyObject *qdbpy_watch_fd(QdbHandle *self)
{
    qdb_handle_t qdb = qdbhandle(self);
    int fd;

    if (!qdb)
        return NULL;

    fd = qdb_watch_fd(qdb);
    if (fd == -1) {
        return none(0);
    } else
#if PY_VERSION_HEX >= 0x03000000
        return PyLong_FromLong(fd);
#else
        return PyInt_FromLong(fd);
#endif
}

#define qdbpy_close_doc "\n"			\
	"Close the connection to Qubes DB.\n"	\
	"\n"					\
	"Returns None on success.\n"		\
	"Raises qubesdb.Error on error.\n"	\
	"\n"

static PyObject *qdbpy_close(QdbHandle *self)
{
    qdb_handle_t qdb = qdbhandle(self);

    if (!qdb)
        return NULL;

    qdb_close(qdb);
    self->qdb = NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

/**
 * Parse path arguments from the given args,
 * convert the given self value to an qdb_handle, and return all two by
 * reference.
 * 
 * @return 1 on success, in which case *qdb, and *path are valid, or 0 on
 * failure.
 */
static int parse_handle_path(QdbHandle *self, PyObject *args,
                                  qdb_handle_t *qdb,
                                  char **path)
{
    int path_len;
    *qdb = qdbhandle(self);

    if (!qdb)
        return 0;

    if (!PyArg_ParseTuple(args, "s#", path, &path_len))
        return 0;

    if (strlen(*path) != path_len) {
        PyErr_SetString(PyExc_TypeError, "null byte in path");
        return 0;
    }

    return 1;
}


static PyObject *none(bool result)
{
    if (result) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    else {
        if (errno == EPIPE) {
            PyErr_SetString(qdb_disconnected_error, "QubesDB disconnected");
        } else if (errno == EINTR) {
            PyErr_SetFromErrno(PyExc_OSError);
        } else {
            PyErr_SetFromErrno(qdb_error);
        }
        return NULL;
    }
}


#define QDBPY_METH(_name, _args) {               \
    .ml_name  = #_name,				\
    .ml_meth  = (PyCFunction) qdbpy_ ## _name,	\
    .ml_flags = _args,                          \
    .ml_doc   = qdbpy_ ## _name ## _doc }

static PyMethodDef qdbhandle_methods[] = {
    QDBPY_METH(read,              METH_VARARGS),
    QDBPY_METH(multiread,         METH_VARARGS),
    QDBPY_METH(write,             METH_VARARGS),
    QDBPY_METH(list,              METH_VARARGS),
    QDBPY_METH(rm,                METH_VARARGS),
    QDBPY_METH(watch,             METH_VARARGS),
    QDBPY_METH(read_watch,        METH_NOARGS),
    QDBPY_METH(unwatch,           METH_VARARGS),
    QDBPY_METH(close,             METH_NOARGS),
    QDBPY_METH(watch_fd,          METH_NOARGS),
    { NULL /* Sentinel. */ },
};

static PyObject *
qdbhandle_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    QdbHandle *self = (QdbHandle *)type->tp_alloc(type, 0);

    if (self == NULL)
        return NULL;

    self->qdb = NULL;

    return (PyObject *)self;
}

static int
qdbhandle_init(QdbHandle *self, PyObject *args)
{
    char *vmname = NULL;

    if (!PyArg_ParseTuple(args, "|s", &vmname))
        goto fail;

    self->qdb = qdb_open(vmname);
    if (!self->qdb)
        goto fail;

    return 0;

 fail:
    PyErr_SetFromErrno(qdb_error);
    return -1;
}

static void qdbhandle_dealloc(QdbHandle *self)
{
    if (self->qdb) {
        qdb_close(self->qdb);
        self->qdb = NULL;
    }

    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyTypeObject qdbhandle_type = {
#if PY_VERSION_HEX >= 0x03000000
    .ob_base = { PyObject_HEAD_INIT(NULL) },
#else
    PyObject_HEAD_INIT(NULL)
#endif
    .tp_name = PKG "." CLS,
    .tp_basicsize = sizeof(QdbHandle),
    .tp_itemsize = 0,
    .tp_dealloc = (destructor)qdbhandle_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "Qubes DB connections",
    .tp_methods = qdbhandle_methods,
    .tp_init = (initproc)qdbhandle_init,
    .tp_new = qdbhandle_new,
};


static PyMethodDef qdb_methods[] = { { NULL } };

#if PY_VERSION_HEX >= 0x03000000
static struct PyModuleDef qubesdb_module = {
    PyModuleDef_HEAD_INIT,
    PKG,  /* name */
    NULL, /* docstring */
    0,    /* size of per-interpreter state of the module */
    qdb_methods
};
#endif

#if PY_VERSION_HEX >= 0x03000000
PyMODINIT_FUNC PyInit_qubesdb(void)
#else
PyMODINIT_FUNC initqubesdb(void)
#endif
{
    PyObject *m;

#if PY_VERSION_HEX >= 0x03000000
    if (PyType_Ready(&qdbhandle_type) < 0)
        return NULL;

    m = PyModule_Create(&qubesdb_module);
    if (m == NULL)
        return NULL;
#else
    if (PyType_Ready(&qdbhandle_type) < 0)
        return;

    m = Py_InitModule(PKG, qdb_methods);
    if (m == NULL)
        return;
#endif

    qdb_error = PyErr_NewException(PKG ".Error", PyExc_RuntimeError, NULL);

    Py_INCREF(&qdbhandle_type);
    PyModule_AddObject(m, CLS, (PyObject *)&qdbhandle_type);

    Py_INCREF(qdb_error);
    PyModule_AddObject(m, "Error", qdb_error);

    qdb_disconnected_error = PyErr_NewExceptionWithDoc(
            PKG ".DisconnectedError",
            "Raised when connection to QubesDB daemon was broken",
            qdb_error,
            NULL
            );
    Py_INCREF(qdb_disconnected_error);
    PyModule_AddObject(m, "DisconnectedError", qdb_disconnected_error);

#if PY_VERSION_HEX >= 0x03000000
    return m;
#endif
}
