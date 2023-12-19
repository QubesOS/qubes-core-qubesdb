#ifndef _QUBESDB_CLIENT_H
#define _QUBESDB_CLIENT_H

#ifdef _WIN32
#include <windows.h>

#ifdef QUBESDBCLIENT_EXPORTS
#    define QUBESDBCLIENT_API __declspec(dllexport)
#else
#    define QUBESDBCLIENT_API __declspec(dllimport)
#endif

#else /* _WIN32 */
#define QUBESDBCLIENT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @file qubesdb-client.h
 * This file describes public QubesDB client interface
 *
 * QubesDB is contiguration interface for Qubes VMs. It consists of two daemons
 * per VM - one in dom0 and one in VM. If you want configure VM from dom0, you
 * need specify which VM at connection time.
 *
 * Database consists of (path, value) pairs. Path must begins with '/', must
 * not end with '/' and can have maximum QDB_MAX_PATH (64) characters
 * (including terminating NULL) from [a-zA-Z0-9_.:/-].  You can use '/' inside
 * of path to specify directories - then you can perform some operations (like
 * LIST, RM or WATCH) on whole directory.
 * Value can consists of at most QDB_MAX_DATA (3072) non-null bytes.
 *
 */

struct qdb_handle;

/** Type of QubesDB connection handle
 */
typedef struct qdb_handle* qdb_handle_t;

/** Open connection to QubesDB daemon for given domain
 *
 * Each VM have own QubesDB daemon, so you need as many connections as many VMs
 * you need to configure
 * @param vmname Name of VM to which you want connect or NULL to connect to
 * local daemon
 * @return Connection handle or NULL in case of failure, should be closed with
 * qdb_close after use
 */
QUBESDBCLIENT_API
qdb_handle_t qdb_open(char *vmname);

/** Close connection to QubesDB daemon
 * @param h Connection handle
 */
QUBESDBCLIENT_API
void qdb_close(qdb_handle_t h);

/** Read single value from QubesDB
 * @param h Connection handle
 * @param path Path to read
 * @param[out] value_len Size of returned data (optional)
 * @return Key contents (NULL terminated) or NULL on failure. Value must be freed with free().
 */
QUBESDBCLIENT_API
char *qdb_read(qdb_handle_t h, char *path, unsigned int *value_len);

/** Get path list matching given prefix
 * @param h Connection handle
 * @param path Path prefix to match
 * @param[out] list_len Length of returned list (optional)
 * @return NULL terminated list of NULL terminated strings with list of paths.
 *         Values must be freed with free().
 */
QUBESDBCLIENT_API
char **qdb_list(qdb_handle_t h, char *path, unsigned int *list_len);

/** Get path list matching given prefixB
 * @param h Connection handle
 * @param path Path prefix to match
 * @param[out] values_len List of lengths of returned data (without terminating NULL)
 * @param[out] list_len Count of returned valued without terminating NULL,NULL (optional)
 * @return List of paths and data. So list length is 2*list_len and have [path,
 *         value, path, value, ...]. The whole list is terminated with two NULLs.
 * All returned data must be freed with free().
 */
QUBESDBCLIENT_API
char **qdb_multiread(qdb_handle_t h, char *path,
        unsigned int **values_len, unsigned int *list_len);

/** Write single value to QubesDB, override existing entry
 * @param h Connection handle
 * @param path Path to write
 * @param value Value to write
 * @param value_len Size of 'value' param
 * @return 1 on success, 0 on failure
 */
QUBESDBCLIENT_API
int qdb_write(qdb_handle_t h, char *path, char *value, unsigned int value_len);

/** Remove value from QubesDB
 * @param h Connection handle
 * @param path Path to remove, if ends with '/' will remove whole directory
 * @return 1 on success (even if no entries removed), 0 on failure
 */
QUBESDBCLIENT_API
int qdb_rm(qdb_handle_t h, char *path);


/** Register watch for given path.
 * Fired events should be received via qdb_read_watch().
 * @param h Connection handle
 * @param path Path to watch, if ends with '/' will watch whole directory
 * @return 1 on success, 0 on failure
 */
QUBESDBCLIENT_API
int qdb_watch(qdb_handle_t h, char *path);

/** Unregister watch for given path.
 * Note that even (shortly) after qdb_unwatch you can receive events for such
 * watch. Probably you want to ignore them, but must be prepared to do so.
 * @param h Connection handle
 * @param path Path of watch to be unregistered.
 * @return 1 on success, 0 on failure
 */
QUBESDBCLIENT_API
int qdb_unwatch(qdb_handle_t h, char *path);

/** Wait for watch event. If some event received earlier (but after last
 * qdb_read_watch call) returns immediately, otherwise block. You can also use
 * select() on FD returned by qdb_watch_fd to wait for events.
 * @param h Connection handle
 * @return Modified path or NULL on failure. Value must be freed with free().
 */
QUBESDBCLIENT_API
char *qdb_read_watch(qdb_handle_t h);

/** Return FD for select().
 * @param h Connection handle
 * @return FD number to use in select() call, on windows it is HANDLE for
 * event object.
 */
QUBESDBCLIENT_API
#ifdef _WIN32
HANDLE
#else
int
#endif
qdb_watch_fd(qdb_handle_t h);

#ifdef _WIN32
/** Free memory allocated by this DLL.
 * This is needed for executables that don't use the same CRT as this DLL (can't just use free() in such cases).
 * @param p The pointer to free
 */
QUBESDBCLIENT_API
void qdb_free(void *p);
#endif

#ifdef __cplusplus
}
#endif
#endif /* _QUBESDB_CLIENT_H */
