
#include <stdint.h>

/* Possible contexts:
 * 1. dom0 -> VM
 * 2. VM -> dom0
 * 3. client -> daemon (in dom0)
 * 4. client -> daemon (in VM)
 */

enum qdb_msg {
    /** Read single value, path must not end with '/'. Successful read return
     * data with QDB_RESP_READ message.
     * 
     * Valid only on local socket. */

    QDB_CMD_READ,
    
    /** Write single value, path must not end with '/'. 
     * 
     * Valid on both local and inter-VM socket. */
    QDB_CMD_WRITE,
    
    /** Read multiple entries with path matching to given prefix (even if path
     * do not end with '/'). If empty path given, dump all database in reverse
     * order (to improve insert on other end).
     * 
     * Results given as series of QDB_RESP_MULTIREAD messages. End of data
     * signaled with data_len = 0 and path[0] = 0.
     * 
     * Valid on both local and inter-VM socket. Used for initial data dump in
     * VM daemon */
    QDB_CMD_MULTIREAD,
    
    /** Get list of entries matching given path (even if path do not end with
     * '/'). Only paths are returned, not values.
     * 
     * Results given as series of QDB_RESP_LIST messages. End of data signaled with
     * data_len = 0 (as in all other QDB_RESP_LIST messages) and path[0] = 0.
     * 
     * Valid only on local socket. */
    QDB_CMD_LIST,
    
    /** Remove entry from database. If path ends with '/' - remove all matching entries.
     * Valid on both local and inter-VM socket. */
    QDB_CMD_RM,
    
    /** Register watch for given path. If path ends with '/' - all matching
     * path will be watched. Given path can not exists in database yet.
     * 
     * When modification detected, QDB_RESP_WATCH will be generated.
     * Application should be prepared to receive QDB_RESP_WATCH at any time,
     * even in the middle of multi-response command processing. 
     * Same path can be registered multiple times - each write/delete will generate as
     * many events as registered matching watches.
     *
     * Valid only on local socket. */
    QDB_CMD_WATCH,
    
    /** Unregister watch for given path.
     *
     * Application should be prepared to receive QDB_RESP_WATCH even for (just)
     * unregistered watches. Probably should ignore it.
     *
     * Valid only on local socket. */
    QDB_CMD_UNWATCH, /* valid in context: 3,4 */

    /* responses */
    /** Command processed successfully, no data in response, path
     * preserved/copied from command message */
    QDB_RESP_OK,
    
    /** Error during processing command - given path not found in database.
     * This can happen for QDB_CMD_READ, QDB_CMD_RM, QDB_CMD_UNWATCH */
    QDB_RESP_ERROR_NOENT,
    
    /** Other error, path preserved/copied from command message */
    QDB_RESP_ERROR,
    
    /** Return data for QDB_CMD_READ */
    QDB_RESP_READ,

    /** Return data for QDB_CMD_MULTIREAD */
    QDB_RESP_MULTIREAD, 

    /** Return data for QDB_RESP_LIST */
    QDB_RESP_LIST, 

    /** Watch event occurred, path contains just modified entry path */
    QDB_RESP_WATCH,
};

#define QDB_MAX_CLIENTS 256
#define QDB_MAX_DATA 3072
#define QDB_MAX_PATH 64

/** Socket path for dom0 part of daemon for given VM */
#ifdef WINNT
#define QDB_DAEMON_PATH_PATTERN TEXT("\\\\.\\pipe\\qubesdb.%hs.sock")
#else
#define QDB_DAEMON_PATH_PATTERN "/var/run/qubes/qubesdb.%s.sock"
#endif
/** Socket path for VM part of daemon */
#ifdef WINNT
#ifdef BACKEND_VMM_wni
#define QDB_DAEMON_LOCAL_PATH TEXT("\\\\.\\pipe\\%hs\\qubesdb.sock")
#else
#define QDB_DAEMON_LOCAL_PATH TEXT("\\\\.\\pipe\\qubesdb.sock")
#endif
#else
#define QDB_DAEMON_LOCAL_PATH "/var/run/qubes/qubesdb.sock"
#endif

struct qdb_hdr {
    /** Message type as listed in `enum qdb_msg` */
    uint8_t type;
    /** Path, null terminated. See commands descriptions for details */
    char path[QDB_MAX_PATH];
    /** Length of data field in bytes. Maximum value QDB_MAX_DATA */
    uint32_t data_len;
    /** data of data_len bytes */
    char data[0];
};

