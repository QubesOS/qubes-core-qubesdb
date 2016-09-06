#ifndef _QUBESDB_INTERNAL_H
#define _QUBESDB_INTERNAL_H
#include <stdint.h>

#include <libvchan.h>

#ifndef WIN32
#include "buffer.h"
#else
#include <log.h>
#include <pipe-server.h>
#endif

#ifndef WIN32
typedef int client_socket_t;
#define INVALID_CLIENT_SOCKET -1
#define SERVER_SOCKET_BACKLOG 5
#endif

#define CLIENT_SOCKET_FORMAT "%d"
#define QUBESDB_VCHAN_PORT 111

#define MAX_FILE_PATH 256

struct client;

#ifndef WIN32
typedef int (*send_watch_notify_t)(struct client *c, char *buf, size_t len);
#else
typedef int (*send_watch_notify_t)(struct client *c, char *buf, size_t len, PIPE_SERVER ps);
#endif

struct qubesdb_entry {
    struct qubesdb_entry *prev;
    struct qubesdb_entry *next;
    char path[QDB_MAX_PATH];
    char *value;
    int value_len;
};

struct qubesdb_watch {
    struct qubesdb_watch *next;
    char path[QDB_MAX_PATH];
    int cmp_len;
    struct client *client;
};

struct qubesdb {
    struct qubesdb_entry *entries;
    struct qubesdb_watch *watches;
    send_watch_notify_t send_watch_notify;
#ifdef WIN32
    PIPE_SERVER pipe_server; // needed to communicate with clients
#endif
};

struct client {
#ifdef WIN32
    LONGLONG id;
#else
    struct client *next;
    client_socket_t fd;
    struct buffer *write_queue;
#endif
};

struct db_daemon_data {
    int remote_domid;           /* remote domain ID for vchan connection */
    char *remote_name;          /* remote domain name in dom0 part, NULL in VM */
    libvchan_t *vchan;          /* vchan connection */
    int remote_connected;       /* if remote daemon connected and ready for
                                 * processing requests (i.e. have
                                 * synchronised database */
#ifdef WIN32
    PIPE_SERVER pipe_server;
    SECURITY_ATTRIBUTES sa;
    HANDLE service_stop_event;
#else
    int socket_fd;              /* local server socket */
    struct client *client_list; /* local clients */
    /* those two are to avoid removing not own files on termination */
    int socket_ino;             /* socket file inode number */
    int pidfile_ino;            /* pidfile inode number */
#endif
    struct qubesdb *db;         /* database */
    int multiread_requested;    /* have requested multiread, if not - drop such
                                   responses */
};

struct qubesdb *qubesdb_init(send_watch_notify_t);

struct qubesdb_entry *qubesdb_search(struct qubesdb *db, char *path, int exact);

/* if entry already exists, return that entry - do not duplicate */
struct qubesdb_entry *qubesdb_insert(struct qubesdb *db, char *path);

int qubesdb_write(struct qubesdb *db, char *path, char *data, int data_len);

/* if key ends with '/', remove whole directory */
/* return 1 if anything removed (and should fire watches), 0 otherwise */
int qubesdb_remove(struct qubesdb *db, char *path);

int qubesdb_add_watch(struct qubesdb *db, char *path,
        struct client *client);
int qubesdb_remove_watch(struct qubesdb *db, char *path,
        struct client *client);
int qubesdb_fire_watches(struct qubesdb *db, char *path);

int handle_vchan_data(struct db_daemon_data *d);
int handle_client_data(struct db_daemon_data *d, struct client *client,
                char *data, int data_len);
int handle_client_connect(struct db_daemon_data *d, struct client *client);
int handle_client_disconnect(struct db_daemon_data *d, struct client *client);
#ifndef WIN32
int write_client_buffered(struct client *client, char *buf, size_t len);
#else
int send_watch_notify(struct client *c, char *buf, size_t len, PIPE_SERVER ps);
#endif

int request_full_db_sync(struct db_daemon_data *d);

#endif /* _QUBESDB_INTERNAL_H */
