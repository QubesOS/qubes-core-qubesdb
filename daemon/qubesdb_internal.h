#ifndef _QUBESDB_INTERNAL_H
#define _QUBESDB_INTERNAL_H
#include <stdint.h>

#include <libvchan.h>

typedef int client_socket_t;
#define INVALID_CLIENT_SOCKET -1

#define SERVER_SOCKET_BACKLOG 5

#define QUBESDB_VCHAN_PORT 111

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
    client_socket_t client_socket;
};


struct qubesdb {
    struct qubesdb_entry *entries;
    struct qubesdb_watch *watches;
};

struct client {
    struct client *next;
    client_socket_t fd;
};


struct db_daemon_data {
    int remote_domid;           /* remote domain ID for vchan connection */
    char *remote_name;          /* remote domain name in dom0 part, NULL in VM */
    libvchan_t *vchan;          /* vchan connection */
    int remote_connected;       /* if remote daemon connected and ready for
                                 * processing requests (i.e. have
                                 * synchronised database */
    int socket_fd;              /* local server socket */
    struct qubesdb *db;         /* database */
    int multiread_requested;    /* have requested multiread, if not drop such
                                   responses */
    struct client *client_list; /* local clients */
};

struct qubesdb *qubesdb_init(void);

struct qubesdb_entry *qubesdb_search(struct qubesdb *db, char *path, int exact);

/* if entry already exists, return that entry - do not duplicate */
struct qubesdb_entry *qubesdb_insert(struct qubesdb *db, char *path);

int qubesdb_write(struct qubesdb *db, char *path, char *data, int data_len);

/* if key ends with '/', remove whole directory */
/* return 1 if anything removed (and should fire watches), 0 otherwise */
int qubesdb_remove(struct qubesdb *db, char *path);

int qubesdb_add_watch(struct qubesdb *db, char *path,
        client_socket_t client_socket);
int qubesdb_remove_watch(struct qubesdb *db, char *path,
        client_socket_t client_socket);
int qubesdb_fire_watches(struct qubesdb *db, char *path);

int handle_vchan_data(struct db_daemon_data *d);
int handle_client_data(struct db_daemon_data *d, client_socket_t client,
                char *data, int data_len);
int handle_client_connect(struct db_daemon_data *d, client_socket_t client);
int handle_client_disconnect(struct db_daemon_data *d, client_socket_t client);

int request_full_db_sync(struct db_daemon_data *d);

#endif /* _QUBESDB_INTERNAL_H */
