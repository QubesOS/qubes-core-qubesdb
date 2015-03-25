#ifndef _QUBESDB_INTERNAL_H
#define _QUBESDB_INTERNAL_H
#include <stdint.h>

#include <libvchan.h>

#ifdef WINNT
typedef HANDLE client_socket_t;
#define INVALID_CLIENT_SOCKET INVALID_HANDLE_VALUE
#define CLIENT_SOCKET_FORMAT "%p"
/* arbitrary numbers */
#define PIPE_MAX_INSTANCES 16
#define PIPE_TIMEOUT    5000
#else
typedef int client_socket_t;
#define INVALID_CLIENT_SOCKET -1
#define CLIENT_SOCKET_FORMAT "%d"
#endif

#define SERVER_SOCKET_BACKLOG 5

#define QUBESDB_VCHAN_PORT 111

#define MAX_FILE_PATH 256

struct client;

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
};

struct client {
    struct client *next;
    client_socket_t fd;
#ifdef WINNT
    int pending_io;
    OVERLAPPED overlapped_read;
    char read_buffer[sizeof(struct qdb_hdr)];
#endif
};


struct db_daemon_data {
    int remote_domid;           /* remote domain ID for vchan connection */
    char *remote_name;          /* remote domain name in dom0 part, NULL in VM */
    libvchan_t *vchan;          /* vchan connection */
    int remote_connected;       /* if remote daemon connected and ready for
                                 * processing requests (i.e. have
                                 * synchronised database */
#ifdef WINNT
    TCHAR socket_path[MAX_FILE_PATH]; /* socket path - Windows code needs at each connection */
    HANDLE socket_inst;         /* socket instance prepared for the new client */
    OVERLAPPED socket_inst_wait; /* pending ConnectToNewClient */
    PSECURITY_DESCRIPTOR socket_sa; /* security settings for service socket */
#else
    int socket_fd;              /* local server socket */
#endif
    struct qubesdb *db;         /* database */
    int multiread_requested;    /* have requested multiread, if not - drop such
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
        struct client *client);
int qubesdb_remove_watch(struct qubesdb *db, char *path,
        struct client *client);
int qubesdb_fire_watches(struct qubesdb *db, char *path);

int handle_vchan_data(struct db_daemon_data *d);
int handle_client_data(struct db_daemon_data *d, struct client *client,
                char *data, int data_len);
int handle_client_connect(struct db_daemon_data *d, struct client *client);
int handle_client_disconnect(struct db_daemon_data *d, struct client *client);

int request_full_db_sync(struct db_daemon_data *d);

#ifdef WINNT
#define perror winnt_perror
void winnt_perror(char *func);
#endif

#endif /* _QUBESDB_INTERNAL_H */
