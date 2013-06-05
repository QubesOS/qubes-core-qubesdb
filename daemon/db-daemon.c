
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>

/* For now link with systemd unconditionaly (all Fedora versions are using it,
 * Archlinux also). But if someone needs no systemd in dependencies,
 * it can be easily turned off, check the code in main() - conditions on
 * getenv("NOTIFY_SOCKET").
 */
#include <systemd/sd-daemon.h>

#include <qubesdb.h>
#include "qubesdb_internal.h"

/** Register new client
 * @param d Daemon global data
 * @param c Socket of new client
 * @return 1 on success, 0 on failure
 */
int add_client(struct db_daemon_data *d, client_socket_t c) {
    struct client *client;

    client = malloc(sizeof(*client));
    if (!client) {
        fprintf(stderr, "ERROR: cannot allocate memory for new client\n");
        return 0;
    }
    client->fd = c;
    client->next = d->client_list;
    d->client_list = client;

    return handle_client_connect(d, c);
}

/** Disconnect client
 * @param d Daemon global data
 * @param c Socket of client to disconnect
 * @return 1 on success, 0 on failure
 */
int disconnect_client(struct db_daemon_data *d, client_socket_t c) {
    struct client *client, *prev_client;

    /* TODO: OS dependent call */
    close(c);

    client = d->client_list;
    prev_client = NULL;
    while (client) {
        if (client->fd == c) {
            if (prev_client)
                prev_client = client->next;
            else
                d->client_list = client->next;
            free(client);
            break;
        }
        prev_client = client;
        client = client->next;
    }

    return handle_client_disconnect(d, c);
}

/** Receive new client connection and register such client
 * @param d Daemon global data
 * @return 1 on success, 0 on failure
 */
int accept_new_client(struct db_daemon_data *d) {
    client_socket_t new_client_fd;
    struct sockaddr_un peer;
    unsigned int addrlen;

    addrlen = sizeof(peer);
    new_client_fd = accept(d->socket_fd, (struct sockaddr *) &peer, &addrlen);
    if (new_client_fd == -1) {
        perror("unix accept");
        exit(1);
    }
    return add_client(d, new_client_fd);
}

/* TODO: OS dependent function */
int fill_fdsets_for_select(struct db_daemon_data *d,
        fd_set * read_fdset) {
    struct client *client;
    int max_fd;

    FD_ZERO(read_fdset);
    FD_SET(d->socket_fd, read_fdset);
    max_fd = d->socket_fd;
    if (d->vchan) {
        FD_SET(libvchan_fd_for_select(d->vchan), read_fdset);
        if (libvchan_fd_for_select(d->vchan) > max_fd)
            max_fd = libvchan_fd_for_select(d->vchan);
    }

    client = d->client_list;
    while (client) {
        FD_SET(client->fd, read_fdset);
        if (client->fd > max_fd)
            max_fd = client->fd;
        client = client->next;
    }
    return max_fd;
}

/* TODO: OS dependent function */
int mainloop(struct db_daemon_data *d) {
    fd_set read_fdset;
    struct client *client;
    int max_fd;
    int ret;
    
    while (1) {
        max_fd = fill_fdsets_for_select(d, &read_fdset);

        ret = select(max_fd+1, &read_fdset, NULL, NULL, NULL);
        if (ret < 0) {
            perror("select");
            break;
        }


        if (d->vchan) {
            if (FD_ISSET(libvchan_fd_for_select(d->vchan), &read_fdset))
                libvchan_wait(d->vchan);
            if (d->remote_connected && !libvchan_is_open(d->vchan)) {
                fprintf(stderr, "vchan closed\n");
                break;
            }
            while (libvchan_data_ready(d->vchan)) {
                if (!handle_vchan_data(d)) {
                    fprintf(stderr, "FATAL: vchan data processing failed\n");
                    exit(1);
                }
            }
        }

        client = d->client_list;
        while (client) {
            if (FD_ISSET(client->fd, &read_fdset)) {
                if (!handle_client_data(d, client->fd, NULL, 0)) {
                    int client_to_remove = client->fd;
                    client = client->next;
                    disconnect_client(d, client_to_remove);
                    continue;
                }
            }
            client = client->next;
        }

        if (FD_ISSET(d->socket_fd, &read_fdset)) {
            accept_new_client(d);
        }
    }
    return 1;
}

#define MAX_FILE_PATH 256
/* TODO: OS dependent function */
int init_server_socket(struct db_daemon_data *d) {
    char socket_address[MAX_FILE_PATH];
    struct sockaddr_un sockname;
    int s;
    int old_umask;

    if (d->remote_name) {
        snprintf(socket_address, MAX_FILE_PATH,
                QDB_DAEMON_PATH_PATTERN, d->remote_name);
        if (d->remote_domid == 0) {
            /* the same daemon as both VM and Admin parts */
            unlink(QDB_DAEMON_LOCAL_PATH);
            symlink(socket_address, 
                    QDB_DAEMON_LOCAL_PATH);
        }
    } else {
        snprintf(socket_address, MAX_FILE_PATH,
                QDB_DAEMON_LOCAL_PATH);
    }

    unlink(socket_address);

    /* make socket available for anyone */
    old_umask = umask(0);

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&sockname, 0, sizeof(sockname));
    sockname.sun_family = AF_UNIX;
    memcpy(sockname.sun_path, socket_address, strlen(socket_address));

    if (bind(s, (struct sockaddr *) &sockname, sizeof(sockname)) == -1) {
        printf("bind() failed\n");
        close(s);
        exit(1);
    }
//      chmod(sockname.sun_path, 0666);
    if (listen(s, SERVER_SOCKET_BACKLOG) == -1) {
        perror("listen() failed\n");
        close(s);
        exit(1);
    }
    d->socket_fd = s;
    umask(old_umask);
    return 1;
}
 
int init_vchan(struct db_daemon_data *d) {

    if (d->remote_name) {
        /* dom0 part: listen for connection */
        if (d->remote_domid == 0) {
            /* do not connect from dom0 to dom0 */
            d->vchan = NULL;
            return 1;
        }
        d->vchan = libvchan_server_init(d->remote_domid, QUBESDB_VCHAN_PORT, 4096, 4096);
        if (!d->vchan)
            return 0;
        d->remote_connected = 0;
    } else {
        /* VM part: connect to admin domain */
        d->vchan = libvchan_client_init(d->remote_domid, QUBESDB_VCHAN_PORT);
        if (!d->vchan)
            return 0;
        d->remote_connected = 1;
    }
    return 1;
}

void usage(char *argv0) {
    fprintf(stderr, "Usage: %s <remote-domid> [<remote-name>]\n", argv0);
    fprintf(stderr, "       Give <remote-name> only in dom0\n");
}

int main(int argc, char **argv) {
    struct db_daemon_data d;
    int ready_pipe[2] = {0, 0};
    pid_t pid;

    if (argc != 2 && argc != 3) {
        usage(argv[0]);
        exit(1);
    }

    memset(&d, 0, sizeof(d));

    d.remote_domid = atoi(argv[1]);
    if (argc >= 3)
        d.remote_name = argv[2];
    else
        d.remote_name = NULL;

    /* if not running under SystemD, fork and use pipe() to notify parent about
     * sucessful start */
    /* FIXME: OS dependent code */
    if (!getenv("NOTIFY_SOCKET")) {
        char buf[6];
        char log_path[MAX_FILE_PATH];
        int log_fd;

        if (pipe(ready_pipe) < 0) {
            perror("pipe");
            exit(1);
        }
        switch (pid = fork()) {
            case -1:
                perror("fork");
                exit(1);
            case 0:
                close(ready_pipe[0]);
                snprintf(log_path, sizeof(log_path), "/var/log/qubes/qubesdb.%s.log", d.remote_name);

                close(0);
                log_fd = open(log_path, O_WRONLY | O_CREAT, 0644);
                if (log_fd < 0) {
                    perror("open logfile");
                    exit(1);
                }
                dup2(log_fd, 1);
                dup2(log_fd, 2);
                close(log_fd);

                break;
            default:
                close(ready_pipe[1]);
                if (read(ready_pipe[0], buf, sizeof(buf)) < strlen("ready")) {
                    fprintf(stderr, "startup failed\n");
                    exit(1);
                }
                exit(0);
        }
    }

    d.db = qubesdb_init();
    if (!d.db) {
        fprintf(stderr, "FATAL: database initialization failed\n");
        exit(1);
    }

    if (!init_server_socket(&d)) {
        fprintf(stderr, "FATAL: server socket initialization failed\n");
        exit(1);
    }

    if (!init_vchan(&d)) {
        fprintf(stderr, "FATAL: vchan initialization failed\n");
        exit(1);
    }

    if (!d.remote_name) {
        /* request database sync from dom0 */
        if (!request_full_db_sync(&d)) {
            fprintf(stderr, "FATAL: failed to request DB sync\n");
            exit(1);
        }
        d.multiread_requested = 1;
        /* wait for complete response */
        while (d.multiread_requested) {
            if (!handle_vchan_data(&d)) {
                fprintf(stderr, "FATAL: vchan error\n");
                exit(1);
            }
        }
    }

    /* now ready for serving requests, notify parent */
    /* FIXME: OS dependent code */
    if (getenv("NOTIFY_SOCKET")) {
        sd_notify(1, "READY=1");
    } else {
        write(ready_pipe[1], "ready", strlen("ready"));
        close(ready_pipe[1]);
    }

    return !mainloop(&d);
}
