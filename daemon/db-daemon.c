#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#ifndef WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include "buffer.h"
#else
#include <windows.h>
#include <sddl.h>
#include <Lmcons.h>
#include <strsafe.h>

#include <log.h>
#include <pipe-server.h>
#include <service.h>
#include <list.h>
#include <vchan-common.h>
#endif

#ifndef WIN32
/* For now link with systemd unconditionaly (all Fedora versions are using it,
 * Archlinux also). But if someone needs no systemd in dependencies,
 * it can be easily turned off, check the code in main() - conditions on
 * getenv("NOTIFY_SOCKET").
 */
#include <systemd/sd-daemon.h>
#else // !WIN32
// parameters for a client pipe thread
struct thread_param {
    struct db_daemon_data *daemon;
    LONGLONG id;
};
#endif

#include <qubesdb.h>
#include "qubesdb_internal.h"

int init_vchan(struct db_daemon_data *d);

#ifndef WIN32
int sigterm_received = 0;
void sigterm_handler(int s) {
    sigterm_received = 1;
}

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

    client->write_queue = buffer_create();
    if (!client->write_queue) {
        fprintf(stderr, "ERROR: cannot allocate memory for new client buffer\n");
        free(client);
        return 0;
    }
    client->next = d->client_list;
    d->client_list = client;

    return handle_client_connect(d, client);
}

/** Disconnect client
 * @param d Daemon global data
 * @param c Socket of client to disconnect
 * @return 1 on success, 0 on failure
 */
int disconnect_client(struct db_daemon_data *d, struct client *c) {
    struct client *client, *prev_client;

    if (!handle_client_disconnect(d, c))
        return 0;

    close(c->fd);
    buffer_free(c->write_queue);

    client = d->client_list;
    prev_client = NULL;
    while (client) {
        if (client == c) {
            if (prev_client)
                prev_client->next = client->next;
            else
                d->client_list = client->next;
            free(client);
            break;
        }
        prev_client = client;
        client = client->next;
    }

    return 1;
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

#else // !WIN32

/* Main pipe server processing loop (separate thread).
 * Takes care of accepting clients and receiving data.
 */
DWORD WINAPI pipe_thread_main(PVOID param) {
    PIPE_SERVER ps = (PIPE_SERVER)param;

    // only returns on error
    return QpsMainLoop(ps);
}

int mainloop(struct db_daemon_data *d) {
    DWORD ret;
    DWORD status;
    HANDLE pipe_thread;
    HANDLE wait_objects[3];

    if (!init_vchan(d)) {
        perror("vchan initialization failed");
        return 0;
    }

    if (!d->remote_name) {
        /* request database sync from dom0 */
        if (!request_full_db_sync(d)) {
            LogError("FATAL: failed to request DB sync");
            return 0;
        }
        d->multiread_requested = 1;
        /* wait for complete response */
        while (d->multiread_requested) {
            if (!handle_vchan_data(d)) {
                LogError("FATAL: vchan error");
                return 0;
            }
        }
    }

    // Create the thread that will handle client pipes
    pipe_thread = CreateThread(NULL, 0, pipe_thread_main, d->pipe_server, 0, NULL);
    if (!pipe_thread) {
        perror("CreateThread(main pipe thread)");
        return 0;
    }

    // We'll wait for the pipe thread to exit, if it terminates
    // we're going down as well.
    wait_objects[0] = pipe_thread;

    // Also exit if the service is being stopped.
    wait_objects[1] = d->service_stop_event;

    // This loop will just process vchan data.
    while (1) {
        wait_objects[2] = libvchan_fd_for_select(d->vchan);
        /* TODO: add one more event for service termination */
        ret = WaitForMultipleObjects(3, wait_objects, FALSE, INFINITE) - WAIT_OBJECT_0;

        switch (ret) {
        case 0: {
            // pipe thread terminated, abort
            GetExitCodeThread(pipe_thread, &status);
            perror2(status, "pipe thread");
            return 0;
        }

        case 1: {
            // service stopped
            LogInfo("service stopped, exiting");
            return 1;
        }

        case 2: {
            // vchan read
            if (d->remote_connected && !libvchan_is_open(d->vchan)) {
                fprintf(stderr, "vchan closed\n");
                if (!d->remote_name) {
                    /* In the VM, wait for possible qubesdb-daemon dom0 restart.
                    * This can be a case for DispVM  */
                    /* FIXME: in such case dom0 daemon will have no entries
                    * currently present in VM instance; perhaps we should
                    * clear VM instance? */
                    if (!init_vchan(d)) {
                        fprintf(stderr, "vchan reconnection failed\n");
                        break;
                    }
                    /* request database sync from dom0 */
                    if (!request_full_db_sync(d)) {
                        fprintf(stderr, "FATAL: failed to request DB sync\n");
                        return 0;
                    }
                    d->multiread_requested = 1;
                } else {
                    break;
                }
                break;
            }

            if (d->remote_connected || libvchan_is_open(d->vchan)) {
                while (libvchan_data_ready(d->vchan)) {
                    if (!handle_vchan_data(d)) {
                        fprintf(stderr, "FATAL: vchan data processing failed\n");
                        return 0;
                    }
                }
            }
            break;
        }

        default: {
            // wait failed
            perror("WaitForMultipleObjects");
            return 0;
        }
        }
    }
    return 1;
}

DWORD WINAPI pipe_thread_client(PVOID param) {
    struct thread_param *p = param;
    struct client c;
    struct qdb_hdr hdr;
    DWORD status;

    c.id = p->id;

    while (1) {
        // blocking read
        status = QpsRead(p->daemon->pipe_server, p->id, &hdr, sizeof(hdr));
        if (ERROR_SUCCESS != status) {
            perror("QpsRead");
            LogWarning("read from client %lu failed", p->id);
            QpsDisconnectClient(p->daemon->pipe_server, p->id);
            free(param);
            return status;
        }

        if (!handle_client_data(p->daemon, &c, (char*)&hdr, sizeof(hdr))) {
            LogWarning("handle_client_data failed, disconnecting client %lu", p->id);
            QpsDisconnectClient(p->daemon->pipe_server, p->id);
            free(param);
            return 1;
        }
    }
}

void client_connected_callback(PIPE_SERVER server, LONGLONG id, PVOID context) {
    HANDLE client_thread;
    struct thread_param *param;

    param = malloc(sizeof(struct thread_param));
    if (!param) {
        LogError("no memory");
        QpsDisconnectClient(server, id);
        return;
    }

    param->id = id;
    param->daemon = context;
    client_thread = CreateThread(NULL, 0, pipe_thread_client, param, 0, NULL);
    if (!client_thread) {
        perror("CreateThread");
        free(param);
        return;
    }
    CloseHandle(client_thread);
    // the client thread will take care of processing client's data
}

int init_server_socket(struct db_daemon_data *d) {
    WCHAR pipe_name[MAX_FILE_PATH];
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD status;

    /* In dom0 listen only on "local" socket */
    if (d->remote_name && d->remote_domid != 0) {
        StringCbPrintfW(pipe_name, sizeof(pipe_name), QDB_DAEMON_PATH_PATTERN, d->remote_name);
    } else {
        StringCbPrintfW(pipe_name, sizeof(pipe_name), QDB_DAEMON_LOCAL_PATH);
    }
 /*
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        //TEXT("S:(ML;;NW;;;LW)D:(A;;FA;;;SY)(A;;FA;;;CO)"),
        L"D:(A;;FA;;;SY)(A;;FA;;;CO)",
        SDDL_REVISION_1,
        &sd,
        NULL)) {
        perror("ConvertStringSecurityDescriptorToSecurityDescriptor");
        return 0;
    }

    d->sa.lpSecurityDescriptor = sd;
    d->sa.bInheritHandle = FALSE;
    d->sa.nLength = sizeof(d->sa);
*/
    LogDebug("pipe: %s", pipe_name);
    status = QpsCreate(pipe_name,
                             4096, // pipe buffers
                             1024 * 1024, // read buffer
                             1000, // write timeout
                             client_connected_callback,
                             NULL,
                             NULL,
                             d, // context
                             NULL,//&d->sa,
                             &d->pipe_server);

    return status == ERROR_SUCCESS;
}

void close_server_socket(struct db_daemon_data *d) {
    QpsDestroy(d->pipe_server);
    d->pipe_server = NULL;
}
#endif // WIN32

#ifndef WIN32

int fill_fdsets_for_select(struct db_daemon_data *d,
        fd_set * read_fdset, fd_set * write_fdset) {
    struct client *client;
    int max_fd;

    FD_ZERO(read_fdset);
    FD_ZERO(write_fdset);
    FD_SET(d->socket_fd, read_fdset);
    max_fd = d->socket_fd;
    if (d->vchan) {
        FD_SET(libvchan_fd_for_select(d->vchan), read_fdset);
        if (libvchan_fd_for_select(d->vchan) > max_fd)
            max_fd = libvchan_fd_for_select(d->vchan);
    }

    client = d->client_list;
    while (client) {
        /* Do not read commands from client, which have some buffered data,
         * first try to send them all. If client do not handle write buffering
         * properly, it can cause a deadlock there, but at least qubesdb-daemon
         * will still handle other requests */
        if (buffer_datacount(client->write_queue))
            FD_SET(client->fd, write_fdset);
        else
            FD_SET(client->fd, read_fdset);
        if (client->fd > max_fd)
            max_fd = client->fd;
        client = client->next;
    }
    return max_fd;
}

int mainloop(struct db_daemon_data *d) {
    fd_set read_fdset;
    fd_set write_fdset;
    struct client *client;
    int max_fd;
    int ret;
    sigset_t sigterm_mask;
    sigset_t oldmask;
    struct timespec ts = { 10, 0 };

    sigemptyset(&sigterm_mask);
    sigaddset(&sigterm_mask, SIGTERM);

    while (1) {
        max_fd = fill_fdsets_for_select(d, &read_fdset, &write_fdset);

        if (sigprocmask(SIG_BLOCK, &sigterm_mask, &oldmask) < 0) {
            perror("sigprocmask");
            break;
        }
        if (sigterm_received) {
            fprintf(stderr, "terminating\n");
            break;
        }
        ret = pselect(max_fd+1, &read_fdset, &write_fdset, NULL, &ts, &oldmask);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            /* client could have disconnected just before select call, so
             * ignore this error and retry
             * FIXME: This probably will loop indefinitelly */
            if (errno == EBADF)
                continue;
            perror("select");
            break;
        }
        /* restore signal mask */
        sigprocmask(SIG_SETMASK, &oldmask, NULL);

        if (d->vchan) {
            if (FD_ISSET(libvchan_fd_for_select(d->vchan), &read_fdset))
                libvchan_wait(d->vchan);
            if (!libvchan_is_open(d->vchan)) {
                fprintf(stderr, "vchan closed\n");
                if (d->remote_connected) {
                    d->remote_connected = 0;
                    /* it was connected before, try to reconnect */
                    fprintf(stderr, "reconnecting\n");
                    if (!init_vchan(d)) {
                        fprintf(stderr, "vchan reconnection failed\n");
                        break;
                    }
                    if (!d->remote_name) {
                        /* FIXME: consider clearing the database, but needs to
                         * handle watches (DispVM case) */
                        /* request database sync from dom0 */
                        if (!request_full_db_sync(d)) {
                            fprintf(stderr, "FATAL: failed to request DB sync\n");
                            exit(1);
                        }
                        d->multiread_requested = 1;
                    }
                } else {
                    /* it wasn't connected, domain is probably dead */
                    break;
                }
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
            if (FD_ISSET(client->fd, &write_fdset)) {
                /* just send bufferred data, possibly not all of them */
                write_client_buffered(client, NULL, 0);
            }
            if (FD_ISSET(client->fd, &read_fdset)) {
                if (!handle_client_data(d, client, NULL, 0)) {
                    struct client *client_to_remove = client;
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
int init_server_socket(struct db_daemon_data *d) {
    char socket_address[MAX_FILE_PATH];
    struct sockaddr_un sockname;
    int s;
    struct stat stat_buf;
    mode_t old_umask;

    if (d->remote_name) {
        snprintf(socket_address, MAX_FILE_PATH,
                QDB_DAEMON_PATH_PATTERN, d->remote_name);
        if (d->remote_domid == 0) {
            /* the same daemon as both VM and Admin parts */
            unlink(QDB_DAEMON_LOCAL_PATH);
            if (symlink(socket_address, QDB_DAEMON_LOCAL_PATH) < 0) {
                perror("symlink " QDB_DAEMON_LOCAL_PATH);
                return 0;
            }
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
        return 0;
    }
//      chmod(sockname.sun_path, 0666);
    if (listen(s, SERVER_SOCKET_BACKLOG) == -1) {
        perror("listen() failed\n");
        close(s);
        return 0;
    }
    d->socket_fd = s;
    umask(old_umask);
    if (stat(sockname.sun_path, &stat_buf))
        d->socket_ino = stat_buf.st_ino;
    return 1;
}

#endif /* !WIN32 */

int init_vchan(struct db_daemon_data *d) {
    if (d->vchan) {
        libvchan_close(d->vchan);
        d->vchan = NULL;
    }
    if (d->remote_name) {
        /* dom0 part: listen for connection */
        if (d->remote_domid == 0) {
            /* do not connect from dom0 to dom0 */
            d->vchan = NULL;
            return 1;
        }
#ifndef WIN32
        d->vchan = libvchan_server_init(d->remote_domid, QUBESDB_VCHAN_PORT, 4096, 4096);
#else
        // We give a 5 minute timeout here because xeniface can take some time
        // to load the first time after reboot after pvdrivers installation.
        d->vchan = VchanInitServer(d->remote_domid, QUBESDB_VCHAN_PORT, 4096, 5 * 60 * 1000);
#endif
        if (!d->vchan)
            return 0;
        d->remote_connected = 0;
    } else {
        /* VM part: connect to admin domain */
#ifndef WIN32
        d->vchan = libvchan_client_init(d->remote_domid, QUBESDB_VCHAN_PORT);
#else
        // We give a 5 minute timeout here because xeniface can take some time
        // to load the first time after reboot after pvdrivers installation.
        d->vchan = VchanInitClient(d->remote_domid, QUBESDB_VCHAN_PORT, 5 * 60 * 1000);
#endif
        if (!d->vchan)
            return 0;
        d->remote_connected = 1;
    }
    return 1;
}

#ifndef WIN32
int create_pidfile(struct db_daemon_data *d) {
    char pidfile_name[256];
    FILE *pidfile;
    mode_t old_umask;
    struct stat stat_buf;

    /* do not create pidfile for VM daemon - service is managed by systemd */
    if (!d->remote_name)
        return 1;
    snprintf(pidfile_name, sizeof(pidfile_name),
            "/var/run/qubes/qubesdb.%s.pid", d->remote_name);

    old_umask = umask(0002);
    pidfile = fopen(pidfile_name, "w");
    umask(old_umask);
    if (!pidfile) {
        perror("pidfile create");
        return 0;
    }
    fprintf(pidfile, "%d\n", getpid());
    if (fstat(fileno(pidfile), &stat_buf))
        d->pidfile_ino = stat_buf.st_ino;
    fclose(pidfile);
    return 1;
}

void remove_pidfile(struct db_daemon_data *d) {
    char pidfile_name[256];
    struct stat stat_buf;

    /* no pidfile for VM daemon - service is managed by systemd */
    if (!d->remote_name)
        return;
    snprintf(pidfile_name, sizeof(pidfile_name),
            "/var/run/qubes/qubesdb.%s.pid", d->remote_name);

    if (stat(pidfile_name, &stat_buf)) {
        /* remove pidfile only if it's the one created this process */
        if (d->pidfile_ino == stat_buf.st_ino)
            unlink(pidfile_name);
    }
}

void close_server_socket(struct db_daemon_data *d) {
    struct sockaddr_un sockname;
    socklen_t addrlen;
    struct stat stat_buf;

    if (d->socket_fd < 0)
        /* already closed */
        return ;
    addrlen = sizeof(sockname);
    if (getsockname(d->socket_fd, (struct sockaddr *)&sockname, &addrlen) < 0)
        /* just do not remove socket when cannot get its path */
        return;

    close(d->socket_fd);
    if (stat(sockname.sun_path, &stat_buf)) {
        /* remove the socket only if it's the one created this process */
        if (d->socket_ino == stat_buf.st_ino)
            unlink(sockname.sun_path);
    }
}
#endif // !WIN32

void usage(char *argv0) {
    fprintf(stderr, "Usage: %s <remote-domid> [<remote-name>]\n", argv0);
    fprintf(stderr, "       Give <remote-name> only in dom0\n");
}

#ifdef WIN32
DWORD WINAPI service_thread(PVOID param) {
    PSERVICE_WORKER_CONTEXT ctx = param;
    struct db_daemon_data *d = ctx->UserContext;

    d->service_stop_event = ctx->StopEvent;

    return mainloop(d) ? NO_ERROR : ERROR_UNIDENTIFIED_ERROR;
}

static void vchan_logger(IN int logLevel, IN const CHAR *function, IN const WCHAR *format, IN va_list args)
{
    WCHAR buf[1024];

    StringCbVPrintfW(buf, sizeof(buf), format, args);
    _LogFormat(logLevel, FALSE, function, buf);
}

#endif

int main(int argc, char **argv) {
    struct db_daemon_data d;
#ifndef WIN32
    int ready_pipe[2] = {0, 0};
    pid_t pid;
#endif
    int ret;

    if (argc != 2 && argc != 3 && argc != 4) {
        usage(argv[0]);
        exit(1);
    }

    memset(&d, 0, sizeof(d));

    d.remote_domid = atoi(argv[1]);
    if (argc >= 3 && strlen(argv[2]) > 0)
        d.remote_name = argv[2];
    else
        d.remote_name = NULL;

    /* if not running under SystemD, fork and use pipe() to notify parent about
     * sucessful start */
    /* FIXME: OS dependent code */
#ifndef WIN32
    if (!getenv("NOTIFY_SOCKET")) {
        char buf[6];
        char log_path[MAX_FILE_PATH];
        int log_fd;
        mode_t old_umask;

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
                old_umask = umask(0);
                log_fd = open(log_path, O_WRONLY | O_CREAT, 0664);
                umask(old_umask);
                if (log_fd < 0) {
                    perror("open logfile");
                    exit(1);
                }
                dup2(log_fd, 1);
                dup2(log_fd, 2);
                close(log_fd);

                setsid();

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

    /* setup graceful shutdown handling */
    signal(SIGTERM, sigterm_handler);
#endif

#ifndef WIN32
    d.db = qubesdb_init(write_client_buffered);
#else
    libvchan_register_logger(vchan_logger);
    d.db = qubesdb_init(send_watch_notify);
#endif
    if (!d.db) {
        fprintf(stderr, "FATAL: database initialization failed\n");
        exit(1);
    }

    if (!init_server_socket(&d)) {
        fprintf(stderr, "FATAL: server socket initialization failed\n");
        exit(1);
    }

#ifdef WIN32
    d.db->pipe_server = d.pipe_server;
    /* For Windows, vchan is initialized later, after the service starts
       and reports to the OS. Otherwise it can time-out after the first
       reboot after installation and OS will kill the service.

       start the service loop, service_thread runs mainloop()
    */
    ret = SvcMainLoop(QDB_DAEMON_SERVICE_NAME,
                      0, // not interested in any control codes
                      service_thread, // worker thread
                      &d, // worker thread context
                      NULL, // notification handler
                      NULL // notification context
                      );
#else
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
        if (write(ready_pipe[1], "ready", strlen("ready")) != strlen("ready"))
            perror("failed to notify parent");
        close(ready_pipe[1]);
    }

    create_pidfile(&d);

    ret = !mainloop(&d);
#endif

    if (d.vchan)
        libvchan_close(d.vchan);

    close_server_socket(&d);

#ifndef WIN32
    remove_pidfile(&d);
#endif

    return ret;
}
