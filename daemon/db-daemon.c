#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <poll.h>
#else
#include <windows.h>
#include <sddl.h>
#include <lmcons.h>
#include <strsafe.h>

#include <log.h>
#include <pipe-server.h>
#include <service.h>
#include <list.h>
#include <vchan-common.h>
#endif

#ifndef _WIN32
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
#else // !_WIN32
// parameters for a client pipe thread
struct thread_param {
    struct db_daemon_data *daemon;
    LONGLONG id;
};
#endif

#include "buffer.h"
#include <qubesdb.h>
#include "qubesdb_internal.h"

#ifndef _WIN32
mode_t rw_socket_mode = 0666;
#endif

int init_vchan(struct db_daemon_data *d);

#ifndef _WIN32
int sigterm_received = 0;
static void sigterm_handler(int s) {
    sigterm_received = 1;
}

/** Register new client
 * @param d Daemon global data
 * @param c Socket of new client
 * @return 1 on success, 0 on failure
 */
static int add_client(struct db_daemon_data *d, client_socket_t c, int is_rw_socket) {
    struct client *client;

    client = malloc(sizeof(*client));
    if (!client) {
        fprintf(stderr, "ERROR: cannot allocate memory for new client\n");
        return 0;
    }
    client->fd = c;
    client->can_write = is_rw_socket;

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
static int disconnect_client(struct db_daemon_data *d, struct client *c) {
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
static int accept_new_client(struct db_daemon_data *d, int is_rw_socket) {
    client_socket_t new_client_fd;
    struct sockaddr_un peer;
    unsigned int addrlen;

    addrlen = sizeof(peer);
    if (is_rw_socket) {
        new_client_fd = accept(d->rw_socket_fd, (struct sockaddr *) &peer, &addrlen);
    } else {
        new_client_fd = accept(d->ro_socket_fd, (struct sockaddr *) &peer, &addrlen);
    }
    if (new_client_fd == -1) {
        perror("unix accept");
        exit(1);
    }
    return add_client(d, new_client_fd, is_rw_socket);
}

#else // !_WIN32

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
            AcquireSRWLockExclusive(&d->lock);
            if (!handle_vchan_data(d)) {
                LogError("FATAL: vchan error");
                ReleaseSRWLockExclusive(&d->lock);
                return 0;
            }
            ReleaseSRWLockExclusive(&d->lock);
        }
    }

    // Create the thread that will handle client pipes
    pipe_thread = CreateThread(NULL, 0, pipe_thread_main, d->pipe_server, 0, NULL);
    if (!pipe_thread) {
        win_perror("CreateThread(main pipe thread)");
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
            win_perror2(status, "pipe thread");
            return 0;
        }

        case 1: {
            // service stopped
            LogInfo("service stopped, exiting");
            goto cleanup;
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
                    /* do not send further updates, until VM's daemon restart
                     * and re-sync */
                    d->remote_connected = 0;
                    break;
                }
                break;
            }

            if (d->remote_connected || libvchan_is_open(d->vchan)) {
                while (libvchan_data_ready(d->vchan)) {
                    AcquireSRWLockExclusive(&d->lock);
                    if (!handle_vchan_data(d)) {
                        fprintf(stderr, "FATAL: vchan data processing failed\n");
                        ReleaseSRWLockExclusive(&d->lock);
                        return 0;
                    }
                    ReleaseSRWLockExclusive(&d->lock);
                }
            }
            break;
        }

        default: {
            // wait failed
            win_perror("WaitForMultipleObjects");
            return 0;
        }
        }
    }

cleanup:
    if (WaitForSingleObject(pipe_thread, 1000) != WAIT_OBJECT_0)
    {
        TerminateThread(pipe_thread, 0);
        CloseHandle(pipe_thread);
    }
    QpsDestroy(d->pipe_server);
    d->pipe_server = NULL;
    if (d->vchan)
    {
        libvchan_close(d->vchan);
        d->vchan = NULL;
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
            LogWarning("QpsRead from client %lu failed: %d", p->id, (int)status);
            AcquireSRWLockExclusive(&p->daemon->lock);
            handle_client_disconnect(p->daemon, &c);
            QpsDisconnectClient(p->daemon->pipe_server, p->id);
            ReleaseSRWLockExclusive(&p->daemon->lock);
            free(param);
            return status;
        }

        AcquireSRWLockExclusive(&p->daemon->lock);
        if (!handle_client_data(p->daemon, &c, (char*)&hdr, sizeof(hdr))) {
            LogWarning("handle_client_data failed, disconnecting client %lu", p->id);
            handle_client_disconnect(p->daemon, &c);
            QpsDisconnectClient(p->daemon->pipe_server, p->id);
            ReleaseSRWLockExclusive(&p->daemon->lock);
            free(param);
            return 1;
        }
        ReleaseSRWLockExclusive(&p->daemon->lock);
    }
    return 0;
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
        win_perror("CreateThread");
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
        win_perror("ConvertStringSecurityDescriptorToSecurityDescriptor");
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
    if (d->pipe_server)
        QpsDestroy(d->pipe_server);
    d->pipe_server = NULL;
}
#endif // _WIN32

#ifndef _WIN32

static size_t fill_fdsets_for_select(struct db_daemon_data *d,
        struct pollfd fds[static MAX_CLIENTS + 3]) {
    struct client *client;
    size_t total_fds = 3;

    fds[0] = (struct pollfd) {
        .fd = d->rw_socket_fd,
        .events = POLLIN | POLLHUP,
        .revents = 0,
    };
    fds[1] = (struct pollfd) {
        .fd = d->ro_socket_fd,
        .events = POLLIN | POLLHUP,
        .revents = 0,
    };
    fds[2] = (struct pollfd) {
        .fd = d->vchan ? libvchan_fd_for_select(d->vchan) : -1,
        .events = POLLIN | POLLHUP,
        .revents = 0,
    };

    client = d->client_list;
    while (client) {
        assert(total_fds < MAX_CLIENTS + 3);
        /* Do not read commands from client, which have some buffered data,
         * first try to send them all. If client do not handle write buffering
         * properly, it can cause a deadlock there, but at least qubesdb-daemon
         * will still handle other requests */
        fds[total_fds++] = (struct pollfd) {
            .fd = client->fd,
            .events = buffer_datacount(client->write_queue) ? POLLOUT : POLLIN | POLLHUP,
            .revents = 0,
        };
        client = client->next;
    }
    return total_fds;
}

static int mainloop(struct db_daemon_data *d) {
    struct client *client;
    int ret;
    static struct pollfd fds[MAX_CLIENTS + 3];
    sigset_t sigterm_mask;
    sigset_t oldmask;
    struct timespec ts = { 10, 0 };

    sigemptyset(&sigterm_mask);
    sigaddset(&sigterm_mask, SIGTERM);

    while (1) {
        size_t current_fd = 3;
        size_t const nfds = fill_fdsets_for_select(d, fds);
        assert(nfds >= 3);
        assert(nfds <= MAX_CLIENTS + 3);

        if (sigprocmask(SIG_BLOCK, &sigterm_mask, &oldmask) < 0) {
            perror("sigprocmask");
            break;
        }
        if (sigterm_received) {
            fprintf(stderr, "terminating\n");
            break;
        }
        ret = ppoll(fds, nfds, &ts, &oldmask);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("ppoll");
            break;
        }
        /* restore signal mask */
        sigprocmask(SIG_SETMASK, &oldmask, NULL);

        if (d->vchan) {
            if (fds[2].revents)
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
            /* trigger pending data write */
            if (libvchan_buffer_space(d->vchan))
                write_vchan_or_client(d, NULL, NULL, 0);
            while (libvchan_data_ready(d->vchan)) {
                if (!handle_vchan_data(d)) {
                    fprintf(stderr, "FATAL: vchan data processing failed\n");
                    exit(1);
                }
            }
        }

        client = d->client_list;
        while (client) {
            assert(current_fd < MAX_CLIENTS + 3);
            short revents = fds[current_fd++].revents;
            if (revents & POLLOUT) {
                /* just send bufferred data, possibly not all of them */
                write_client_buffered(client, NULL, 0);
            }
            if (revents & (POLLIN | POLLHUP)) {
                if (!handle_client_data(d, client, NULL, 0)) {
                    struct client *client_to_remove = client;
                    client = client->next;
                    disconnect_client(d, client_to_remove);
                    continue;
                }
            }
            client = client->next;
        }
        assert(current_fd == nfds);

        if (fds[0].revents) {
            accept_new_client(d, 1);
        }
        if (fds[1].revents) {
            accept_new_client(d, 0);
        }
    }
    return 1;
}

/* FIXME: This function is now mis-named - it should be called
 * init_server_sockets, but renaming it would force us to either rename the
 * corresponding Windows function with the same name (which would imply
 * implementing rw and ro sockets for Windows), or would require us to use an
 * ifdef to cope with different function names. Both of those options are a
 * pain, so we live with a poorly named function for now. */
static int init_server_socket(struct db_daemon_data *d) {
    struct sockaddr_un rw_sockname;
    struct sockaddr_un ro_sockname;
    int s;
    struct stat stat_buf;
    mode_t old_umask;

    memset(&rw_sockname, 0, sizeof(rw_sockname));
    memset(&ro_sockname, 0, sizeof(ro_sockname));
    rw_sockname.sun_family = ro_sockname.sun_family = AF_UNIX;
    if (mkdir("/var/run/qubes", 0775) && errno != EEXIST) {
        perror("mkdir /var/run/qubes");
        return 0;
    }
    if (d->remote_name) {
        if ((unsigned)snprintf(rw_sockname.sun_path,
                               sizeof rw_sockname.sun_path,
                               QDB_DAEMON_PATH_RW_PATTERN, d->remote_name) >=
            sizeof rw_sockname.sun_path) {
            perror("snprintf()");
            return 0;
        }
        if ((unsigned)snprintf(ro_sockname.sun_path,
                               sizeof ro_sockname.sun_path,
                               QDB_DAEMON_PATH_RO_PATTERN, d->remote_name) >=
            sizeof ro_sockname.sun_path) {
            perror("snprintf()");
            return 0;
        }
        if (d->remote_domid == 0) {
            /* the same daemon as both VM and Admin parts */
            unlink(QDB_DAEMON_LOCAL_RW_PATH);
            unlink(QDB_DAEMON_LOCAL_RO_PATH);
            if (symlink(rw_sockname.sun_path, QDB_DAEMON_LOCAL_RW_PATH) < 0) {
                perror("symlink " QDB_DAEMON_LOCAL_RW_PATH);
                return 0;
            }
            if (symlink(ro_sockname.sun_path, QDB_DAEMON_LOCAL_RO_PATH) < 0) {
                perror("symlink " QDB_DAEMON_LOCAL_RO_PATH);
                return 0;
            }
        }
    } else {
        _Static_assert(sizeof QDB_DAEMON_LOCAL_RW_PATH
                       <= sizeof rw_sockname.sun_path,
                       QDB_DAEMON_LOCAL_RW_PATH "too long");
        _Static_assert(sizeof QDB_DAEMON_LOCAL_RO_PATH
                       <= sizeof ro_sockname.sun_path,
                       QDB_DAEMON_LOCAL_RO_PATH "too long");
        strcpy(rw_sockname.sun_path, QDB_DAEMON_LOCAL_RW_PATH);
        strcpy(ro_sockname.sun_path, QDB_DAEMON_LOCAL_RO_PATH);
    }

    if (unlink(rw_sockname.sun_path) && errno != ENOENT) {
        perror("unlink() failed");
        return 0;
    }
    if (unlink(ro_sockname.sun_path) && errno != ENOENT) {
        perror("unlink() failed");
        return 0;
    }

    /* make rw socket available to a potentially restricted set of users */
    old_umask = umask(~rw_socket_mode & 0777);

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bind(s, (struct sockaddr *) &rw_sockname,
             sizeof(rw_sockname)) == -1) {
        perror("bind() failed");
        close(s);
        return 0;
    }
//      chmod(rw_sockname.sun_path, rw_socket_mode);
    if (listen(s, SERVER_SOCKET_BACKLOG) == -1) {
        perror("listen() failed");
        close(s);
        return 0;
    }
    d->rw_socket_fd = s;

    /* make ro socket available for anyone */
    umask(0111);

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bind(s, (struct sockaddr *) &ro_sockname,
             sizeof(ro_sockname)) == -1) {
        perror("bind() failed");
        close(s);
        return 0;
    }
//      chmod(ro_sockname.sun_path, 0666);
    if (listen(s, SERVER_SOCKET_BACKLOG) == -1) {
        perror("listen() failed");
        close(s);
        return 0;
    }
    d->ro_socket_fd = s;

    umask(old_umask);
    if (stat(rw_sockname.sun_path, &stat_buf) == 0)
        d->rw_socket_ino = stat_buf.st_ino;
    if (stat(ro_sockname.sun_path, &stat_buf) == 0)
        d->ro_socket_ino = stat_buf.st_ino;
    return 1;
}

#endif /* !_WIN32 */

int init_vchan(struct db_daemon_data *d) {
    if (d->vchan) {
        buffer_free(d->vchan_buffer);
        libvchan_close(d->vchan);
        d->vchan = NULL;
    }
    d->vchan_buffer = buffer_create();
    if (!d->vchan_buffer) {
        fprintf(stderr, "vchan buffer allocation failed\n");
        return 0;
    }
    d->vchan_pending_hdr.type = QDB_INVALID_CMD;

    if (d->remote_name) {
        /* dom0 part: listen for connection */
        if (d->remote_domid == 0) {
            /* do not connect from dom0 to dom0 */
            d->vchan = NULL;
            return 1;
        }
#ifndef _WIN32
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
#ifndef _WIN32
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

#ifndef _WIN32
static int create_pidfile(struct db_daemon_data *d) {
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
    if (fstat(fileno(pidfile), &stat_buf) == 0)
        d->pidfile_ino = stat_buf.st_ino;
    fclose(pidfile);
    return 1;
}

static void remove_pidfile(struct db_daemon_data *d) {
    char pidfile_name[256];
    struct stat stat_buf;

    /* no pidfile for VM daemon - service is managed by systemd */
    if (!d->remote_name)
        return;
    snprintf(pidfile_name, sizeof(pidfile_name),
            "/var/run/qubes/qubesdb.%s.pid", d->remote_name);

    if (stat(pidfile_name, &stat_buf) == 0) {
        /* remove pidfile only if it's the one created this process */
        if (d->pidfile_ino == stat_buf.st_ino)
            unlink(pidfile_name);
    }
}

/* FIXME: This function's name is also bad; it should be
 * close_server_sockets. */
static void close_server_socket(struct db_daemon_data *d) {
    struct sockaddr_un rw_sockname;
    struct sockaddr_un ro_sockname;
    socklen_t addrlen;
    struct stat stat_buf;

    do {
        if (d->rw_socket_fd < 0)
            /* already closed */
            break;
        addrlen = sizeof(rw_sockname);
        if (getsockname(d->rw_socket_fd, (struct sockaddr *)&rw_sockname,
                        &addrlen) < 0)
            /* just do not remove socket when cannot get its path */
            break;

        close(d->rw_socket_fd);
        if (stat(rw_sockname.sun_path, &stat_buf) == 0) {
            /* remove the socket only if it's the one created this process */
            if (d->rw_socket_ino == stat_buf.st_ino)
                unlink(rw_sockname.sun_path);
        }
    } while(0);

    do {
        if (d->ro_socket_fd < 0)
            /* already closed */
            break;
        addrlen = sizeof(ro_sockname);
        if (getsockname(d->ro_socket_fd, (struct sockaddr *)&ro_sockname,
                        &addrlen) < 0)
            /* just do not remove socket when cannot get its path */
            break;

        close(d->ro_socket_fd);
        if (stat(ro_sockname.sun_path, &stat_buf) == 0) {
            /* remove the socket only if it's the one created this process */
            if (d->ro_socket_ino == stat_buf.st_ino)
                unlink(ro_sockname.sun_path);
        }
    } while(0);
}
#endif // !_WIN32

static void usage(char *argv0) {
#ifndef _WIN32
    fprintf(stderr, "Usage: %s [--rw-socket-perms=666] <remote-domid> [<remote-name>]\n", argv0);
#else
    fprintf(stderr, "Usage: %s <remote-domid> [<remote-name>]\n", argv0);
#endif
    fprintf(stderr, "       Give <remote-name> only in dom0\n");
}

#ifdef _WIN32
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

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
#else
int fuzz_main(int argc, char **argv) {
#endif
    int arg_pos = 0;
    struct db_daemon_data d;
#ifndef _WIN32
    int ready_pipe[2] = {0, 0};
#endif
    int ret;

    if (argc < 1) {
        fprintf(stderr, "argc < 1, cannot continue\n");
        exit(1);
#ifndef _WIN32
    } else if (argc < 2 || argc > 4) {
#else
    } else if (argc < 2 || argc > 3) {
#endif
        usage(argv[0]);
        exit(1);
    }
    arg_pos = 1;

#ifndef _WIN32
    if (strncmp(argv[arg_pos], "--rw-socket-perms=", strlen("--rw-socket-perms=")) == 0) {
        char *arg_start = strsep(&argv[arg_pos], "=");
        char *endptr = NULL;
        unsigned long parse_mode = 0;

        assert(arg_start != NULL);
        if (argv[arg_pos] == NULL) {
            usage(argv[0]);
            exit(1);
        }
        if (strlen(argv[arg_pos]) == 0) {
            usage(argv[0]);
            exit(1);
        }

        parse_mode = strtoul(argv[arg_pos], &endptr, 8);
        if (*endptr != '\0') {
            usage(argv[0]);
            exit(1);
        }
        if (parse_mode > 0777) {
            usage(argv[0]);
            exit(1);
        }

        rw_socket_mode = parse_mode;
        arg_pos++;

        if (argc - arg_pos < 1) {
            usage(argv[0]);
            exit(1);
        }
    }
#endif

#ifndef _WIN32
    memset(&d, 0, sizeof(d));
#else
    RtlSecureZeroMemory(&d, sizeof(d));
#endif

    d.remote_domid = atoi(argv[arg_pos]);
    if (argc - arg_pos >= 2 && strlen(argv[arg_pos + 1]) > 0)
        d.remote_name = argv[arg_pos + 1];
    else
        d.remote_name = NULL;

    /* if not running under SystemD, fork and use pipe() to notify parent about
     * sucessful start */
    /* FIXME: OS dependent code */
#ifndef _WIN32
#ifdef HAVE_SYSTEMD
    if (!getenv("NOTIFY_SOCKET")) {
#else
    if (1) {
#endif
        char buf[6];
        char log_path[MAX_FILE_PATH];
        int log_fd;
        mode_t old_umask;

        if (pipe(ready_pipe) < 0) {
            perror("pipe");
            exit(1);
        }
        switch (fork()) {
            case -1:
                perror("fork");
                exit(1);
            case 0:
                close(ready_pipe[0]);
                snprintf(log_path, sizeof(log_path), "/var/log/qubes/qubesdb.%s.log", d.remote_name ? d.remote_name : "dom0");

                close(0);
                old_umask = umask(0);
                log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0664);
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

#ifndef _WIN32
    d.db = qubesdb_init(write_client_buffered);
#else
    libvchan_register_logger(vchan_logger, LogGetLevel());
    d.db = qubesdb_init(send_watch_notify);
    InitializeSRWLock(&d.lock);
#endif
    if (!d.db) {
        fprintf(stderr, "FATAL: database initialization failed\n");
        exit(1);
    }

    if (!init_server_socket(&d)) {
        fprintf(stderr, "FATAL: server socket initialization failed\n");
        exit(1);
    }

#ifdef _WIN32
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
#else /* _WIN32 */
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
#ifdef HAVE_SYSTEMD
    if (getenv("NOTIFY_SOCKET")) {
        sd_notify(1, "READY=1");
    } else
#endif /* HAVE_SYSTEMD */
    {
        if (write(ready_pipe[1], "ready", strlen("ready")) != strlen("ready"))
            perror("failed to notify parent");
        close(ready_pipe[1]);
    }

    create_pidfile(&d);

    ret = !mainloop(&d);
#endif /* !_WIN32 */

    close_server_socket(&d);

#ifndef WIN32
    remove_pidfile(&d);
#endif

    return ret;
}
