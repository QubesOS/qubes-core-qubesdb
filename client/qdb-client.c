#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <windows.h>
#include <Lmcons.h>
#include <strsafe.h>
#include <log.h>
#include <qubes-io.h>
#include <pipe-server.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <assert.h>
#include <errno.h>

#include <qubesdb.h>
#include <qubesdb-client.h>

#define MAX_FILE_NAME 256

/* type of value returned by read/write functions - on windows
 * ReadFile/WriteFile expects DWORD as bytes count */
#ifdef WIN32
typedef DWORD rw_ret_t;
#define strdup _strdup
#else
typedef int rw_ret_t;
#endif

struct path_list {
    struct path_list *next;
    char *path;
};

struct qdb_handle {
#ifdef WIN32
    HANDLE read_pipe;
    HANDLE write_pipe;
#else
    int fd;
#endif
    char *vmname;
    int connected;

    /* pending watch event received */
    struct path_list *watch_list;
};

void free_path_list(struct path_list *plist) {
    struct path_list *tmp;

    while (plist) {
        tmp = plist;
        plist = plist->next;
        free(tmp->path);
        free(tmp);
    }
}

#ifdef WIN32
static int connect_to_daemon(struct qdb_handle *qh) {
    WCHAR pipe_name[MAX_FILE_NAME];
    ULONG status;

    if (qh->vmname && strcmp(qh->vmname, "dom0") != 0) {
        StringCbPrintf(pipe_name, sizeof(pipe_name), QDB_DAEMON_PATH_PATTERN, qh->vmname);
    } else {
#ifdef BACKEND_VMM_wni
        /* on WNI we don't have separate namespace for each VM (all is in the
         * single system) */
        DWORD user_name_len = UNLEN + 1;
        WCHAR user_name[user_name_len];

        if (!GetUserName(user_name, &user_name_len)) {
            perror("GetUserName");
            return 0;
        }
        StringCbPrintf(pipe_name, sizeof(pipe_name), QDB_DAEMON_LOCAL_PATH, user_name);
#else

        StringCbPrintf(pipe_name, sizeof(pipe_name), QDB_DAEMON_LOCAL_PATH);
#endif
    }

    qh->read_pipe = INVALID_HANDLE_VALUE;
    qh->write_pipe = INVALID_HANDLE_VALUE;

    status = QpsConnect(pipe_name, &qh->read_pipe, &qh->write_pipe);
    if (status != ERROR_SUCCESS)
    {
        perror2(status, "connect to server");
        return 0;
    }

    return 1;
}

#else /* !WIN32 */

static int connect_to_daemon(struct qdb_handle *qh) {
    struct sockaddr_un remote;
    int len;
    int fd;

    if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1) {
        perror("socket");
        goto error;
    }

    remote.sun_family = AF_UNIX;
    if (qh->vmname) {
        snprintf(remote.sun_path, sizeof(remote.sun_path), QDB_DAEMON_PATH_PATTERN, qh->vmname);
    } else {
        snprintf(remote.sun_path, sizeof(remote.sun_path), QDB_DAEMON_LOCAL_PATH);
    }

    len = strlen(remote.sun_path) + sizeof(remote.sun_family);
    if (connect(fd, (struct sockaddr *) &remote, len) == -1) {
        goto error;
    }
    qh->fd = fd;
    return 1;

error:
    if (fd >= 0)
        close(fd);
    qh->fd = -1;
    return 0;
}

#endif /* !WIN32 */

/** Send message to daemon. If EPIPE encountered try to reconnect (perhaps
 * daemon has restarted, or closed connection after previous (invalid)
 * command).
 * @param h Connection handle
 * @param hdr Command header
 * @param data Command data (required only when hdr->data_len > 0)
 * @return 1 on success, 0 on failure
 */
#ifdef WIN32
static int send_command_to_daemon(qdb_handle_t h, struct qdb_hdr *hdr, void *data) {
    /* if commands needs additional data, the last parameter must not be NULL
     */
    assert(data || hdr->data_len == 0);
    /* This function writes at most QDB_MAX_DATA bytes (3k) at once,
     * which is atomic on Linux */

    if (!QioWriteBuffer(h->write_pipe, hdr, sizeof(*hdr))) {
        /* some fatal error on previous command (and daemon closed connection)
         * perhaps? or daemon has restarted */
        if (GetLastError() == ERROR_BROKEN_PIPE) {
            /* try to reconnect */
            CloseHandle(h->read_pipe);
            CloseHandle(h->write_pipe);
            if (!connect_to_daemon(h))
            /* FIXME: register watches again */
                /* reconnect failed */
                return 0;
            else {
                /* try again */
                if (!QioWriteBuffer(h->write_pipe, hdr, sizeof(*hdr))) {
                    perror("write to daemon");
                    return 0;
                }
                else
                    return 1;
            }
        } else {
            /* other write error */
            perror("write to daemon");
            return 0;
        }
    }
    if (data && !QioWriteBuffer(h->write_pipe, data, hdr->data_len)) {
        /* no recovery after header send, daemon most likely closed connection
         * in reaction to our data */
        perror("write to daemon");
        return 0;
    }
    return 1;
}

#else /* !WIN32 */

static int send_command_to_daemon(qdb_handle_t h, struct qdb_hdr *hdr,
        void *data) {
    /* if commands needs additional data, the last parameter must not be NULL
     */
    assert(data || hdr->data_len == 0);

    /* try to reconnect if previous connection was severed */
    if (!h->connected) {
        if (!connect_to_daemon(h)) {
            /* reconnect failed */
            errno = EPIPE;
            return 0;
        }
        /* FIXME: register watches again */
    }
    /* This function writes at most QDB_MAX_DATA bytes (3k) at once,
     * which is atomic on Linux */
    if (write(h->fd, hdr, sizeof(*hdr)) < (int)sizeof(*hdr)) {
        /* some fatal error on previous command (and daemon closed connection)
         * perhaps? or daemon has restarted */
        if (errno == EPIPE) {
            /* try to reconnect */
            close(h->fd);
            /* FIXME: register watches again */
            if (!connect_to_daemon(h)) {
                /* reconnect failed */
                h->connected = 0;
                errno = EPIPE;
                return 0;
            } else {
                /* try again */
                if (write(h->fd, hdr, sizeof(*hdr)) < (int)sizeof(*hdr))
                    return 0;
                else
                    return 1;
            }
        } else {
            /* other write error */
            perror("write to daemon");
            return 0;
        }
    }
    if (data && write(h->fd, data, hdr->data_len) < hdr->data_len) {
        /* no recovery after header send, daemon most likely closed connection
         * in reaction to our data */
        return 0;
    }
    return 1;
}

#endif /* !WIN32 */

qdb_handle_t qdb_open(char *vmname) {
    struct qdb_handle *h;

    h = malloc(sizeof(*h));
    if (!h)
        return NULL;

    if (vmname)
        h->vmname = strdup(vmname);
    else
        h->vmname = NULL;

    if (!connect_to_daemon(h))
        goto error;
    h->connected = 1;

    h->watch_list = NULL;

    return h;

error:
#ifdef WIN32
    if (h->read_pipe != INVALID_HANDLE_VALUE)
        CloseHandle(h->read_pipe);
    if (h->write_pipe != INVALID_HANDLE_VALUE)
        CloseHandle(h->write_pipe);
#else
    if (h->fd > -1)
        close(h->fd);
#endif
    if (h->vmname)
        free(h->vmname);
    free(h);
    return NULL;
}

void qdb_close(qdb_handle_t h) {
    if (!h)
        return;
    if (h->vmname)
        free(h->vmname);
    free_path_list(h->watch_list);
    if (h->connected) {
#ifdef WIN32
        FlushFileBuffers(h->write_pipe);
        CloseHandle(h->write_pipe);
        CloseHandle(h->read_pipe);
#else
        shutdown(h->fd, SHUT_RDWR);
        close(h->fd);
#endif
    }
    free(h);
}

/** Can get fired watches before actual response, so handle it in separate
 * function */
static int get_response(qdb_handle_t h, struct qdb_hdr *hdr) {
    rw_ret_t len;
    struct path_list *w;

    do {
#ifdef WIN32
        if (!ReadFile(h->read_pipe, hdr, sizeof(*hdr), &len, NULL))
            return 0;
#else
        len = read(h->fd, hdr, sizeof(*hdr));
#endif
        if (len <= 0) {
            if (len == 0) {
                h->connected = 0;
#ifdef WIN32
                CloseHandle(h->read_pipe);
                h->read_pipe = INVALID_HANDLE_VALUE;
#else
                close(h->fd);
#endif
                errno = EPIPE;
            }
            return 0;
        }
        if (len < (int)sizeof(*hdr)) {
            /* partial read?! */
            return 0;
        }
        if (hdr->type == QDB_RESP_WATCH) {
            assert(hdr->data_len == 0);
            w = malloc(sizeof(*w));
            if (!w)
                return 0;
            w->path = strdup(hdr->path);
            w->next = h->watch_list;
            h->watch_list = w;
        }
    } while (hdr->type == QDB_RESP_WATCH);
    return 1;
}

static int verify_path(char *path) {
    if (!path)
        return 0;
    if (path[0] != '/')
        return 0;
    if (strlen(path) >= QDB_MAX_PATH)
        return 0;
    /* TODO: verify path content? will be verified by daemon anyway */
    return 1;
}

char *qdb_read(qdb_handle_t h, char *path, unsigned int *value_len) {
    struct qdb_hdr hdr;
    char *value;
    uint32_t got_data;
    rw_ret_t ret;

    if (!h)
        return NULL;
    if (!verify_path(path))
        return NULL;

    hdr.type = QDB_CMD_READ;
    /* already verified string length */
#ifdef WIN32
    StringCbCopyA(hdr.path, sizeof(hdr.path), path);
#else
    strcpy(hdr.path, path);
#endif
    hdr.data_len = 0;
    if (!send_command_to_daemon(h, &hdr, NULL))
        /* some fatal error perhaps? */
        return NULL;
    if (!get_response(h, &hdr))
        return NULL;
    /* TODO: make this distinguishable from other errors */
    if (hdr.type == QDB_RESP_ERROR_NOENT) {
        errno = ENOENT;
        return NULL;
    }
    if (hdr.type == QDB_RESP_ERROR) {
        /* TODO? */
        assert(hdr.data_len == 0);
        return NULL;
    }
    assert(hdr.type == QDB_RESP_READ);
    /* +1 for terminating \0 */
    value = malloc(hdr.data_len+1);
    if (!value)
        return NULL;
    got_data = 0;
    while (got_data < hdr.data_len) {
#ifdef WIN32
        ret = hdr.data_len - got_data; // this function always reads the requested size
        if (!QioReadBuffer(h->read_pipe, value+got_data, hdr.data_len-got_data)) {
#else
        ret = read(h->fd, value+got_data, hdr.data_len-got_data);
        if (ret <= 0) {
#endif
            free(value);
            return NULL;
        }
        got_data += ret;
    }
    value[got_data] = '\0';

    if (value_len)
        *value_len = got_data;

    return value;
}

char **qdb_list(qdb_handle_t h, char *path, unsigned int *list_len) {
    struct qdb_hdr hdr;
    struct path_list *plist = NULL;
    struct path_list *plist_tmp;
    int count = 0;
    char **ret;

    if (!h)
        return NULL;
    if (!verify_path(path))
        return NULL;

    hdr.type = QDB_CMD_LIST;
    /* already verified string length */
#ifdef WIN32
    StringCbCopyA(hdr.path, sizeof(hdr.path), path);
#else
    strcpy(hdr.path, path);
#endif
    hdr.data_len = 0;
    if (!send_command_to_daemon(h, &hdr, NULL))
        /* some fatal error perhaps? */
        return NULL;

    /* receive entries (QDB_RESP_LIST messages) and add them to plist at the
     * beginning. This means that list will be in reverse order. */
    while (1) {
        if (!get_response(h, &hdr)) {
            free_path_list(plist);
            return NULL;
        }
        if (hdr.type == QDB_RESP_ERROR) {
            free_path_list(plist);
            return NULL;
        }
        assert(hdr.type == QDB_RESP_LIST);
        if (!hdr.path[0])
            /* end of list */
            break;

        plist_tmp = malloc(sizeof(*plist_tmp));
        if (!plist_tmp) {
            /* OOM */
            free_path_list(plist);
            return NULL;
        }

        plist_tmp->path = strdup(hdr.path);
        if (!plist_tmp->path) {
            /* OOM */
            free_path_list(plist);
            return NULL;
        }
        plist_tmp->next = plist;
        plist = plist_tmp;
        count++;
    }
    ret = malloc((count+1) * sizeof(char*));
    if (!ret) {
        /* OOM */
        free_path_list(plist);
        return NULL;
    }

    /* End of table marker */
    ret[count] = NULL;

    if (list_len)
        *list_len = count;

    /* write responses to array, in reverse order so entries will be back
     * sorted */
    while (plist && count) {
        ret[--count] = plist->path;
        plist_tmp = plist;
        plist = plist->next;
        free(plist_tmp);
    }
    return ret;
}

char **qdb_multiread(qdb_handle_t h, char *path,
        unsigned int **values_len, unsigned int *list_len) {
    struct qdb_hdr hdr;
    int count = 0;
    char *value;
    uint32_t got_data;
    char **ret = NULL, **ret2;
    rw_ret_t read_ret;
    unsigned int *len_ret = NULL, *len_ret2;

    if (!h)
        return NULL;
    if (!verify_path(path))
        return NULL;

    hdr.type = QDB_CMD_MULTIREAD;
    /* already verified string length */
#ifdef WIN32
    StringCbCopyA(hdr.path, sizeof(hdr.path), path);
#else
    strcpy(hdr.path, path);
#endif
    hdr.data_len = 0;
    if (!send_command_to_daemon(h, &hdr, NULL))
        /* some fatal error perhaps? */
        return NULL;

    /* initial arrays */
    ret = malloc(2*sizeof(char*));
    if (!ret) {
        return NULL;
    }

    if (values_len) {
        len_ret = malloc(sizeof(unsigned int));
        if (!len_ret) {
            free(ret);
            return NULL;
        }
    }

    /* receive entries (QDB_RESP_MULTIREAD messages) */
    while (1) {
        if (!get_response(h, &hdr)) {
            free(ret);
            free(len_ret);
            return NULL;
        }
        assert(hdr.type == QDB_RESP_MULTIREAD);
        if (!hdr.path[0])
            /* end of list */
            break;

        /* +1 for terminating \0 */
        value = malloc(hdr.data_len+1);
        if (!value) {
            free(ret);
            free(len_ret);
            return NULL;
        }
        got_data = 0;
        while (got_data < hdr.data_len) {
#ifdef WIN32
            read_ret = hdr.data_len - got_data; // this function always reads the requested size
            if (!QioReadBuffer(h->read_pipe, value+got_data, hdr.data_len-got_data)) {
#else
            read_ret = read(h->fd, value+got_data, hdr.data_len-got_data);
            if (read_ret <= 0) {
#endif
                free(value);
                free(ret);
                free(len_ret);
                return NULL;
            }
            got_data += read_ret;
        }
        value[got_data] = '\0';

        /* (path+value)*count + NULL,NULL
         * Note that count is still unchanged */
        ret2 = realloc(ret, 2*(count+2)*sizeof(char*));
        if (!ret2) {
            free(ret);
            free(value);
            free(len_ret);
            return NULL;
        }
        ret = ret2;

        if (values_len) {
            len_ret2 = realloc(len_ret, (count+2)*sizeof(unsigned int));
            if (!len_ret2) {
                free(len_ret);
                free(value);
                free(ret);
                return NULL;
            }
            len_ret = len_ret2;
        }

        /* first path */
        ret[2*count] = strdup(hdr.path);
        /* then data */
        ret[2*count+1] = value;
        /* and data len if requested */
        if (values_len)
            len_ret[count] = hdr.data_len;
        count++;
    }

    /* End of table marker */
    ret[2*count] = NULL;
    ret[2*count+1] = NULL;

    if (values_len)
        *values_len = len_ret;
    if (list_len)
        *list_len = count;

    return ret;
}

/** Write single value to QubesDB, will override existing entry.
 */
int qdb_write(qdb_handle_t h, char *path, char *value, unsigned int value_len) {
    struct qdb_hdr hdr;

    if (!h)
        return 0;
    /* daemon will verify data anyway, but check here to return meaningful
     * error message */
    if (!verify_path(path))
        return 0;
    if (!value || value_len > QDB_MAX_DATA)
        return 0;

    hdr.type = QDB_CMD_WRITE;
    /* already verified string length */
#ifdef WIN32
    StringCbCopyA(hdr.path, sizeof(hdr.path), path);
#else
    strcpy(hdr.path, path);
#endif
    hdr.data_len = value_len;
    if (!send_command_to_daemon(h, &hdr, value))
        /* some fatal error perhaps? */
        return 0;
    if (!get_response(h, &hdr))
        return 0;
    if (hdr.type == QDB_RESP_ERROR) {
        /* TODO? */
        assert(hdr.data_len == 0);
        return 0;
    }
    assert(hdr.type == QDB_RESP_OK);
    assert(hdr.data_len == 0);
    return 1;
}

/** Common function for simple commands - only path as argument and no return data.
 * @param h Connection handle
 * @param path Entry path
 * @param cmd Command (hdr.type content)
 * @return 1 on success, 0 on failure
 */
static int qdb__simple_cmd(qdb_handle_t h, char *path, int cmd) {
    struct qdb_hdr hdr;

    if (!h)
        return 0;
    if (!verify_path(path))
        return 0;

    hdr.type = cmd;
    /* already verified string length */
#ifdef WIN32
    StringCbCopyA(hdr.path, sizeof(hdr.path), path);
#else
    strcpy(hdr.path, path);
#endif
    hdr.data_len = 0;

    if (!send_command_to_daemon(h, &hdr, NULL))
        /* some fatal error perhaps? */
        return 0;

    if (!get_response(h, &hdr))
        return 0;
    /* TODO: ignore NOENT for now */
    if (hdr.type == QDB_RESP_ERROR_NOENT) {
        return 1;
    }
    if (hdr.type == QDB_RESP_ERROR) {
        /* TODO? */
        assert(hdr.data_len == 0);
        return 0;
    }
    assert(hdr.type == QDB_RESP_OK);
    assert(hdr.data_len == 0);
    return 1;
}

int qdb_watch(qdb_handle_t h, char *path) {
    return qdb__simple_cmd(h, path, QDB_CMD_WATCH);
}

int qdb_unwatch(qdb_handle_t h, char *path) {
    return qdb__simple_cmd(h, path, QDB_CMD_UNWATCH);
}

int qdb_rm(qdb_handle_t h, char *path) {
    return qdb__simple_cmd(h, path, QDB_CMD_RM);
}

#ifdef WIN32
HANDLE
#else
int
#endif
qdb_watch_fd(qdb_handle_t h) {
#ifdef WIN32
    /* TODO: begin overlapped read operation and return event handle */
    /* TODO: for overlapped read, pipe should be opened in overlapped mode */
    return INVALID_HANDLE_VALUE;
#else
    if (!h->connected) {
        if (!connect_to_daemon(h)) {
            /* reconnect failed */
            errno = EPIPE;
            return -1;
        }
        /* FIXME: register watches again */
    }
    return h->fd;
#endif
}

char *qdb_read_watch(qdb_handle_t h) {
    struct qdb_hdr hdr;
    struct path_list *w;
    char *ret = NULL;
    int len;

    if (!h)
        return 0;

    /** already received event */
    if (h->watch_list) {
        w = h->watch_list;
        h->watch_list = w->next;
        ret = w->path;
        free(w);
    } else {
#ifdef WIN32
        len = sizeof(hdr);
        if (!QioReadBuffer(h->read_pipe, &hdr, sizeof(hdr))) {
#else
        if ((len=read(h->fd, &hdr, sizeof(hdr))) < (int)sizeof(hdr)) {
#endif
            if (len==0)
                errno = EPIPE;
            return NULL;
        }
        /* only MULTIREAD is handled with multiple qdb_* calls, so if this
         * isn't WATCH we missed something */
        assert(hdr.type == QDB_RESP_WATCH);
        ret = strdup(hdr.path);
    }
    return ret;
}

#ifdef WIN32
void qdb_free(void *p) {
    free(p);
}
#endif
