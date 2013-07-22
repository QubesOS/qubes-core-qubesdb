#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>


#include <libvchan.h>

#include <qubesdb.h>
#include "qubesdb_internal.h"

/** Check if given string matches path specification (i.e. have only allowed
 * characters). This function allows for '/' at the end, so if particular
 * command doesn't permit so, appropriate handle_* function should additionally
 * check for it.
 * @param path String to check
 * @return 1 if everything is OK, 0 if path is invalid
 */
int verify_path(char *path) {
    int i;
    int path_len;

    path_len = strlen(path);
    if (path_len >= QDB_MAX_PATH)
        return 0;
    for (i = 0; i < path_len; i++) {
        if (path[i] == 0)
            break;
        if (path[i] >= 'a' && path[i] <= 'z')
            continue;
        if (path[i] >= 'Z' && path[i] <= 'Z')
            continue;
        if (path[i] >= '0' && path[i] <= '9')
            continue;
        switch (path[i]) {
            case '_':
            case '-':
            case '/':
            case '.':
            case ':':
                break;
            default:
                /* forbidden character in path */
                return 0;
        }
    }
    return 1;
}

/** Check if given data doesn't contains forbidden characters (currently only
 * \0).
 * @param data Data buffer.
 * @param len Data size
 * @return 1 if everything is OK, 0 if invalid data detected
 */
int verify_data(char *data, int len) {
    int i;

    for (i = 0; i < len; i++) {
        /* forbid NULL byte */
        if (data[i] == 0)
            return 0;
    }
    return 1;
}

/** Sanitize message header.
 * @param untrusted_hdr Header to be checked
 * @param vchan Does message was received via vchan link?
 * @return 1 if OK, 0 if some invalid field value was detected
 */
int verify_hdr(struct qdb_hdr *untrusted_hdr, int vchan) {
    switch (untrusted_hdr->type) {
        case QDB_CMD_WRITE:
        case QDB_CMD_READ:
        case QDB_CMD_RM:
        case QDB_CMD_MULTIREAD:
        case QDB_CMD_LIST:
        case QDB_CMD_WATCH:
        case QDB_CMD_UNWATCH:
            break;
        case QDB_RESP_OK:
        case QDB_RESP_ERROR:
        case QDB_RESP_MULTIREAD:
            /* those messages expected only on vchan daemon interface */
            if (vchan)
                break;
            else
                return 0;
        default:
            /* invalid command */
            return 0;
    }
    /* ensure path is null terminated */
    untrusted_hdr->path[sizeof(untrusted_hdr->path)-1] = '\0';
    if (!verify_path(untrusted_hdr->path))
        return 0;
    if (untrusted_hdr->data_len >= QDB_MAX_DATA)
        return 0;
    return 1;
}

/* write to either client given by fd parameter or vchan if 
 * fd == INVALID_CLIENT_SOCKET
 */
int write_vchan_or_client(struct db_daemon_data *d, client_socket_t fd,
        char *data, int data_len) {
    int ret, count;

    if (fd == INVALID_CLIENT_SOCKET) {
        /* vchan */
        if (!d->vchan)
            /* if vchan not connected, just do nothing */
            return 1;
        if (libvchan_send(d->vchan, data, data_len) < 0) {
            perror("vchan write");
            exit(1);
        }
        return 1;
    } else {
        count = 0;
        while (count < data_len) {
            ret = write(fd, data+count, data_len-count);
            if (ret < 0) {
                perror("client write");
                return 0;
            }
            count += ret;
        }
        return 1;
    }
}

int read_vchan_or_client(struct db_daemon_data *d, client_socket_t fd,
        char *data, int data_len) {
    int ret, count;

    if (fd == INVALID_CLIENT_SOCKET) {
        /* vchan */
        if (!d->vchan)
            /* if vchan not connected, return error */
            return 0;
        if (libvchan_recv(d->vchan, data, data_len) < 0) {
            perror("vchan read");
            exit(1);
        }
        return 1;
    } else {
        count = 0;
        while (count < data_len) {
            ret = read(fd, data+count, data_len-count);
            if (ret < 0) {
                if (errno == ECONNRESET)
                    return 0;
                perror("client read");
                return 0;
            }
            count += ret;
        }
        return 1;
    }
}

/** Discard specified amount of data on given communication channel
 * @param d Daemon global data
 * @param fd From which client discard data. INVALID_CLIENT_SOCKET means vchan.
 * @param amount Size of data to discard in bytes.
 * @return 1 on success, 0 on failure
 */
int discard_data(struct db_daemon_data *d, client_socket_t client, int amount) {
    char buf[256];
    int data_to_read;

    while (amount) {
        data_to_read = amount < sizeof(buf) ? amount : sizeof(buf);
        if (!read_vchan_or_client(d, client, buf, data_to_read))
            return 0;
        amount -= data_to_read;
    }
    return 1;
}

/** Discard 'data' part of message and send QDB_RESP_ERROR. To be used when
 * invalid header detected.
 * @param d Daemon global data
 * @param client Client connection (INVALID_CLIENT_SOCKET means vchan)
 * @param hdr Original header received from client. hdr->data_len bytes will be
 * discarded. WARNING: This struct will be modified to send response.
 * @return 1 on success, 0 on failure (recovery failed and client should be
 * disconnected).
 */
int discard_data_and_send_error(struct db_daemon_data *d, client_socket_t client,
        struct qdb_hdr *hdr) {

    if (discard_data(d, client, hdr->data_len)) {
        hdr->type = QDB_RESP_ERROR;
        hdr->data_len = 0;
        if (write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
            return 1;
    }
    return 0;
}

/** Handle 'write' command. Modify the database and send notification to other
 * vchan side (if command received from local client). After modification (and
 * sending response+notification) appropriate watches are fired.
 * This command is valid on both client socket and vchan, so input data must be
 * handled with special care.
 * @param d Daemon global data
 * @param client Client connection (INVALID_CLIENT_SOCKET means vchan)
 * @param hdr Original header received from client.
 *        WARNING: This struct will be modified to send response.
 * @return 1 on success (message handled and responded, even if response is
 *           error message), 0 if fatal error occured and client should be
 *           disconnected.
 */
int handle_write(struct db_daemon_data *d, client_socket_t client,
        struct qdb_hdr *hdr) {
    char untrusted_data[QDB_MAX_DATA];
    char *data;

    if (!read_vchan_or_client(d, client, untrusted_data, hdr->data_len)) {
        return 0;
    }

    if (!verify_data(untrusted_data, hdr->data_len)) {
        fprintf(stderr, "invalid data received from peer\n");
        /* recovery path */
        hdr->data_len = 0; // data already received
        return discard_data_and_send_error(d, client, hdr);
    }
    data = untrusted_data;

    if (!qubesdb_write(d->db, hdr->path, data, hdr->data_len)) {
        fprintf(stderr, "failed to write path %s\n", hdr->path);
        hdr->type = QDB_RESP_ERROR;
        hdr->data_len = 0;
        write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr));
        return 0;
    } else {
        if (client != INVALID_CLIENT_SOCKET && d->remote_connected) {
            /* if write was from local client, duplicate it through vchan */
            write_vchan_or_client(d, INVALID_CLIENT_SOCKET,
                    (char*)hdr, sizeof(*hdr));
            write_vchan_or_client(d, INVALID_CLIENT_SOCKET,
                    data, hdr->data_len);
        }
        hdr->type = QDB_RESP_OK;
        hdr->data_len = 0;
        if (!write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
            return 0;
        qubesdb_fire_watches(d->db, hdr->path);
        return 1;
    }
}

/** Handle 'rm' command. Modify the database and send notification to other
 * vchan side (if command received from local client). After modification (and
 * sending response+notification) appropriate watches are fired.
 * This command is valid on both client socket and vchan, so input data must be
 * handled with special care.
 * @param d Daemon global data
 * @param client Client connection (INVALID_CLIENT_SOCKET means vchan)
 * @param hdr Original header received from client.
 *        WARNING: This struct will be modified to send response.
 * @return 1 on success (message handled and responded, even if response is
 *           error message), 0 if fatal error occured and client should be
 *           disconnected.
 */
/* this command is valid on both client socket and vchan */
int handle_rm(struct db_daemon_data *d, client_socket_t client,
        struct qdb_hdr *hdr) {

    if (hdr->data_len > 0) {
        fprintf(stderr, "CMD_RM shouldn't have data field\n");
        /* recovery path */
        return discard_data_and_send_error(d, client, hdr);
    }

    if (!qubesdb_remove(d->db, hdr->path)) {
        hdr->type = QDB_RESP_ERROR_NOENT;
        hdr->data_len = 0;
        if (!write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
            return 0;
        /* failed rm received from vchan is fatal - means some database
         * de-synchronization */
        if (client == INVALID_CLIENT_SOCKET)
            return 0;
    } else {
        if (client != INVALID_CLIENT_SOCKET && d->remote_connected) {
            /* if rm was from local client, duplicate it through vchan */
            write_vchan_or_client(d, INVALID_CLIENT_SOCKET,
                    (char*)hdr, sizeof(*hdr));
        }
        hdr->type = QDB_RESP_OK;
        hdr->data_len = 0;
        if (!write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
            return 0;
        qubesdb_fire_watches(d->db, hdr->path);
    }
    return 1;
}


/** Handle 'read' command. 
 * This command is only valid local socket.
 * @param d Daemon global data
 * @param client Client connection (INVALID_CLIENT_SOCKET means vchan)
 * @param hdr Original header received from client.
 *        WARNING: This struct will be modified to send response.
 * @return 1 on success (message handled and responded, even if response is
 *           error message), 0 if fatal error occured and client should be
 *           disconnected.
 */
int handle_read(struct db_daemon_data *d, client_socket_t client,
        struct qdb_hdr *hdr) {
    struct qubesdb_entry *db_entry;

    if (hdr->data_len > 0) {
        fprintf(stderr, "CMD_READ shouldn't have data field\n");
        return 0;
    }

    db_entry = qubesdb_search(d->db, hdr->path, 1);
    if (!db_entry) {
        hdr->type = QDB_RESP_ERROR_NOENT;
        hdr->data_len = 0;
        if (!write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
            return 0;
    } else {
        hdr->type = QDB_RESP_READ;
        hdr->data_len = db_entry->value_len;
        if (!write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
            return 0;
        if (!write_vchan_or_client(d, client,
                    db_entry->value, hdr->data_len))
            return 0;
    }
    return 1;
}

/** Handle 'multiread' command. Send all mathing entries. This command is used
 * for initial database synchronization by VM client part.
 * vchan side (if command received from local client).
 * This command is valid on both client socket and vchan, so input data must be
 * handled with special care.
 * @param d Daemon global data
 * @param client Client connection (INVALID_CLIENT_SOCKET means vchan)
 * @param hdr Original header received from client.
 *        WARNING: This struct will be modified to send response.
 * @return 1 on success (message handled and responded, even if response is
 *           error message), 0 if fatal error occured and client should be
 *           disconnected.
 */
int handle_multiread(struct db_daemon_data *d, client_socket_t client,
        struct qdb_hdr *hdr) {
    struct qubesdb_entry *db_entry;
    char search_path[QDB_MAX_PATH];
    int search_path_len;

    if (hdr->data_len > 0) {
        fprintf(stderr, "CMD_MULTIREAD shouldn't have data field\n");
        /* recovery path */
        return discard_data_and_send_error(d, client, hdr);
    }

    strncpy(search_path, hdr->path, QDB_MAX_PATH);
    search_path_len = strlen(search_path);

    hdr->type = QDB_RESP_MULTIREAD;

    if (search_path_len) {
        db_entry = qubesdb_search(d->db, search_path, 0);
    } else {
        /* if full database requested, dump in reverser order so insertion-sort
         * on the other side will be more efficient */
        db_entry = d->db->entries->prev;
    }
    while (db_entry != d->db->entries &&
             strncmp(db_entry->path, search_path, search_path_len) == 0) {
        strncpy(hdr->path, db_entry->path, sizeof(hdr->path));
        hdr->data_len = db_entry->value_len;
        if (!write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
            return 0;
        if (!write_vchan_or_client(d, client,
                    db_entry->value, hdr->data_len))
            return 0;
        if (search_path_len)
            db_entry = db_entry->next;
        else
            db_entry = db_entry->prev;
    }
    /* end of data */
    hdr->data_len = 0;
    hdr->path[0] = 0;
    if (!write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
        return 0;
    return 1;
}

/** Handle 'list' command. Send list of paths matching given prefix.
 * This command is only valid local socket.
 * @param d Daemon global data
 * @param client Client connection (INVALID_CLIENT_SOCKET means vchan)
 * @param hdr Original header received from client.
 *        WARNING: This struct will be modified to send response.
 * @return 1 on success (message handled and responded, even if response is
 *           error message), 0 if fatal error occured and client should be
 *           disconnected.
 */
int handle_list(struct db_daemon_data *d, client_socket_t client,
        struct qdb_hdr *hdr) {
    struct qubesdb_entry *db_entry;
    char search_path[QDB_MAX_PATH];
    int search_path_len;

    if (hdr->data_len > 0) {
        fprintf(stderr, "CMD_LIST shouldn't have data field\n");
        /* recovery path */
        return discard_data_and_send_error(d, client, hdr);
    }

    strncpy(search_path, hdr->path, QDB_MAX_PATH);
    search_path_len = strlen(search_path);

    hdr->type = QDB_RESP_LIST;

    db_entry = qubesdb_search(d->db, search_path, 0);
    while (db_entry != d->db->entries && 
             strncmp(db_entry->path, search_path, search_path_len) == 0) {
        strncpy(hdr->path, db_entry->path, sizeof(hdr->path));
        hdr->data_len = 0;
        if (!write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
            return 0;
        db_entry = db_entry->next;
    }
    /* end of data */
    hdr->data_len = 0;
    hdr->path[0] = 0;
    if (!write_vchan_or_client(d, client, (char*)hdr, sizeof(*hdr)))
        return 0;
    return 1;
}

/** Handle single response to 'multiread' command. This incoming message is
 * valid only on vchan and is used only for initial database synchronization.
 * Modify the database but do not send any notigications nor fire watches.
 * @param d Daemon global data
 * @param client Client connection (INVALID_CLIENT_SOCKET means vchan)
 * @param hdr Original header received from client.
 * @return 1 on success, 0 if fatal error occured and client should be
 *           disconnected.
 */
int handle_vchan_multiread_resp(struct db_daemon_data *d, struct qdb_hdr *hdr) {
    char data[QDB_MAX_DATA];

    if (hdr->data_len && libvchan_recv(d->vchan, data, hdr->data_len) < 0) {
        perror("vchan read");
        return 0;
    }

    if (hdr->path[0] == '\0') {
        /* empty path - end of data */
        d->multiread_requested = 0;
        return 1;
    }

    if (!verify_data(data, hdr->data_len)) {
        fprintf(stderr, "invalid data received from peer\n");
        return 0;
    }

    if (!qubesdb_write(d->db, hdr->path, data, hdr->data_len)) {
        fprintf(stderr, "failed to insert entry\n");
        return 0;
    }
    /* do not fire watches on initial data dump */
    return 1;
}


/** Handle new vchan command. This functions is called every time when any new
 * vchan command is detected (but not yet read). It receives data from other
 * vchan peer, carefully verify its contents and call appropriate handle
 * function. Any error in processing vchan data should be considered fatal.
 * @param d Daemon global data
 * @return 1 on success (message handled and responded), 0 if error
 *           occured and client should be disconnected.
 */
int handle_vchan_data(struct db_daemon_data *d) {
    struct qdb_hdr untrusted_hdr;
    struct qdb_hdr hdr;

    if (libvchan_recv(d->vchan, &untrusted_hdr, sizeof(untrusted_hdr)) < 0) {
        perror("vchan read");
        return 0;
    }
    if (!verify_hdr(&untrusted_hdr, 1)) {
        fprintf(stderr, "invalid message received from peer\n");
        return 0;
    }
    hdr = untrusted_hdr;

    switch (hdr.type) {
        case QDB_CMD_WRITE:
            if (!handle_write(d, INVALID_CLIENT_SOCKET, &hdr))
                return 0;
            break;
        case QDB_CMD_MULTIREAD:
            if (!handle_multiread(d, INVALID_CLIENT_SOCKET, &hdr))
                return 0;
            /* remote have synchronized database, send furher updates */
            d->remote_connected = 1;
            break;

        case QDB_CMD_RM:
            if (!handle_rm(d, INVALID_CLIENT_SOCKET, &hdr))
                return 0;
            break;

        case QDB_RESP_OK:
            break;
        case QDB_RESP_ERROR:
            fprintf(stderr, "received error from peer\n");
            if (hdr.data_len) {
                fprintf(stderr, "FATAL: error packet contains some unexpected data\n");
                return 0;
            }
            break;
        case QDB_RESP_MULTIREAD:
            if (d->multiread_requested) {
                if (!handle_vchan_multiread_resp(d, &hdr))
                    return 0;
            } else {
                fprintf(stderr, "spurious MULTIREAD response\n");
                return 0;
            }
            break;
        default:
            fprintf(stderr, "unexpected command from peer: %d\n", hdr.type);
            return 0;
    }
    return 1;
}

/** Handle data from client; if some data already received by caller, pass it
 * via data+data_len parameters.
 * @param d Daemon global data
 * @param client Client socket from which handle command
 * @param data Data buffer already received from client. Must be no more than
 *             sizeof(struct qdb_hdr).
 * @param data_len Size of filled buffer in 'data'
 * @return 1 on success (message handled and responded, even if response is
 *           error message), 0 if fatal error occured and client should be
 *           disconnected.
 */
int handle_client_data(struct db_daemon_data *d, client_socket_t client,
        char *data, int data_len) {
    struct qdb_hdr hdr;
    int ret = 1;

    if (data_len > sizeof(hdr)) {
        fprintf(stderr, "BUG(handle_client_data): caller passed more data than "
                "header size, cannot continue\n");
        exit(1);
    }
    memcpy(&hdr, data, data_len);
    /* TODO: OS dependent call */
    if ((ret=read(client, ((char*)&hdr)+data_len, sizeof(hdr)-data_len)) < 0) {
        if (errno == ECONNRESET)
            return 0;
        perror("read from client");
        return 0;
    }
    if (ret+data_len == 0) {
        /* EOF */
        return 0;
    }

    if (!verify_hdr(&hdr, 0)) {
        fprintf(stderr, "invalid message received from client %d\n", client);
        /* recovery path */
        return discard_data_and_send_error(d, client, &hdr);
    }


    switch (hdr.type) {
        case QDB_CMD_READ:
            ret = handle_read(d, client, &hdr);
            break;

        case QDB_CMD_WRITE:
            ret = handle_write(d, client, &hdr);
            break;

        case QDB_CMD_MULTIREAD:
            ret = handle_multiread(d, client, &hdr);
            break;

        case QDB_CMD_LIST:
            ret = handle_list(d, client, &hdr);
            break;

        case QDB_CMD_RM:
            ret = handle_rm(d, client, &hdr);
            break;

        case QDB_CMD_WATCH:
            ret = qubesdb_add_watch(d->db, hdr.path, client);
            hdr.type = ret ? QDB_RESP_OK : QDB_RESP_ERROR;
            hdr.data_len = 0;
            if (!write_vchan_or_client(d, client, (char*)&hdr, sizeof(hdr)))
                ret = 0;
            break;

        case QDB_CMD_UNWATCH:
            ret = qubesdb_remove_watch(d->db, hdr.path, client);
            hdr.type = ret ? QDB_RESP_OK : QDB_RESP_ERROR_NOENT;
            hdr.data_len = 0;
            /* NOENT isn't fatal */
            ret = 1;
            if (!write_vchan_or_client(d, client, (char*)&hdr, sizeof(hdr)))
                ret = 0;
            break;

        default:
            fprintf(stderr, "unexpected command from peer: %d\n", hdr.type);
            /* recovery path */
            return discard_data_and_send_error(d, client, &hdr);
    }
    return ret;
}

int handle_client_connect(struct db_daemon_data *d, client_socket_t client) {
    /* currently nothing */
    return 1;
}

int handle_client_disconnect(struct db_daemon_data *d, client_socket_t client) {
    /* remove all watches owned by this client */
    qubesdb_remove_watch(d->db, NULL, client);
    return 1;
}

int request_full_db_sync(struct db_daemon_data *d) {
    struct qdb_hdr hdr;

    hdr.type = QDB_CMD_MULTIREAD;
    hdr.path[0] = 0;
    hdr.data_len = 0;
    
    return write_vchan_or_client(d, INVALID_CLIENT_SOCKET, (char*)&hdr, sizeof(hdr));
}
