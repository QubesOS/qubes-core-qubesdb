/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <qubesdb.h>
#include "qubesdb_internal.h"

struct libvchan {
    struct qdb_hdr input;
    int input_ready;
    char output[4096];
    size_t output_len;
};

int libvchan_buffer_space(libvchan_t *vchan) {
    return sizeof(vchan->output) - vchan->output_len;
}

int libvchan_write(libvchan_t *vchan, const void *data, size_t size) {
    assert(size <= (size_t)libvchan_buffer_space(vchan));
    memcpy(vchan->output + vchan->output_len, data, size);
    vchan->output_len += size;
    return size;
}

int libvchan_data_ready(libvchan_t *vchan) {
    return vchan->input_ready ? sizeof(vchan->input) : 0;
}

int libvchan_recv(libvchan_t *vchan, void *data, size_t size) {
    assert(vchan->input_ready && size == sizeof(vchan->input));
    memcpy(data, &vchan->input, size);
    vchan->input_ready = 0;
    return size;
}

void libvchan_close(libvchan_t *vchan) {
    (void)vchan;
    assert(!"unexpected vchan close");
}

struct test_client {
    struct client client;
    int peer_fd;
};

static char *watch_paths[] = {
    "/", "/dir/", "/dir/key", "/dir/sub/", "/dir/sub/key",
    "/other/", "/dir",
};

static char *key_paths[] = {
    "/dir", "/dir/key", "/dir/sub/key", "/dir/sub/second",
    "/directory/key", "/other/key",
};

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

struct fixture {
    struct db_daemon_data daemon;
    struct libvchan vchan;
    struct test_client writer;
    struct test_client watchers[ARRAY_SIZE(watch_paths)];
};

static struct qdb_hdr header(int type, const char *path) {
    struct qdb_hdr hdr = { .type = type };
    assert(strlen(path) < sizeof(hdr.path));
    strcpy(hdr.path, path);
    return hdr;
}

static void init_client(struct test_client *client) {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    client->client.fd = sockets[0];
    client->peer_fd = sockets[1];
    client->client.can_write = 1;
    client->client.write_queue = buffer_create();
    assert(client->client.write_queue);
}

static void close_client(struct test_client *client) {
    assert(buffer_datacount(client->client.write_queue) == 0);
    close(client->client.fd);
    if (client->peer_fd >= 0)
        close(client->peer_fd);
    buffer_free(client->client.write_queue);
}

static struct qdb_hdr receive_header(int fd) {
    struct qdb_hdr hdr;
    size_t received = 0;
    while (received < sizeof(hdr)) {
        ssize_t count = recv(fd, (char *)&hdr + received,
                sizeof(hdr) - received, MSG_DONTWAIT);
        assert(count > 0);
        received += count;
    }
    assert(hdr.data_len == 0);
    return hdr;
}

static void expect_header(int fd, int type, const char *path) {
    struct qdb_hdr hdr = receive_header(fd);
    if (hdr.type != type || strcmp(hdr.path, path) != 0)
        fprintf(stderr, "expected message %d for %s, got %d for %s\n",
                type, path, hdr.type, hdr.path);
    assert(hdr.type == type);
    assert(strcmp(hdr.path, path) == 0);
}

static void expect_empty(int fd) {
    char byte;
    assert(recv(fd, &byte, sizeof(byte), MSG_DONTWAIT) == -1);
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
}

static void watch(struct fixture *f, struct test_client *client,
        const char *path) {
    struct qdb_hdr hdr = header(QDB_CMD_WATCH, path);
    assert(handle_client_data(&f->daemon, &client->client,
                (char *)&hdr, sizeof(hdr)) == 1);
    expect_header(client->peer_fd, QDB_RESP_OK, path);
    expect_empty(client->peer_fd);
}

static void setup(struct fixture *f) {
    size_t i;
    memset(f, 0, sizeof(*f));
    f->daemon.db = qubesdb_init(write_client_buffered);
    f->daemon.vchan = &f->vchan;
    f->daemon.remote_connected = 1;
    f->daemon.vchan_buffer = buffer_create();
    f->daemon.vchan_pending_hdr.type = QDB_INVALID_CMD;
    assert(f->daemon.db && f->daemon.vchan_buffer);
    init_client(&f->writer);
    for (i = 0; i < ARRAY_SIZE(key_paths); i++)
        assert(qubesdb_write(f->daemon.db, key_paths[i], "value", 5));
    for (i = 0; i < ARRAY_SIZE(watch_paths); i++) {
        init_client(&f->watchers[i]);
        watch(f, &f->watchers[i], watch_paths[i]);
    }
}

static void teardown(struct fixture *f) {
    size_t i;
    for (i = 0; i < ARRAY_SIZE(watch_paths); i++) {
        assert(handle_client_disconnect(&f->daemon,
                    &f->watchers[i].client));
        expect_empty(f->watchers[i].peer_fd);
        close_client(&f->watchers[i]);
    }
    assert(handle_client_disconnect(&f->daemon, &f->writer.client));
    if (f->writer.peer_fd >= 0)
        expect_empty(f->writer.peer_fd);
    close_client(&f->writer);
    assert(!f->daemon.db->watches);
    assert(!f->vchan.input_ready);
    assert(f->vchan.output_len == 0);
    assert(buffer_datacount(f->daemon.vchan_buffer) == 0);
    qubesdb_destroy(f->daemon.db);
    buffer_free(f->daemon.vchan_buffer);
}

static void remove_path(struct fixture *f, const char *path, int remote,
        int response) {
    struct qdb_hdr hdr = header(QDB_CMD_RM, path);
    if (remote) {
        struct qdb_hdr reply;
        f->vchan.input = hdr;
        f->vchan.input_ready = 1;
        assert(handle_vchan_data(&f->daemon) == 1);
        assert(f->vchan.output_len == sizeof(reply));
        memcpy(&reply, f->vchan.output, sizeof(reply));
        assert(reply.type == response && reply.data_len == 0);
        assert(strcmp(reply.path, path) == 0);
        f->vchan.output_len = 0;
    } else {
        struct qdb_hdr replicated;
        assert(handle_client_data(&f->daemon, &f->writer.client,
                    (char *)&hdr, sizeof(hdr)) == 1);
        expect_header(f->writer.peer_fd, response, path);
        expect_empty(f->writer.peer_fd);
        if (response == QDB_RESP_OK) {
            assert(f->vchan.output_len == sizeof(replicated));
            memcpy(&replicated, f->vchan.output, sizeof(replicated));
            assert(replicated.type == QDB_CMD_RM && replicated.data_len == 0);
            assert(strcmp(replicated.path, path) == 0);
        } else {
            assert(f->vchan.output_len == 0);
        }
        f->vchan.output_len = 0;
    }
}

/* Expected recipients are explicit, so the test does not repeat watch matching. */
static void expect_key_events(struct fixture *f) {
    expect_header(f->watchers[0].peer_fd, QDB_RESP_WATCH, "/dir/key");
    expect_header(f->watchers[1].peer_fd, QDB_RESP_WATCH, "/dir/key");
    expect_header(f->watchers[2].peer_fd, QDB_RESP_WATCH, "/dir/key");
}

static void expect_subdir_events(struct fixture *f) {
    size_t i;
    for (i = 0; i < 2; i++) {
        expect_header(f->watchers[i].peer_fd, QDB_RESP_WATCH, "/dir/sub/key");
        expect_header(f->watchers[i].peer_fd, QDB_RESP_WATCH, "/dir/sub/second");
    }
    expect_header(f->watchers[3].peer_fd, QDB_RESP_WATCH, "/dir/sub/key");
    expect_header(f->watchers[3].peer_fd, QDB_RESP_WATCH, "/dir/sub/second");
    expect_header(f->watchers[4].peer_fd, QDB_RESP_WATCH, "/dir/sub/key");
}

static void test_remove(int remote, const char *path) {
    struct fixture f;
    int root = strcmp(path, "/") == 0;
    int directory = strcmp(path, "/dir/") == 0;
    int subdir = strcmp(path, "/dir/sub/") == 0;
    size_t i;

    setup(&f);
    remove_path(&f, path, remote, QDB_RESP_OK);
    if (root) {
        expect_header(f.watchers[0].peer_fd, QDB_RESP_WATCH, "/dir");
        expect_header(f.watchers[6].peer_fd, QDB_RESP_WATCH, "/dir");
    }
    if (!subdir)
        expect_key_events(&f);
    if (root || directory || subdir)
        expect_subdir_events(&f);
    if (root) {
        expect_header(f.watchers[0].peer_fd, QDB_RESP_WATCH, "/directory/key");
        expect_header(f.watchers[0].peer_fd, QDB_RESP_WATCH, "/other/key");
        expect_header(f.watchers[5].peer_fd, QDB_RESP_WATCH, "/other/key");
    }
    for (i = 0; i < ARRAY_SIZE(key_paths); i++) {
        int removed = root ||
            (directory && i >= 1 && i <= 3) ||
            (subdir && i >= 2 && i <= 3) ||
            (!directory && !subdir && i == 1);
        assert(!!qubesdb_search(f.daemon.db, key_paths[i], 1) == !removed);
    }
    for (i = 0; i < ARRAY_SIZE(watch_paths); i++)
        expect_empty(f.watchers[i].peer_fd);

    /* A repeated remote removal is acknowledged, but no key changed again. */
    remove_path(&f, path, remote,
            remote ? QDB_RESP_OK : QDB_RESP_ERROR_NOENT);
    teardown(&f);
}

static void test_duplicate_watches(void) {
    struct fixture f;
    setup(&f);
    watch(&f, &f.watchers[2], "/dir/key");
    remove_path(&f, "/dir/", 0, QDB_RESP_OK);
    expect_key_events(&f);
    expect_header(f.watchers[2].peer_fd, QDB_RESP_WATCH, "/dir/key");
    expect_subdir_events(&f);
    teardown(&f);
}

static void test_watching_client_removes_key(void) {
    struct fixture f;
    struct qdb_hdr hdr = header(QDB_CMD_RM, "/dir/key");

    setup(&f);
    assert(handle_client_data(&f.daemon, &f.watchers[2].client,
                (char *)&hdr, sizeof(hdr)) == 1);
    /* Keep the reply first, so the client's watch fd remains readable. */
    expect_header(f.watchers[2].peer_fd, QDB_RESP_OK, "/dir/key");
    expect_header(f.watchers[2].peer_fd, QDB_RESP_WATCH, "/dir/key");
    expect_header(f.watchers[0].peer_fd, QDB_RESP_WATCH, "/dir/key");
    expect_header(f.watchers[1].peer_fd, QDB_RESP_WATCH, "/dir/key");
    assert(f.vchan.output_len == sizeof(hdr));
    memcpy(&hdr, f.vchan.output, sizeof(hdr));
    assert(hdr.type == QDB_CMD_RM && hdr.data_len == 0);
    assert(strcmp(hdr.path, "/dir/key") == 0);
    f.vchan.output_len = 0;
    teardown(&f);
}

static void test_reply_failure(void) {
    struct fixture f;
    struct qdb_hdr hdr = header(QDB_CMD_RM, "/dir/");

    setup(&f);
    close(f.writer.peer_fd);
    f.writer.peer_fd = -1;
    assert(handle_client_data(&f.daemon, &f.writer.client,
                (char *)&hdr, sizeof(hdr)) == 0);
    expect_key_events(&f);
    expect_subdir_events(&f);
    /* The deleted entries must be freed even when the reply fails. */
    assert(!qubesdb_search(f.daemon.db, "/dir/key", 1));
    assert(!qubesdb_search(f.daemon.db, "/dir/sub/key", 1));
    assert(!qubesdb_search(f.daemon.db, "/dir/sub/second", 1));
    assert(f.vchan.output_len == sizeof(hdr));
    memcpy(&hdr, f.vchan.output, sizeof(hdr));
    assert(hdr.type == QDB_CMD_RM && hdr.data_len == 0);
    assert(strcmp(hdr.path, "/dir/") == 0);
    f.vchan.output_len = 0;
    teardown(&f);
}

int main(void) {
    int remote;
    assert(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    for (remote = 0; remote <= 1; remote++) {
        test_remove(remote, "/dir/key");
        test_remove(remote, "/dir/");
        test_remove(remote, "/dir/sub/");
        test_remove(remote, "/");
    }
    test_duplicate_watches();
    test_watching_client_removes_key();
    test_reply_failure();
    puts("recursive deletion watch tests passed");
    return 0;
}
