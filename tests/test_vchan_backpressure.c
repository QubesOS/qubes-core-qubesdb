/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Include the daemon so the tests run its event loop and startup sync wait. */
static int test_ppoll(struct pollfd *, nfds_t, const struct timespec *,
        const sigset_t *);
#define ppoll test_ppoll
#define main qubesdb_daemon_main
#include "../daemon/db-daemon.c"
#undef main
#undef ppoll

struct libvchan {
    char input[8192];
    int input_left;
    int input_offset;
    int output_space;
    char output[4096];
    size_t output_len;
    int event_pipe[2];
    void (*on_wait)(libvchan_t *);
    libvchan_t *peer;
    size_t received_bytes;
    int legacy_rm_guard;
};

static void (*poll_hook)(struct pollfd *, nfds_t);

static int test_ppoll(struct pollfd *fds, nfds_t nfds,
        const struct timespec *timeout, const sigset_t *mask) {
    (void)timeout;
    (void)mask;
    assert(poll_hook);
    poll_hook(fds, nfds);
    return 1;
}

int libvchan_buffer_space(libvchan_t *vchan) {
    return vchan->output_space;
}

int libvchan_write(libvchan_t *vchan, const void *data, size_t size) {
    assert(size <= (size_t)vchan->output_space);
    assert(size <= sizeof(vchan->output) - vchan->output_len);
    memcpy(vchan->output + vchan->output_len, data, size);
    vchan->output_len += size;
    vchan->output_space -= size;
    return size;
}

int libvchan_recv(libvchan_t *vchan, void *data, size_t size) {
    if (vchan->peer) {
        libvchan_t *source = vchan->peer;
        assert(size <= source->output_len);
        memcpy(data, source->output, size);
        source->output_len -= size;
        memmove(source->output, source->output + size, source->output_len);
        /* Ring capacity returns only when the receiver reads the bytes. */
        source->output_space += size;
        assert(source->output_space <= sizeof(source->output));
    } else {
        assert(size <= (size_t)vchan->input_left);
        memcpy(data, vchan->input + vchan->input_offset, size);
        vchan->input_left -= size;
        vchan->input_offset += size;
    }
    vchan->received_bytes += size;
    return size;
}

void libvchan_close(libvchan_t *vchan) {
    (void)vchan;
    assert(!"output pressure must not reset the connection");
}

libvchan_t *libvchan_server_init(int domain, int port, size_t read_min,
        size_t write_min) {
    (void)domain;
    (void)port;
    (void)read_min;
    (void)write_min;
    assert(!"unexpected reconnection");
    return NULL;
}

libvchan_t *libvchan_client_init(int domain, int port) {
    (void)domain;
    (void)port;
    assert(!"unexpected reconnection");
    return NULL;
}

int libvchan_is_open(libvchan_t *vchan) {
    (void)vchan;
    return 1;
}

int libvchan_fd_for_select(libvchan_t *vchan) {
    return vchan->event_pipe[0];
}

int libvchan_wait(libvchan_t *vchan) {
    if (vchan->on_wait)
        vchan->on_wait(vchan);
    return 0;
}

int libvchan_data_ready(libvchan_t *vchan) {
    return vchan->peer ? vchan->peer->output_len : vchan->input_left;
}

static void setup(struct db_daemon_data *d, struct libvchan *vchan) {
    memset(d, 0, sizeof(*d));
    memset(vchan, 0, sizeof(*vchan));
    assert(pipe(vchan->event_pipe) == 0);
    d->remote_name = "test-vm";
    d->remote_connected = 1;
    d->rw_socket_fd = d->ro_socket_fd = -1;
    d->vchan = vchan;
    d->vchan_buffer = buffer_create();
    d->vchan_pending_hdr.type = QDB_INVALID_CMD;
    d->db = qubesdb_init(NULL);
    assert(d->vchan_buffer && d->db);
}

static void teardown(struct db_daemon_data *d) {
    close(d->vchan->event_pipe[0]);
    close(d->vchan->event_pipe[1]);
    clear_vchan_sync(d);
    qubesdb_destroy(d->db);
    buffer_free(d->vchan_buffer);
    buffer_free(d->vchan_reply_buffer);
}

static void request(struct libvchan *vchan, int type) {
    struct qdb_hdr hdr = { .type = type };
    strcpy(hdr.path, "/same-key");
    memcpy(vchan->input, &hdr, sizeof(hdr));
    vchan->input_offset = 0;
    vchan->input_left = sizeof(hdr);
}

static void test_guest_requests_wait_for_output(void) {
    struct db_daemon_data d;
    struct libvchan vchan;
    int types[] = { QDB_CMD_RM, QDB_CMD_WRITE };
    size_t i;

    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        setup(&d, &vchan);
        while (!vchan_requests_paused(&d)) {
            request(&vchan, types[i]);
            assert(handle_vchan_data(&d) == 1);
            assert(vchan.input_left == 0);
        }
        assert(buffer_datacount(d.vchan_reply_buffer) <=
                VCHAN_BUFFER_HIGH_WATER);
        assert(buffer_datacount(d.vchan_buffer) == 0);
        request(&vchan, types[i]);
        assert(handle_vchan_data(&d) == 2);
        assert(vchan.input_left == 0);
        assert(d.vchan_pending_hdr.type == types[i]);

        vchan.output_space = sizeof(vchan.output);
        assert(write_vchan_or_client(&d, NULL, NULL, 0));
        assert(!vchan_requests_paused(&d));
        assert(handle_vchan_data(&d) == 1);
        assert(vchan.input_left == 0);
        teardown(&d);
    }
}

static void test_paused_write_preserves_its_payload(void) {
    struct db_daemon_data d;
    struct libvchan vchan;
    struct qdb_hdr hdr = { .type = QDB_RESP_OK };
    struct qubesdb_entry *entry;

    setup(&d, &vchan);
    while (!vchan_requests_paused(&d))
        assert(write_vchan_or_client(&d, NULL, (char *)&hdr, sizeof(hdr)));
    hdr.type = QDB_CMD_WRITE;
    hdr.data_len = 3;
    strcpy(hdr.path, "/paused");
    memcpy(vchan.input, &hdr, sizeof(hdr));
    memcpy(vchan.input + sizeof(hdr), "new", 3);
    vchan.input_left = sizeof(hdr) + 3;
    assert(handle_vchan_data(&d) == 2);
    assert(d.vchan_pending_hdr.type == QDB_CMD_WRITE);
    assert(vchan.input_left == 3);
    assert(!qubesdb_search(d.db, "/paused", 1));
    assert(handle_vchan_data(&d) == 2);
    assert(vchan.input_left == 3);
    vchan.output_space = sizeof(vchan.output);
    assert(write_vchan_or_client(&d, NULL, NULL, 0));
    assert(!vchan_requests_paused(&d));
    assert(handle_vchan_data(&d) == 1);
    assert(vchan.input_left == 0);
    assert(d.vchan_pending_hdr.type == QDB_INVALID_CMD);
    entry = qubesdb_search(d.db, "/paused", 1);
    assert(entry && entry->value_len == 3);
    assert(memcmp(entry->value, "new", 3) == 0);
    teardown(&d);
}

static void test_partial_output_keeps_byte_order(void) {
    struct db_daemon_data d;
    struct libvchan vchan;
    char first[] = "first";
    char second[] = "second";

    setup(&d, &vchan);
    d.remote_name = NULL;
    vchan.output_space = 2;
    assert(write_vchan_or_client(&d, NULL, first, sizeof(first)));
    assert(buffer_datacount(d.vchan_buffer) == sizeof(first) - 2);
    assert(write_vchan_or_client(&d, NULL, second, sizeof(second)));
    vchan.output_space = sizeof(first) + sizeof(second) - 2;
    assert(write_vchan_or_client(&d, NULL, NULL, 0));
    assert(buffer_datacount(d.vchan_buffer) == 0);
    assert(vchan.output_len == sizeof(first) + sizeof(second));
    assert(memcmp(vchan.output, first, sizeof(first)) == 0);
    assert(memcmp(vchan.output + sizeof(first), second, sizeof(second)) == 0);
    teardown(&d);
}

static void test_buffer_size_arithmetic(void) {
    struct buffer *b = buffer_create();
    char data = 'x';

    assert(b);
    b->data_count = INT_MAX;
    errno = 0;
    assert(!buffer_append(b, &data, 1));
    assert(errno == ENOSPC);
    b->data_count = 0;
    assert(buffer_reserve_limited(b, 10, 10));
    assert(buffer_datacount(b) == 0);
    assert(!buffer_reserve_limited(b, 11, 10));
    buffer_free(b);
}

static int local_request(struct db_daemon_data *d, int type,
        const char *path, const char *value, int len) {
    int fds[2];
    struct client c = { .can_write = 1 };
    struct qdb_hdr hdr = { .type = type, .data_len = len };

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    c.fd = fds[0];
    c.write_queue = buffer_create();
    assert(c.write_queue);
    strcpy(hdr.path, path);
    if (len)
        assert(write(fds[1], value, len) == len);
    assert(handle_client_data(d, &c, (char *)&hdr, sizeof(hdr)));
    assert(read(fds[1], &hdr, sizeof(hdr)) == sizeof(hdr));
    assert(hdr.data_len == 0);
    close(fds[0]);
    close(fds[1]);
    buffer_free(c.write_queue);
    return hdr.type;
}

static void consume(struct db_daemon_data *d) {
    while (libvchan_data_ready(d->vchan) ||
            d->vchan_pending_hdr.type != QDB_INVALID_CMD) {
        int ret;
        /* Reproduce the response-space guard in the older guest handler.
         * The full historical handler is also checked separately. */
        if (d->vchan->legacy_rm_guard) {
            struct qdb_hdr hdr = d->vchan_pending_hdr;
            if (hdr.type == QDB_INVALID_CMD &&
                    libvchan_data_ready(d->vchan) >= sizeof(hdr))
                memcpy(&hdr, d->vchan->peer->output, sizeof(hdr));
            if (hdr.type == QDB_CMD_RM)
                assert(libvchan_buffer_space(d->vchan) >= sizeof(hdr));
        }
        ret = handle_vchan_data(d);
        assert(ret);
        if (ret == 2)
            break;
    }
}

/* Both rings have 4 KiB capacity. Only libvchan_recv() frees their space. */
static void pump(struct db_daemon_data *dom0, struct db_daemon_data *guest) {
    struct libvchan *out = dom0->vchan;
    struct libvchan *in = guest->vchan;
    int count;

    if (!out->peer) {
        assert(!out->input_left && !in->input_left);
        out->peer = in;
        in->peer = out;
        out->output_space = sizeof(out->output) - out->output_len;
        in->output_space = sizeof(in->output) - in->output_len;
    }
    /* Match the event loop: consume incoming acknowledgments before
     * transmitting another batch of commands to the guest. */
    consume(dom0);
    assert(write_vchan_or_client(dom0, NULL, NULL, 0));
    count = buffer_datacount(dom0->vchan_buffer);
    if (dom0->vchan_sync_buffer)
        count += buffer_datacount(dom0->vchan_sync_buffer);
    if (dom0->vchan_reply_buffer)
        count += buffer_datacount(dom0->vchan_reply_buffer);
    assert(count <= VCHAN_BUFFER_LIMIT);
    assert(write_vchan_or_client(guest, NULL, NULL, 0));
}

static void drain(struct db_daemon_data *dom0, struct db_daemon_data *guest) {
    while (dom0->vchan_sync_buffer || buffer_datacount(dom0->vchan_buffer) ||
            (dom0->vchan_reply_buffer && buffer_datacount(dom0->vchan_reply_buffer)) ||
            buffer_datacount(guest->vchan_buffer) || dom0->vchan->output_len ||
            guest->vchan->output_len) {
        pump(dom0, guest);
        consume(guest);
    }
    assert(dom0->vchan_pending_hdr.type == QDB_INVALID_CMD);
    assert(guest->vchan_pending_hdr.type == QDB_INVALID_CMD);
}

static void test_removal_burst_consumes_guest_acknowledgments(int mixed) {
    struct db_daemon_data dom0, guest;
    struct libvchan host_vchan, guest_vchan;
    char path[QDB_MAX_PATH];
    int i;

    setup(&dom0, &host_vchan);
    setup(&guest, &guest_vchan);
    guest.remote_name = NULL;
    guest_vchan.legacy_rm_guard = 1;
    for (i = 1999; i >= 0; i--) {
        snprintf(path, sizeof(path), "/key-%04d", i);
        assert(qubesdb_write(dom0.db, path, "old", 3));
        assert(qubesdb_write(guest.db, path, "old", 3));
    }
    /* The stalled guest has not consumed any of these removals. */
    for (i = 0; i < 2000; i++) {
        snprintf(path, sizeof(path), "/key-%04d", i);
        assert(local_request(&dom0, QDB_CMD_RM, path, NULL, 0) == QDB_RESP_OK);
    }
    assert(buffer_datacount(dom0.vchan_buffer) == 2000 * sizeof(struct qdb_hdr));
    pump(&dom0, &guest);
    if (mixed) {
        /* A guest request is ahead of its removal replies in the same ring.
         * Let the older guest fill the response ring before dom0 runs. */
        assert(local_request(&guest, QDB_CMD_WRITE, "/guest-key", "new", 3) ==
                QDB_RESP_OK);
        for (i = 0; i < 55; i++)
            assert(handle_vchan_data(&guest) == 1);
    } else {
        consume(&guest);
    }
    assert(buffer_datacount(dom0.vchan_buffer) >= VCHAN_BUFFER_HIGH_WATER);
    assert(!vchan_requests_paused(&dom0));
    assert(libvchan_buffer_space(&guest_vchan) < sizeof(struct qdb_hdr));
    /* Reach the acknowledgments even when a WRITE precedes them. */
    assert(handle_vchan_data(&dom0) == 1);
    assert(libvchan_buffer_space(&guest_vchan) >= sizeof(struct qdb_hdr));
    drain(&dom0, &guest);
    for (i = 0; i < 2000; i++) {
        snprintf(path, sizeof(path), "/key-%04d", i);
        assert(!qubesdb_search(dom0.db, path, 1));
        assert(!qubesdb_search(guest.db, path, 1));
    }
    if (mixed) {
        struct qubesdb_entry *entry = qubesdb_search(dom0.db, "/guest-key", 1);
        assert(entry && entry->value_len == 3);
        assert(memcmp(entry->value, "new", 3) == 0);
        assert(qubesdb_search(guest.db, "/guest-key", 1));
    }
    assert(host_vchan.received_bytes ==
            (2000 + mixed) * sizeof(struct qdb_hdr) + 3 * mixed);
    assert(guest_vchan.received_bytes ==
            (2000 + mixed) * sizeof(struct qdb_hdr));
    teardown(&guest);
    teardown(&dom0);
}

static void test_pressure_preserves_accepted_deletions(void) {
    struct db_daemon_data dom0, guest;
    struct libvchan host_vchan, guest_vchan;
    char data[QDB_MAX_DATA - 1];
    struct qubesdb_entry *entry;

    memset(data, 'x', sizeof(data));
    setup(&dom0, &host_vchan);
    setup(&guest, &guest_vchan);
    guest.remote_name = NULL;
    assert(qubesdb_write(dom0.db, "/removed", "old", 3));
    assert(qubesdb_write(guest.db, "/removed", "old", 3));
    assert(qubesdb_write(dom0.db, "/retained", "old", 3));
    assert(qubesdb_write(guest.db, "/retained", "old", 3));
    assert(local_request(&dom0, QDB_CMD_RM, "/removed", NULL, 0) == QDB_RESP_OK);
    while (local_request(&dom0, QDB_CMD_WRITE, "/same-key", data,
                sizeof(data)) == QDB_RESP_OK)
        assert(buffer_datacount(dom0.vchan_buffer) <= VCHAN_BUFFER_LIMIT);
    memset(data, 'y', sizeof(data));
    assert(local_request(&dom0, QDB_CMD_WRITE, "/same-key", data,
                sizeof(data)) == QDB_RESP_ERROR);
    entry = qubesdb_search(dom0.db, "/same-key", 1);
    assert(entry && entry->value[0] == 'x');
    /* Fill the remaining room with zero-length writes, then reject RM. */
    while (local_request(&dom0, QDB_CMD_WRITE, "/empty", NULL, 0) == QDB_RESP_OK)
        assert(buffer_datacount(dom0.vchan_buffer) <= VCHAN_BUFFER_LIMIT);
    assert(local_request(&dom0, QDB_CMD_RM, "/retained", NULL, 0) ==
            QDB_RESP_ERROR);
    assert(qubesdb_search(dom0.db, "/retained", 1));
    drain(&dom0, &guest);
    assert(!qubesdb_search(guest.db, "/removed", 1));
    assert(qubesdb_search(guest.db, "/retained", 1));
    entry = qubesdb_search(guest.db, "/same-key", 1);
    assert(entry && entry->value[0] == 'x');
    assert(local_request(&dom0, QDB_CMD_RM, "/retained", NULL, 0) == QDB_RESP_OK);
    drain(&dom0, &guest);
    assert(!qubesdb_search(guest.db, "/retained", 1));
    teardown(&guest);
    teardown(&dom0);
}

/* Reply space remains available after local replication reaches its cap. */
static void test_guest_reply_has_reserved_space_and_packet_priority(void) {
    struct db_daemon_data dom0;
    struct libvchan vchan;
    struct qdb_hdr hdr = { .type = QDB_CMD_WRITE, .data_len = 3 };
    struct qubesdb_entry *entry;
    char data[QDB_MAX_DATA - 1];
    int queued;

    memset(data, 'x', sizeof(data));
    setup(&dom0, &vchan);
    while (local_request(&dom0, QDB_CMD_WRITE, "/host-key", data,
                sizeof(data)) == QDB_RESP_OK)
        ;
    queued = buffer_datacount(dom0.vchan_buffer);
    assert(queued <= VCHAN_BUFFER_LIMIT - VCHAN_BUFFER_HIGH_WATER);
    assert(!vchan_requests_paused(&dom0));
    strcpy(hdr.path, "/guest-key");
    memcpy(vchan.input, &hdr, sizeof(hdr));
    memcpy(vchan.input + sizeof(hdr), "new", 3);
    vchan.input_left = sizeof(hdr) + 3;
    assert(handle_vchan_data(&dom0) == 1);
    entry = qubesdb_search(dom0.db, "/guest-key", 1);
    assert(entry && entry->value_len == 3);
    assert(memcmp(entry->value, "new", 3) == 0);
    assert(buffer_datacount(dom0.vchan_buffer) == queued);
    assert(buffer_datacount(dom0.vchan_reply_buffer) == sizeof(hdr));

    /* A reply overtakes queued commands. A command waits for enough room
     * for its header and payload, so no reply can split that packet. */
    vchan.output_space = sizeof(hdr) + 2;
    assert(write_vchan_or_client(&dom0, NULL, NULL, 0));
    assert(vchan.output_len == sizeof(hdr));
    memcpy(&hdr, vchan.output, sizeof(hdr));
    assert(hdr.type == QDB_RESP_OK);
    assert(strcmp(hdr.path, "/guest-key") == 0);
    assert(buffer_datacount(dom0.vchan_buffer) == queued);
    assert(!buffer_datacount(dom0.vchan_reply_buffer));
    vchan.output_space = sizeof(vchan.output) - vchan.output_len;
    assert(write_vchan_or_client(&dom0, NULL, NULL, 0));
    memcpy(&hdr, vchan.output + sizeof(hdr), sizeof(hdr));
    assert(hdr.type == QDB_CMD_WRITE);
    assert(strcmp(hdr.path, "/host-key") == 0);
    assert(hdr.data_len == sizeof(data));
    assert(memcmp(vchan.output + 2 * sizeof(hdr), data, sizeof(data)) == 0);
    assert(vchan.output_len == 2 * sizeof(hdr) + sizeof(data));
    teardown(&dom0);
}

static void test_full_reply_queue_resumes_request_before_sending_commands(void) {
    struct db_daemon_data dom0;
    struct libvchan vchan;
    struct qdb_hdr hdr = { .type = QDB_CMD_WRITE, .data_len = 3 };
    struct qdb_hdr ack = { .type = QDB_RESP_OK };
    size_t offset;

    setup(&dom0, &vchan);
    while (!vchan_requests_paused(&dom0)) {
        request(&vchan, QDB_CMD_WRITE);
        assert(handle_vchan_data(&dom0) == 1);
    }
    assert(qubesdb_write(dom0.db, "/host-key", "old", 3));
    assert(local_request(&dom0, QDB_CMD_RM, "/host-key", NULL, 0) == QDB_RESP_OK);
    assert(buffer_datacount(dom0.vchan_buffer) == sizeof(hdr));

    strcpy(hdr.path, "/paused");
    memcpy(vchan.input, &hdr, sizeof(hdr));
    memcpy(vchan.input + sizeof(hdr), "new", 3);
    memcpy(vchan.input + sizeof(hdr) + 3, &ack, sizeof(ack));
    vchan.input_offset = 0;
    vchan.input_left = 2 * sizeof(hdr) + 3;
    assert(handle_vchan_data(&dom0) == 2);
    assert(vchan.input_left == sizeof(hdr) + 3);
    assert(!qubesdb_search(dom0.db, "/paused", 1));

    /* Flushing replies frees capacity for the saved WRITE. The replication
     * command must wait while the guest's acknowledgment is still unread. */
    vchan.output_space = sizeof(vchan.output);
    assert(write_vchan_or_client(&dom0, NULL, NULL, 0));
    assert(!vchan_requests_paused(&dom0));
    assert(handle_vchan_data(&dom0) == 1);
    assert(qubesdb_search(dom0.db, "/paused", 1));
    assert(vchan.input_left == sizeof(hdr));
    assert(handle_vchan_data(&dom0) == 1);
    assert(vchan.input_left == 0);
    assert(buffer_datacount(dom0.vchan_buffer) == sizeof(hdr));
    assert(buffer_datacount(dom0.vchan_reply_buffer) <= VCHAN_BUFFER_HIGH_WATER);
    for (offset = 0; offset < vchan.output_len; offset += sizeof(hdr)) {
        memcpy(&hdr, vchan.output + offset, sizeof(hdr));
        assert(hdr.type == QDB_RESP_OK && !hdr.data_len);
    }
    teardown(&dom0);
}

static struct db_daemon_data *sync_source, *sync_guest;

static void supply_sync(libvchan_t *vchan) {
    assert(vchan == sync_guest->vchan);
    pump(sync_source, sync_guest);
}

static void test_large_startup_sync_and_concurrent_updates(void) {
    struct db_daemon_data dom0, guest;
    struct libvchan host_vchan, guest_vchan;
    struct qdb_hdr hdr = { .type = QDB_CMD_MULTIREAD };
    struct qubesdb_entry *a, *b;
    char data[QDB_MAX_DATA - 1];
    char path[QDB_MAX_PATH];
    int i;

    memset(data, 'x', sizeof(data));
    setup(&dom0, &host_vchan);
    setup(&guest, &guest_vchan);
    dom0.remote_connected = 0;
    guest.remote_name = NULL;
    guest.multiread_requested = 1;
    assert(6000 * sizeof(data) > VCHAN_BUFFER_LIMIT);
    for (i = 6000; i; i--) {
        snprintf(path, sizeof(path), "/key-%06d", i);
        assert(qubesdb_write(dom0.db, path, data, sizeof(data)));
    }
    assert(qubesdb_write(dom0.db, "/deleted", "old", 3));
    assert(qubesdb_write(dom0.db, "/replaced", "old", 3));
    memcpy(host_vchan.input, &hdr, sizeof(hdr));
    host_vchan.input_left = sizeof(hdr);
    assert(handle_vchan_data(&dom0) == 1);
    assert(dom0.vchan_sync && dom0.remote_connected);
    assert(local_request(&dom0, QDB_CMD_RM, "/deleted", NULL, 0) == QDB_RESP_OK);
    assert(local_request(&dom0, QDB_CMD_WRITE, "/replaced", "new", 3) == QDB_RESP_OK);
    assert(local_request(&dom0, QDB_CMD_WRITE, "/new", "new", 3) == QDB_RESP_OK);
    /* Keep sync stalled while local changes exhaust their reserved budget. */
    while (local_request(&dom0, QDB_CMD_WRITE, "/new", data,
                sizeof(data)) == QDB_RESP_OK)
        assert(buffer_datacount(dom0.vchan_buffer) <=
                VCHAN_BUFFER_LIMIT - VCHAN_BUFFER_HIGH_WATER);
    while (local_request(&dom0, QDB_CMD_WRITE, "/empty", NULL, 0) == QDB_RESP_OK)
        assert(buffer_datacount(dom0.vchan_buffer) <=
                VCHAN_BUFFER_LIMIT - VCHAN_BUFFER_HIGH_WATER);
    assert(local_request(&dom0, QDB_CMD_RM, "/replaced", NULL, 0) ==
            QDB_RESP_ERROR);
    assert(qubesdb_search(dom0.db, "/replaced", 1));
    sync_source = &dom0;
    sync_guest = &guest;
    guest_vchan.on_wait = supply_sync;
    assert(wait_for_full_db_sync(&guest));
    assert(!guest.multiread_requested);
    guest_vchan.on_wait = NULL;
    drain(&dom0, &guest);
    a = dom0.db->entries->next;
    b = guest.db->entries->next;
    while (a != dom0.db->entries && b != guest.db->entries) {
        assert(strcmp(a->path, b->path) == 0);
        assert(a->value_len == b->value_len);
        assert(memcmp(a->value, b->value, a->value_len) == 0);
        a = a->next;
        b = b->next;
    }
    assert(a == dom0.db->entries && b == guest.db->entries);
    teardown(&guest);
    teardown(&dom0);
}

static void test_empty_sync_and_prefix_order(void) {
    struct db_daemon_data dom0, guest;
    struct libvchan host_vchan, guest_vchan;
    struct qdb_hdr hdr = { .type = QDB_CMD_MULTIREAD };
    int i;

    for (i = 0; i < 2; i++) {
        setup(&dom0, &host_vchan);
        setup(&guest, &guest_vchan);
        dom0.remote_connected = 0;
        guest.remote_name = NULL;
        guest.multiread_requested = 1;
        if (i) {
            assert(qubesdb_write(dom0.db, "/prefix/b", "", 0));
            assert(qubesdb_write(dom0.db, "/prefix/a", "", 0));
            assert(qubesdb_write(dom0.db, "/other", "", 0));
            strcpy(hdr.path, "/prefix/");
        }
        memcpy(host_vchan.input, &hdr, sizeof(hdr));
        host_vchan.input_left = sizeof(hdr);
        assert(handle_vchan_data(&dom0) == 1);
        pump(&dom0, &guest);
        memcpy(&hdr, host_vchan.output, sizeof(hdr));
        assert(hdr.type == QDB_RESP_MULTIREAD);
        if (i)
            assert(strcmp(hdr.path, "/prefix/a") == 0);
        else
            assert(!hdr.path[0]);
        consume(&guest);
        assert(!guest.multiread_requested);
        assert(!qubesdb_search(guest.db, "/other", 1));
        if (i) {
            assert(qubesdb_search(guest.db, "/prefix/a", 1));
            assert(qubesdb_search(guest.db, "/prefix/b", 1));
        }
        teardown(&guest);
        teardown(&dom0);
        hdr.type = QDB_CMD_MULTIREAD;
    }
}

static struct db_daemon_data *loop_daemon;
static int loop_peer, loop_step;

static void service_local_client(struct pollfd *fds, nfds_t nfds) {
    struct db_daemon_data *d = loop_daemon;
    struct qdb_hdr hdr = { .type = QDB_CMD_READ };
    char value[3];
    nfds_t i;

    assert(nfds == 4);
    for (i = 0; i < nfds; i++)
        fds[i].revents = 0;
    switch (loop_step++) {
        case 0:
            assert(vchan_requests_paused(d));
            strcpy(hdr.path, "/local");
            assert(write(loop_peer, &hdr, sizeof(hdr)) == sizeof(hdr));
            fds[3].revents = POLLIN;
            break;
        case 1:
            assert(read(loop_peer, &hdr, sizeof(hdr)) == sizeof(hdr));
            assert(hdr.type == QDB_RESP_READ && hdr.data_len == sizeof(value));
            assert(read(loop_peer, value, sizeof(value)) == sizeof(value));
            assert(memcmp(value, "old", sizeof(value)) == 0);
            assert(d->vchan->input_left == 0);
            assert(d->vchan_pending_hdr.type == QDB_CMD_WRITE);
            d->vchan->output_space = sizeof(d->vchan->output);
            fds[2].revents = POLLIN;
            break;
        case 2:
            assert(d->vchan->input_left == 0);
            assert(qubesdb_search(d->db, "/same-key", 1));
            sigterm_received = 1;
            break;
        default:
            assert(!"event loop did not terminate");
    }
}

static void test_event_loop_serves_clients_while_guest_is_paused(void) {
    struct db_daemon_data d;
    struct libvchan vchan;
    struct client client = { .can_write = 1 };
    struct qdb_hdr hdr = { .type = QDB_RESP_OK };
    int fds[2];
    sigset_t oldmask;

    setup(&d, &vchan);
    assert(qubesdb_write(d.db, "/local", "old", 3));
    while (!vchan_requests_paused(&d))
        assert(write_vchan_or_client(&d, NULL, (char *)&hdr, sizeof(hdr)));
    request(&vchan, QDB_CMD_WRITE);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    client.fd = fds[0];
    client.write_queue = buffer_create();
    assert(client.write_queue);
    d.client_list = &client;
    loop_daemon = &d;
    loop_peer = fds[1];
    loop_step = 0;
    poll_hook = service_local_client;
    sigterm_received = 0;
    assert(sigprocmask(SIG_SETMASK, NULL, &oldmask) == 0);
    assert(mainloop(&d));
    assert(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0);
    assert(loop_step == 3);
    poll_hook = NULL;
    sigterm_received = 0;
    close(fds[0]);
    close(fds[1]);
    buffer_free(client.write_queue);
    teardown(&d);
}

static int loop_mutation_type;

static void replicate_single_local_mutation(struct pollfd *fds, nfds_t nfds) {
    struct db_daemon_data *d = loop_daemon;
    struct qdb_hdr hdr = { .type = loop_mutation_type };
    int len = loop_mutation_type == QDB_CMD_WRITE ? 3 : 0;
    nfds_t i;

    assert(nfds == 4);
    for (i = 0; i < nfds; i++)
        fds[i].revents = 0;
    switch (loop_step++) {
        case 0:
            assert(!buffer_datacount(d->vchan_buffer));
            assert(!d->vchan->output_len);
            assert(d->vchan->output_space >= sizeof(hdr) + len);
            strcpy(hdr.path, "/local");
            hdr.data_len = len;
            assert(write(loop_peer, &hdr, sizeof(hdr)) == sizeof(hdr));
            if (len)
                assert(write(loop_peer, "new", len) == len);
            fds[3].revents = POLLIN;
            break;
        case 1:
            /* Entering the next poll with no further client or peer event.
             * The successful command must already be in the vchan ring. */
            assert(recv(loop_peer, &hdr, sizeof(hdr), MSG_DONTWAIT) ==
                    sizeof(hdr));
            assert(hdr.type == QDB_RESP_OK && !hdr.data_len);
            assert(d->vchan->output_len == sizeof(hdr) + len);
            assert(!buffer_datacount(d->vchan_buffer));
            memcpy(&hdr, d->vchan->output, sizeof(hdr));
            assert(hdr.type == loop_mutation_type);
            assert(strcmp(hdr.path, "/local") == 0);
            assert(hdr.data_len == len);
            if (len)
                assert(memcmp(d->vchan->output + sizeof(hdr), "new", len) == 0);
            sigterm_received = 1;
            break;
        default:
            assert(!"event loop did not terminate");
    }
}

static void test_event_loop_replicates_mutation_before_next_poll(void) {
    int types[] = { QDB_CMD_WRITE, QDB_CMD_RM };
    size_t i;

    for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        struct db_daemon_data d;
        struct libvchan vchan;
        struct client client = { .can_write = 1 };
        int fds[2];
        sigset_t oldmask;

        setup(&d, &vchan);
        assert(qubesdb_write(d.db, "/local", "old", 3));
        vchan.output_space = sizeof(vchan.output);
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        client.fd = fds[0];
        client.write_queue = buffer_create();
        assert(client.write_queue);
        d.client_list = &client;
        loop_daemon = &d;
        loop_peer = fds[1];
        loop_step = 0;
        loop_mutation_type = types[i];
        poll_hook = replicate_single_local_mutation;
        sigterm_received = 0;
        assert(sigprocmask(SIG_SETMASK, NULL, &oldmask) == 0);
        assert(mainloop(&d));
        assert(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0);
        assert(loop_step == 2);
        poll_hook = NULL;
        sigterm_received = 0;
        close(fds[0]);
        close(fds[1]);
        buffer_free(client.write_queue);
        teardown(&d);
    }
}

int main(void) {
    test_guest_requests_wait_for_output();
    test_paused_write_preserves_its_payload();
    test_partial_output_keeps_byte_order();
    test_buffer_size_arithmetic();
    test_removal_burst_consumes_guest_acknowledgments(0);
    test_removal_burst_consumes_guest_acknowledgments(1);
    test_pressure_preserves_accepted_deletions();
    test_guest_reply_has_reserved_space_and_packet_priority();
    test_full_reply_queue_resumes_request_before_sending_commands();
    test_large_startup_sync_and_concurrent_updates();
    test_empty_sync_and_prefix_order();
    test_event_loop_serves_clients_while_guest_is_paused();
    test_event_loop_replicates_mutation_before_next_poll();
    return 0;
}
