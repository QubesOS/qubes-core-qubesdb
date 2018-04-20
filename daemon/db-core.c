#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#else
#define strdup _strdup
#include <strsafe.h>
#endif

#include <qubesdb.h>
#include "qubesdb_internal.h"

struct qubesdb *qubesdb_init(send_watch_notify_t send_notify_func) {
    struct qubesdb *db;

    db = malloc(sizeof (*db));
    if (!db) {
        return NULL;
    }

    db->entries = malloc(sizeof(*db->entries));
    if (!db->entries) {
        free(db);
        return NULL;
    }

    db->entries->prev = db->entries;
    db->entries->next = db->entries;
    db->entries->path[0] = '/';
    db->entries->path[1] = '\0';
    db->entries->value = strdup("");

    db->watches = NULL;

    db->send_watch_notify = send_notify_func;

    return db;
}

struct qubesdb_entry *qubesdb_search(struct qubesdb *db, char *path, int exact) {
    struct qubesdb_entry *entry;
    int diff;

    entry = db->entries->next;

    while (entry != db->entries) {
        diff = strcmp(path, entry->path);
        if (!diff)
            return entry;
        if (diff < 0) {
            if (exact)
                return NULL;
            else
                return entry; /* FIXME: entry->prev? */
        }
        entry = entry->next;
    }
    if (exact)
        return NULL;
    else
        return entry;
}

struct qubesdb_entry *qubesdb_insert(struct qubesdb *db, char *path) {
    struct qubesdb_entry *entry, *new_entry;

    if (!path)
        return NULL;
    /* path must begin with '/'
     * Note: this also guarantee strlen(path) > 0 */
    if (path[0] != '/')
        return NULL;
    /* path cannot end with '/' */
    if (path[strlen(path)-1] == '/')
        return NULL;
    if (strlen(path) >= QDB_MAX_PATH)
        return NULL;
    entry = qubesdb_search(db, path, 0);
    if (!entry)
        /* shouldn't happen */
        return NULL;
    if (strcmp(entry->path, path)==0) {
        /* entry already exists */
        return entry;
    } else {
        new_entry = calloc(1,sizeof(*new_entry));
        if (!new_entry)
            return NULL;
#ifndef WIN32
        strncpy(new_entry->path, path, QDB_MAX_PATH - 1);
#else
        StringCbCopyA(new_entry->path, sizeof(new_entry->path), path);
#endif

        new_entry->value = NULL;
        new_entry->next = entry;
        new_entry->prev = entry->prev;
        entry->prev->next = new_entry;
        entry->prev = new_entry;
        return new_entry;
    }
}

int qubesdb_write(struct qubesdb *db, char *path, char *data, int data_len) {
    struct qubesdb_entry *db_entry;

    db_entry = qubesdb_insert(db, path);
    if (!db_entry) {
        return 0;
    }
    if (db_entry->value)
        free(db_entry->value);
    db_entry->value = malloc(data_len);
    memcpy(db_entry->value, data, data_len);
    db_entry->value_len = data_len;
    return 1;
}

int qubesdb_remove(struct qubesdb *db, char *path) {
    struct qubesdb_entry *entry;
    struct qubesdb_entry *tmp_entry;
    int remove_dir, cmp_len;
    int anything_removed = 0;

    cmp_len = (int)strlen(path);
    /* check if requested whole dir remove */
    if (path[cmp_len-1] == '/') {
        remove_dir = 1;
    } else {
        /* compare with trailing \0 for exact match */
        cmp_len++;
        remove_dir = 0;
    }

    entry = qubesdb_search(db, path, !remove_dir);
    if (!entry)
        return 0;
    while (strncmp(entry->path, path, cmp_len) == 0) {
        tmp_entry = entry;
        entry = entry->next;

        tmp_entry->prev->next = tmp_entry->next;
        tmp_entry->next->prev = tmp_entry->prev;
        free(tmp_entry->value);
        free(tmp_entry);
        anything_removed = 1;
    }
    return anything_removed;
}

int qubesdb_add_watch(struct qubesdb *db, char *path,
        struct client *client) {
    struct qubesdb_watch *new_watch;

    new_watch = calloc(1,sizeof(*new_watch));
    if (!new_watch) {
        return 0;
    }
    new_watch->next = db->watches;
    db->watches = new_watch;
    new_watch->client = client;
    /* path already verified by caller */
#ifndef WIN32
    strncpy(new_watch->path, path, QDB_MAX_PATH - 1);
#else
    StringCbCopyA(new_watch->path, sizeof(new_watch->path), path);
#endif
    new_watch->cmp_len = (int)strlen(path) + 1;
    if (new_watch->cmp_len >= 2 && path[new_watch->cmp_len-2] == '/')
        new_watch->cmp_len--;
    return 1;
}

int qubesdb_remove_watch(struct qubesdb *db, char *path,
        struct client *client) {
    struct qubesdb_watch *watch, *prev_watch, *tmp_watch;
    int anything_removed = 0;

    watch = db->watches;
    prev_watch = NULL;
    while (watch) {
        if (watch->client == client &&
                (!path || strcmp(watch->path, path) == 0)) {
            if (prev_watch)
                prev_watch->next = watch->next;
            else
                db->watches = watch->next;
            tmp_watch = watch;
            watch = watch->next;
            free(tmp_watch);
            anything_removed = 1;
            if (path)
                /* remove only one matching entry */
                break;
            else
                /* remove all entries for given client */
                continue;
        }
        prev_watch = watch;
        watch = watch->next;
    }
    return anything_removed;
}

int qubesdb_fire_watches(struct qubesdb *db, char *path) {
    struct qubesdb_watch *watch;
    struct qdb_hdr hdr;
    int fired_anything = 0;

    watch = db->watches;
    while (watch) {
        if (strncmp(watch->path, path, watch->cmp_len) == 0) {
            hdr.type = QDB_RESP_WATCH;
#ifndef WIN32
            strncpy(hdr.path, path, sizeof(hdr.path) - 1);
            hdr.path[sizeof(hdr.path) - 1] = '\0';
#else
            StringCbCopyA(hdr.path, sizeof(hdr.path), path);
#endif
            hdr.data_len = 0;

#ifndef WIN32
            if (db->send_watch_notify && db->send_watch_notify(watch->client, (char*)&hdr, sizeof(hdr)) < 0)
                fprintf(stderr, "Failed to fire watch on %s for client %d\n", path, watch->client->fd);
#else
            if (db->send_watch_notify && db->send_watch_notify(watch->client, (char*)&hdr, sizeof(hdr), db->pipe_server) < 0)
                fprintf(stderr, "Failed to fire watch on %s for client %d\n", path, watch->client->id);
#endif
            fired_anything = 1;
        }
        watch = watch->next;
    }
    return fired_anything;
}
