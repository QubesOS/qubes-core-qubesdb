/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2010  Rafal Wojtczuk  <rafal@invisiblethingslab.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "buffer.h"

struct buffer *buffer_create(void)
{
    struct buffer *b;

    b = malloc(sizeof(struct buffer));
    if (!b)
        return NULL;
    b->buffer = malloc(BUFFER_SIZE_MIN);
    if (!b->buffer) {
        free(b);
        return NULL;
    }
    b->buffer_size = BUFFER_SIZE_MIN;
    b->data_offset = 0;
    b->data_count = 0;
    return b;
}

void buffer_free(struct buffer *b) {
    if (!b)
        return;
    if (b->buffer)
        free(b->buffer);
    free(b);
}

// We optimize for buffer_substract(), as it can be called
// many times; malloc(newsize) in buffer_append() should be rare
// in normal circumstances.

int buffer_append(struct buffer *b, char *buf, int size)
{
    if (size + b->data_offset + b->data_count > b->buffer_size) {
        int newsize = b->data_count + size + BUFFER_SIZE_MIN;
        char *newbuf;
        newbuf = malloc(newsize);
        if (!newbuf) {
            perror("malloc");
            return 0;
        }
        memcpy(newbuf, b->buffer + b->data_offset, b->data_count);
        free(b->buffer);
        b->buffer = newbuf;
        b->buffer_size = newsize;
        b->data_offset = 0;
    }
    memcpy(b->buffer + b->data_offset + b->data_count, buf, size);
    b->data_count += size;
    return 1;
}

int buffer_datacount(struct buffer *b)
{
    return b->data_count;
}

char *buffer_data(struct buffer *b)
{
    return b->buffer + b->data_offset;
}

void buffer_substract(struct buffer *b, int count)
{
    assert(count <= b->data_count);
    b->data_count -= count;
    b->data_offset += count;
    if (b->data_count == 0) {
        if (b->buffer_size > BUFFER_SIZE_MIN) {
            free(b->buffer);
            b->buffer = malloc(BUFFER_SIZE_MIN);
            if (!b->buffer) {
                perror("malloc");
                exit(1);
            }

        }
        b->data_offset = 0;
        b->buffer_size = BUFFER_SIZE_MIN;
    }
}
