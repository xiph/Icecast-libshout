/* -*- c-basic-offset: 8; -*- */
/* webm.c: WebM data handler
 * $Id$
 *
 *  Copyright (C) 2002-2012 the Icecast team <team@icecast.org>
 *  Copyright (C) 2015-2019 Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the Free
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_INTTYPES_H
#   include <inttypes.h>
#endif

#include <shout/shout.h>
#include "shout_private.h"

/* -- local datatypes -- */

/* unused state for a filter that passes
 * through data unmodified.
 */
/* TODO: Run data through the internal buffers
 * so we have a spot we can insert processing.
 */
/* TODO: incorporate EBML parsing & extract
 * timestamps from Clusters and SimpleBlocks.
 */
/* TODO: provide for "fake chaining", where
 * concatinated files have extra headers stripped
 * and Cluster / Block timestamps rewritten
 */
typedef struct _webm_t {

    /* buffer state */
    size_t input_position;
    size_t output_position;

    /* buffer storage */
    unsigned char input_buffer[SHOUT_BUFSIZE];
    unsigned char output_buffer[SHOUT_BUFSIZE];

} webm_t;

/* -- static prototypes -- */
static int  send_webm(shout_t *self, const unsigned char *data, size_t len);
static void close_webm(shout_t *self);

static size_t copy_possible(const void *src,    size_t srcLen,
                                  void *target, size_t targetLen);
static int flush_output(shout_t *self, webm_t *webm);

/* -- interface functions -- */
int shout_open_webm(shout_t *self)
{
    webm_t *webm_filter;

    /* Alloc WebM filter */
    if (!(webm_filter = (webm_t *)calloc(1, sizeof(webm_t)))) {
        return self->error = SHOUTERR_MALLOC;
    }

    /* configure shout state */
    self->format_data = webm_filter;

    self->send = send_webm;
    self->close = close_webm;

    return SHOUTERR_SUCCESS;
}

static int send_webm(shout_t *self, const unsigned char *data, size_t len)
{
    webm_t *webm = (webm_t *) self->format_data;
    /* IMPORTANT TODO: we just send the raw data. We need throttling. */

    size_t copied = 0;
    unsigned const char *src = data;
    unsigned char *target;
    size_t target_space;

    self->error = SHOUTERR_SUCCESS;

    while(len > 0 && self->error == SHOUTERR_SUCCESS) {
        target = webm->output_buffer + webm->output_position;
        target_space = SHOUT_BUFSIZE - webm->output_position;
        copied = copy_possible(src, len, target, target_space);

        src += copied;
        webm->output_position += copied;
        len -= copied;
        self->error = flush_output(self, webm);
    }

    return self->error;
}

static void close_webm(shout_t *self)
{
    webm_t *webm_filter = (webm_t *) self->format_data;
    if(webm_filter) free(webm_filter);
}

/* -- utility functions -- */

/* Copies as much of the source buffer into the target
 * as will fit, and returns the actual size copied.
 */
static size_t copy_possible(const void *src,    size_t srcLen,
                                  void *target, size_t targetLen)
{
    size_t to_copy = srcLen;
    if(targetLen < to_copy) to_copy = targetLen;

    memcpy(target, src, to_copy);
    return to_copy;
}

/* Send currently buffered output to the server.
 * Output buffering is needed because parsing
 * and/or rewriting code may pass through small
 * chunks at a time, and we don't want to expend a
 * syscall on each one.
 * However, we do not want to leave sendable data
 * in the buffer before we return to the client and
 * potentially sleep, so this is called before
 * send_webm() returns.
 */
static int flush_output(shout_t *self, webm_t *webm)
{
    if(webm->output_position == 0) {
        return self->error = SHOUTERR_SUCCESS;
    }

    ssize_t ret = shout_send_raw(self, webm->output_buffer, webm->output_position);
    if (ret != (ssize_t) webm->output_position) {
        return self->error = SHOUTERR_SOCKET;
    }

    webm->output_position = 0;
    return self->error = SHOUTERR_SUCCESS;
}
