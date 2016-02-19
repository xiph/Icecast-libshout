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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_INTTYPES_H
#   include <inttypes.h>
#endif

#include <shout/shout.h>
#include "shout_private.h"

/* -- local datatypes -- */

typedef enum webm_parsing_state {
    WEBM_STATE_READ_TAG = 0,
    WEBM_STATE_COPY_THRU
} webm_parsing_state;

/* state for a filter that passes
 * through data unmodified.
 */
/* TODO: incorporate EBML parsing & extract
 * timestamps from Clusters and SimpleBlocks.
 */
/* TODO: provide for "fake chaining", where
 * concatinated files have extra headers stripped
 * and Cluster / Block timestamps rewritten
 */
typedef struct _webm_t {

    /* processing state */
    bool waiting_for_more_input;
    webm_parsing_state parsing_state;
    uint64_t copy_len;

    /* buffer state */
    size_t input_write_position;
    size_t input_read_position;
    size_t output_position;

    /* buffer storage */
    unsigned char input_buffer[SHOUT_BUFSIZE];
    unsigned char output_buffer[SHOUT_BUFSIZE];

} webm_t;

/* -- static prototypes -- */
static int  send_webm(shout_t *self, const unsigned char *data, size_t len);
static void close_webm(shout_t *self);

static int webm_process(shout_t *self, webm_t *webm);
static int webm_output(shout_t *self, webm_t *webm, const unsigned char *data, size_t len);

static size_t copy_possible(const void *src_base,
                            size_t *src_position,
                            size_t src_len,
                            void *target_base,
                            size_t *target_position,
                            size_t target_len);
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

    size_t input_progress = 0;
    self->error = SHOUTERR_SUCCESS;

    while(input_progress < len && self->error == SHOUTERR_SUCCESS) {
        copy_possible(data, &input_progress, len,
                      webm->input_buffer, &webm->input_write_position, SHOUT_BUFSIZE);

        self->error = webm_process(self, webm);
    }

    /* Squeeze out any possible output, unless we're failing */
    if(self->error == SHOUTERR_SUCCESS) {
        self->error = flush_output(self, webm);
    }

    return self->error;
}

static void close_webm(shout_t *self)
{
    webm_t *webm_filter = (webm_t *) self->format_data;
    if(webm_filter) free(webm_filter);
}

/* -- processing functions -- */

/* Process what we can of the input buffer,
 * extracting statistics or rewriting the
 * stream as necessary.
 * Returns a status code to indicate socket errors.
 */
static int webm_process(shout_t *self, webm_t *webm)
{
    /* IMPORTANT TODO: we just send the raw data. We need throttling. */
    size_t to_process;

    /* loop as long as buffer holds process-able data */
    while( webm->input_read_position < webm->input_write_position
           && !webm->waiting_for_more_input
           && self->error == SHOUTERR_SUCCESS ) {

        /* calculate max space an operation can work on */
        to_process = webm->input_write_position - webm->input_read_position;

        /* perform appropriate operation */
        switch(webm->parsing_state) {
            case WEBM_STATE_READ_TAG:
                /* Stub: copy everything obliviously */
                webm->copy_len = to_process;
                webm->parsing_state = WEBM_STATE_COPY_THRU;
                break;

            case WEBM_STATE_COPY_THRU:
                /* copy a known quantity of bytes to the output */

                /* calculate size needing to be copied this step */
                if(webm->copy_len < to_process) {
                    to_process = webm->copy_len;
                }

                /* do copy */
                self->error = webm_output(self, webm,
                                          webm->input_buffer + webm->input_read_position,
                                          to_process);

                /* update state with copy progress */
                webm->copy_len -= to_process;
                webm->input_read_position += to_process;
                if(webm->copy_len == 0) {
                    webm->parsing_state = WEBM_STATE_READ_TAG;
                }

                break;

        }

    }

    if(webm->input_read_position < webm->input_write_position) {
        /* slide unprocessed data to front of buffer */
        to_process = webm->input_write_position - webm->input_read_position;
        memmove(webm->input_buffer, webm->input_buffer + webm->input_read_position, to_process);

        webm->input_read_position = 0;
        webm->input_write_position = to_process;
    } else {
        /* subtract read position instead of zeroing;
         * this allows skipping over large spans of data by
         * setting the read pointer far ahead. Processing won't
         * resume until the read pointer is actually within the buffer.
         */
        webm->input_read_position -= webm->input_write_position;
        webm->input_write_position = 0;
    }

    return self->error;
}

/* Queue the given data in the output buffer,
 * flushing as needed. Returns a status code
 * to allow detecting socket errors on a flush.
 */
static int webm_output(shout_t *self, webm_t *webm, const unsigned char *data, size_t len)
{
    size_t output_progress = 0;

    while(output_progress < len && self->error == SHOUTERR_SUCCESS)
    {
        copy_possible(data, &output_progress, len,
                      webm->output_buffer, &webm->output_position, SHOUT_BUFSIZE);

        if(webm->output_position == SHOUT_BUFSIZE) {
            self->error = flush_output(self, webm);
        }
    }

    return self->error;
}

/* -- utility functions -- */

/* Copies as much of the source buffer into the target
 * as will fit, and returns the actual size copied.
 * Updates position pointers to match.
 */
static size_t copy_possible(const void *src_base,
                            size_t *src_position,
                            size_t src_len,
                            void *target_base,
                            size_t *target_position,
                            size_t target_len)
{
    size_t src_space = src_len - *src_position;
    size_t target_space = target_len - *target_position;

    size_t to_copy = src_space;
    if(target_space < to_copy) to_copy = target_space;

    memcpy(target_base + *target_position, src_base + *src_position, to_copy);

    *src_position += to_copy;
    *target_position += to_copy;

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
        return self->error;
    }

    ssize_t ret = shout_send_raw(self, webm->output_buffer, webm->output_position);
    if (ret != (ssize_t) webm->output_position) {
        return self->error = SHOUTERR_SOCKET;
    }

    webm->output_position = 0;
    return self->error;
}
