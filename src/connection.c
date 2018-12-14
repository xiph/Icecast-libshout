/*
 *  Copyright (C) 2018      Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>
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

shout_connection_t *shout_connection_new(shout_t *self, const shout_protocol_impl_t *impl, const void *plan)
{
    shout_connection_t *con;

    if (!self || !impl)
        return NULL;

    con = calloc(1, sizeof(*con));
    if (!con)
        return NULL;

    con->refc = 1;
    con->socket = SOCK_ERROR;
    con->selected_tls_mode = SHOUT_TLS_AUTO;
    con->impl = impl;
    con->plan = plan;

    return con;
}

int                 shout_connection_ref(shout_connection_t *con)
{
    if (!con)
        return SHOUTERR_INSANE;

    con->refc++;

    return SHOUTERR_SUCCESS;
}

int                 shout_connection_unref(shout_connection_t *con)
{
    if (!con)
        return SHOUTERR_INSANE;

    con->refc--;

    if (con->refc)
        return SHOUTERR_SUCCESS;

    if (con->destory)
        con->destory(con);

    shout_connection_disconnect(con);

    free(con);

    return SHOUTERR_SUCCESS;
}

static struct timeval shout_connection_iter__wait_for_io__get_timeout(shout_connection_t *con, shout_t *shout)
{
    static const struct timeval tv_blocking = {
        .tv_sec = 8,
        .tv_usec = 0
    };
    static const struct timeval tv_nonblocking = {
        .tv_sec = 0,
        .tv_usec = 1000
    };

    if (con->nonblocking) {
        return tv_nonblocking;
    } else {
        return tv_blocking;
    }
}

static shout_connection_return_state_t shout_connection_iter__wait_for_io(shout_connection_t *con, shout_t *shout, int for_read, int for_write)
{
    struct timeval tv = shout_connection_iter__wait_for_io__get_timeout(con, shout);
    fd_set fhset_r;
    fd_set fhset_w;
    fd_set fhset_e;
    int ret;

    FD_ZERO(&fhset_r);
    FD_ZERO(&fhset_w);
    FD_ZERO(&fhset_e);
    FD_SET(con->socket, &fhset_r);
    FD_SET(con->socket, &fhset_w);
    FD_SET(con->socket, &fhset_e);

    ret = select(con->socket + 1, (for_read) ? &fhset_r : NULL, (for_write) ? &fhset_w : NULL, &fhset_e, &tv);

    if (ret > 0 && (FD_ISSET(con->socket, &fhset_r) || FD_ISSET(con->socket, &fhset_w) || FD_ISSET(con->socket, &fhset_e))) {
        return SHOUT_RS_DONE;
    } else if (ret == 0) {
        shout->error = SHOUTERR_RETRY;
        return SHOUT_RS_TIMEOUT;
    } else {
        shout->error = SHOUTERR_SOCKET;
        return SHOUT_RS_ERROR;
    }
}

static shout_connection_return_state_t shout_connection_iter__socket(shout_connection_t *con, shout_t *shout)
{
    shout_connection_return_state_t ret;
    int rc;

    switch (con->current_socket_state) {
        case SHOUT_SOCKSTATE_UNCONNECTED:
            shout->error = shout_connection_connect(con, shout);
            if (shout->error == SHOUTERR_SUCCESS) {
                con->current_socket_state = SHOUT_SOCKSTATE_CONNECTING;
                return SHOUT_RS_DONE;
            }
        break;
        case SHOUT_SOCKSTATE_CONNECTING:
            if (con->nonblocking) {
                ret = shout_connection_iter__wait_for_io(con, shout, 1, 1);
                if (ret != SHOUT_RS_DONE) {
                    return ret;
                }
            }

            if (sock_connected(con->socket, 0) == 1) {
                con->current_socket_state = SHOUT_SOCKSTATE_CONNECTED;
                return SHOUT_RS_DONE;
            }
        break;
        case SHOUT_SOCKSTATE_CONNECTED:
            shout_tls_try_connect(con->tls);
            con->current_socket_state = SHOUT_SOCKSTATE_TLS_CONNECTING;
            return SHOUT_RS_DONE;
        break;
        case SHOUT_SOCKSTATE_TLS_CONNECTING:
        case SHOUT_SOCKSTATE_TLS_CONNECTED:
            rc = shout_tls_try_connect(con->tls);
            if (rc == SHOUTERR_SUCCESS) {
                con->current_socket_state = SHOUT_SOCKSTATE_TLS_VERIFIED;
                return SHOUT_RS_DONE;
            } else if (rc == SHOUTERR_BUSY) {
                return SHOUT_RS_NOTNOW;
            } else {
                shout->error = rc;
                return SHOUT_RS_ERROR;
            }
        break;
    }

    shout->error = SHOUTERR_SOCKET;
    return SHOUT_RS_ERROR;
}

ssize_t shout_connection__read(shout_connection_t *con, shout_t *shout, void *buf, size_t len)
{
#ifdef HAVE_OPENSSL
    if (con->tls)
        return shout_tls_read(con->tls, buf, len);
#endif
    return sock_read_bytes(con->socket, buf, len);
}

ssize_t shout_connection__write(shout_connection_t *con, shout_t *shout, const void *buf, size_t len)
{
#ifdef HAVE_OPENSSL
    if (con->tls)
        return shout_tls_write(con->tls, buf, len);
#endif
    return sock_write_bytes(con->socket, buf, len);
}
int shout_connection__recoverable(shout_connection_t *con, shout_t *shout)
{
#ifdef HAVE_OPENSSL
    if (con->tls)
        return shout_tls_recoverable(con->tls);
#endif
    return sock_recoverable(sock_error());
}

static ssize_t try_write(shout_connection_t *con, shout_t *shout, const void *data_p, size_t len)
{
    ssize_t         ret;
    size_t          pos = 0;
    unsigned char  *data = (unsigned char*)data_p;

    /* loop until whole buffer is written (unless it would block) */
    do {
        ret = shout_connection__write(con, shout, data + pos, len - pos);
        if (ret > 0)
            pos += ret;
    } while (pos < len && ret >= 0);

    if (ret < 0) {
        if (shout_connection__recoverable(con, shout)) {
            shout->error = SHOUTERR_BUSY;
            return pos;
        }
        shout->error = SHOUTERR_SOCKET;
        return ret;
    }
    return pos;
}

static shout_connection_return_state_t shout_connection_iter__message__send_queue(shout_connection_t *con, shout_t *shout)
{
    shout_buf_t *buf;
    int          ret;

    if (!con->wqueue.len)
        return SHOUT_RS_DONE;

    buf = con->wqueue.head;
    while (buf) {
        ret = try_write(con, shout, buf->data + buf->pos, buf->len - buf->pos);
        if (ret < 0) {
            if (shout->error == SHOUTERR_BUSY) {
                return SHOUT_RS_NOTNOW;
            } else {
                return SHOUT_RS_ERROR;
            }
        }

        buf->pos += ret;
        con->wqueue.len -= ret;
        if (buf->pos == buf->len) {
            con->wqueue.head = buf->next;
            free(buf);
            buf = con->wqueue.head;
            if (buf)
                buf->prev = NULL;
        } else {
            /* incomplete write */
            return SHOUT_RS_NOTNOW;
        }
    }
    return SHOUT_RS_DONE;
}

static shout_connection_return_state_t shout_connection_iter__message__recv(shout_connection_t *con, shout_t *shout)
{
    char buf[1024];
    ssize_t rc;
    int ret;

    rc = shout_connection__read(con, shout, buf, sizeof(buf));

    if (rc < 0 && shout_connection__recoverable(con, shout))
        return SHOUT_RS_NOTNOW;

    if (rc > 0) {
        if ((ret = shout_queue_data(&(con->rqueue), (unsigned char*)buf, rc)) != SHOUTERR_SUCCESS) {
            shout->error = ret;
            return SHOUT_RS_ERROR;
        }
    }

    return con->impl->msg_get(shout, con);
}
static shout_connection_return_state_t shout_connection_iter__message(shout_connection_t *con, shout_t *shout)
{
    shout_connection_return_state_t ret = SHOUT_RS_DONE;

    switch (con->current_message_state) {
        case SHOUT_MSGSTATE_IDLE:
            return SHOUT_RS_DONE;
        break;
        case SHOUT_MSGSTATE_CREATING0:
        case SHOUT_MSGSTATE_CREATING1:
            if (con->impl->msg_create) {
                ret = con->impl->msg_create(shout, con);
            }
            if (ret == SHOUT_RS_DONE) {
                if (con->current_message_state == SHOUT_MSGSTATE_CREATING0) {
                    con->current_message_state = SHOUT_MSGSTATE_SENDING0;
                } else {
                    con->current_message_state = SHOUT_MSGSTATE_SENDING1;
                }
            }
            return ret;
        break;
        case SHOUT_MSGSTATE_SENDING0:
            ret = shout_connection_iter__message__send_queue(con, shout);
            if (ret == SHOUT_RS_DONE) {
                con->current_message_state = SHOUT_MSGSTATE_WAITING0;
            }
            return ret;
        break;
        case SHOUT_MSGSTATE_SENDING1:
            if (con->wqueue.len) {
                return shout_connection_iter__message__send_queue(con, shout);
            } else {
                return SHOUT_RS_ERROR;
            }
        break;
        case SHOUT_MSGSTATE_WAITING0:
        case SHOUT_MSGSTATE_WAITING1:
            ret = shout_connection_iter__wait_for_io(con, shout, 1, 0);
            if (ret == SHOUT_RS_DONE) {
                if (con->current_message_state == SHOUT_MSGSTATE_WAITING0) {
                    con->current_message_state = SHOUT_MSGSTATE_RECEIVING0;
                } else {
                    con->current_message_state = SHOUT_MSGSTATE_RECEIVING1;
                }
            }
            return ret;
        break;
        case SHOUT_MSGSTATE_RECEIVING0:
        case SHOUT_MSGSTATE_RECEIVING1:
            ret = shout_connection_iter__message__recv(con, shout);
            if (ret == SHOUT_RS_DONE) {
                if (con->current_message_state == SHOUT_MSGSTATE_RECEIVING0) {
                    con->current_message_state = SHOUT_MSGSTATE_RECEIVED0;
                } else {
                    con->current_message_state = SHOUT_MSGSTATE_RECEIVING1;
                }
            }
            return ret;
        break;
        case SHOUT_MSGSTATE_RECEIVED0:
        case SHOUT_MSGSTATE_RECEIVED1:
            if (con->impl->msg_parse)
                ret = con->impl->msg_parse(shout, con);
            return ret;
        break;
        case SHOUT_MSGSTATE_PARSED_INFORMATIONAL0:
        case SHOUT_MSGSTATE_PARSED_INFORMATIONAL1:
            con->current_message_state = SHOUT_MSGSTATE_CREATING1;
            return SHOUT_RS_DONE;
        break;
        case SHOUT_MSGSTATE_PARSED_FINAL:
            con->current_message_state = SHOUT_MSGSTATE_IDLE;
            return SHOUT_RS_DONE;
        break;
    }

    shout->error = SHOUTERR_SOCKET;
    return SHOUT_RS_ERROR;
}

static shout_connection_return_state_t shout_connection_iter__protocol(shout_connection_t *con, shout_t *shout)
{
    shout_connection_return_state_t ret;

    if (!con->impl->protocol_iter) {
        con->current_protocol_state = con->target_protocol_state;
        return SHOUT_RS_DONE;
    }

    ret = con->impl->protocol_iter(shout, con);
    switch (ret) {
        case SHOUT_RS_ERROR:
            shout->error = SHOUTERR_SOCKET;
        break;
        case SHOUT_RS_NOTNOW:
        case SHOUT_RS_TIMEOUT:
            shout->error = SHOUTERR_RETRY;
        break;
    }

    return ret;
}

int                 shout_connection_iter(shout_connection_t *con, shout_t *shout)
{
    int found;
    int retry;

    if (!con || !shout)
        return SHOUTERR_INSANE;

    if (con->socket == SOCK_ERROR)
        return SHOUTERR_NOCONNECT;


#define __iter(what) \
    while (!retry && con->target_ ## what ## _state != con->current_ ## what ## _state) { \
        found = 1; \
        shout_connection_return_state_t ret = shout_connection_iter__ ## what (con, shout); \
        switch (ret) { \
            case SHOUT_RS_DONE: \
                continue; \
            break; \
            case SHOUT_RS_TIMEOUT: \
            case SHOUT_RS_NOTNOW: \
                if (con->nonblocking) \
                    return SHOUTERR_RETRY; \
                retry = 1; \
            break; \
            case SHOUT_RS_ERROR: \
                return shout->error; \
            break; \
        } \
    }

    do {
        found = 0;
        retry = 0;
        __iter(socket)
        __iter(message)
        __iter(protocol)
    } while (found || retry);

    return SHOUTERR_SUCCESS;
}

int                 shout_connection_select_tlsmode(shout_connection_t *con, int tlsmode)
{
    if (!con)
        return SHOUTERR_INSANE;

    if (tlsmode == con->selected_tls_mode)
        return SHOUTERR_SUCCESS;

#ifdef HAVE_OPENSSL
    if (con->tls)
        return SHOUTERR_BUSY;
#endif

    if (con->selected_tls_mode != SHOUT_TLS_AUTO && con->selected_tls_mode != SHOUT_TLS_AUTO_NO_PLAIN)
        return SHOUTERR_BUSY;

    if ((tlsmode == SHOUT_TLS_DISABLED || tlsmode == SHOUT_TLS_AUTO) && con->selected_tls_mode == SHOUT_TLS_AUTO_NO_PLAIN)
        return SHOUTERR_NOTLS;

    switch (tlsmode) {
        case SHOUT_TLS_DISABLED:
        case SHOUT_TLS_AUTO:
        case SHOUT_TLS_AUTO_NO_PLAIN:
        case SHOUT_TLS_RFC2818:
        case SHOUT_TLS_RFC2817:
            con->selected_tls_mode = tlsmode;
            return SHOUTERR_SUCCESS;
        break;
        default:
            return SHOUTERR_INSANE;
        break;
    }

    return SHOUTERR_INSANE;
}
int                 shout_connection_set_nonblocking(shout_connection_t *con, unsigned int nonblocking)
{
    if (!con)
        return SHOUTERR_INSANE;

    if (con->socket != SOCK_ERROR)
        return SHOUTERR_BUSY;

    con->nonblocking = nonblocking;

    return SHOUTERR_SUCCESS;
}

int                 shout_connection_set_next_timeout(shout_connection_t *con, shout_t *shout, uint32_t timeout /* [ms] */);
int                 shout_connection_connect(shout_connection_t *con, shout_t *shout)
{
    int port;

    if (!con || !shout)
        return SHOUTERR_INSANE;

    if (con->socket != SOCK_ERROR || con->current_socket_state != SHOUT_SOCKSTATE_UNCONNECTED)
        return SHOUTERR_BUSY;

    shout_connection_set_nonblocking(con, shout_get_nonblocking(shout));

    port = shout->port;
    if (shout_get_protocol(shout) == SHOUT_PROTOCOL_ICY)
        port++;

    if (con->nonblocking) {
        con->socket = sock_connect_non_blocking(shout->host, port);
    } else {
        con->socket = sock_connect(shout->host, port);
    }

    if (con->socket < 0) {
        con->socket = SOCK_ERROR;
        return SHOUTERR_NOCONNECT;
    }

    con->current_socket_state = SHOUT_SOCKSTATE_CONNECTING;
    con->target_socket_state = SHOUT_SOCKSTATE_CONNECTED;
    if (con->target_message_state != SHOUT_MSGSTATE_IDLE)
        con->current_message_state = SHOUT_MSGSTATE_CREATING0;

    if (shout->tls_mode == SHOUT_TLS_RFC2818)
        return shout_connection_starttls(con, shout);

    return SHOUTERR_SUCCESS;
}
int                 shout_connection_disconnect(shout_connection_t *con)
{
    if (!con)
        return SHOUTERR_INSANE;

#ifdef HAVE_OPENSSL
    if (con->tls)
        shout_tls_close(con->tls);
    con->tls = NULL;
#endif

    if (con->socket != SOCK_ERROR)
        sock_close(con->socket);
    con->socket = SOCK_ERROR;

    con->target_socket_state = SHOUT_SOCKSTATE_UNCONNECTED;
    con->current_socket_state = SHOUT_SOCKSTATE_UNCONNECTED;

    return SHOUTERR_SUCCESS;
}
ssize_t             shout_connection_send(shout_connection_t *con, shout_t *shout, const void *buf, size_t len)
{
    int ret;

    if (!con || !shout)
        return -1;

    if (con->current_message_state != SHOUT_MSGSTATE_SENDING1)
        return -1;

    ret = shout_queue_data(&(con->wqueue), buf, len);
    if (ret != SHOUTERR_SUCCESS)
        return -1;

    shout_connection_iter(con, shout);

    return len;
}

int                 shout_connection_starttls(shout_connection_t *con, shout_t *shout)
{
    if (!con || !shout)
        return SHOUTERR_INSANE;

    if (con->tls)
        return SHOUTERR_BUSY;

    con->tls = shout_tls_new(shout, con->socket);
    if (!con->tls) /* just guessing that it's a malloc error */
        return SHOUTERR_MALLOC;

    con->target_socket_state = SHOUT_SOCKSTATE_TLS_VERIFIED;

    return SHOUTERR_SUCCESS;
}
