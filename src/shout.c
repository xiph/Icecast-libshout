/* -*- c-basic-offset: 8; -*- */
/* shout.c: Implementation of public libshout interface shout.h
 *
 *  Copyright (C) 2002-2004 the Icecast team <team@icecast.org>,
 *  Copyright (C) 2012-2015 Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>
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
 *
 * $Id$
 */

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <shout/shout.h>

#include <common/net/sock.h>
#include <common/timing/timing.h>
#include <common/httpp/httpp.h>

#include "shout_private.h"
#include "util.h"

#ifdef _MSC_VER
#   ifndef va_copy
#       define va_copy(ap1, ap2) memcpy(&ap1, &ap2, sizeof(va_list))
#   endif
#   define vsnprintf      _vsnprintf
#   define inline         _inline
#endif

/* -- local prototypes -- */
static int try_connect(shout_t *self);

/* -- static data -- */
static int _initialized = 0;

/* -- public functions -- */

void shout_init(void)
{
    if (_initialized)
        return;

    sock_initialize();
    _initialized = 1;
}

void shout_shutdown(void)
{
    if (!_initialized)
        return;

    sock_shutdown();
    _initialized = 0;
}

shout_t *shout_new(void)
{
    shout_t *self;

    /* in case users haven't done this explicitly. Should we error
     * if not initialized instead? */
    shout_init();

    if (!(self = (shout_t*)calloc(1, sizeof(shout_t)))) {
        return NULL;
    }

    if (shout_set_host(self, LIBSHOUT_DEFAULT_HOST) != SHOUTERR_SUCCESS) {
        shout_free(self);
        return NULL;
    }

    if (shout_set_user(self, LIBSHOUT_DEFAULT_USER) != SHOUTERR_SUCCESS) {
        shout_free(self);
        return NULL;
    }

    if (shout_set_agent(self, LIBSHOUT_DEFAULT_USERAGENT) != SHOUTERR_SUCCESS) {
        shout_free(self);
        return NULL;
    }

    if (!(self->audio_info = _shout_util_dict_new())) {
        shout_free(self);
        return NULL;
    }

    if (!(self->meta = _shout_util_dict_new())) {
        shout_free(self);
        return NULL;
    }

    if (shout_set_meta(self, "name", "no name") != SHOUTERR_SUCCESS) {
        shout_free(self);
        return NULL;
    }

#ifdef HAVE_OPENSSL
    if (shout_set_allowed_ciphers(self, LIBSHOUT_DEFAULT_ALLOWED_CIPHERS) != SHOUTERR_SUCCESS) {
        shout_free(self);
        return NULL;
    }

    self->tls_mode      = SHOUT_TLS_AUTO;
#endif

    self->port      = LIBSHOUT_DEFAULT_PORT;
    self->format    = LIBSHOUT_DEFAULT_FORMAT;
    self->protocol  = LIBSHOUT_DEFAULT_PROTOCOL;

    return self;
}

void shout_free(shout_t *self)
{
    if (!self)
        return;

    if (!self->connection)
        return;

    if (self->host)
        free(self->host);
    if (self->password)
        free(self->password);
    if (self->mount)
        free(self->mount);
    if (self->user)
        free(self->user);
    if (self->useragent)
        free(self->useragent);
    if (self->audio_info)
        _shout_util_dict_free (self->audio_info);
    if (self->meta)
        _shout_util_dict_free (self->meta);

#ifdef HAVE_OPENSSL
    if (self->ca_directory)
        free(self->ca_directory);
    if (self->ca_file)
        free(self->ca_file);
    if (self->allowed_ciphers)
        free(self->allowed_ciphers);
    if (self->client_certificate)
        free(self->client_certificate);
#endif

    free(self);
}

int shout_open(shout_t *self)
{
    /* sanity check */
    if (!self)
        return SHOUTERR_INSANE;
    if (self->connection)
        return SHOUTERR_CONNECTED;
    if (!self->host || !self->password || !self->port)
        return self->error = SHOUTERR_INSANE;
    if (self->format == SHOUT_FORMAT_OGG &&  (self->protocol != SHOUT_PROTOCOL_HTTP && self->protocol != SHOUT_PROTOCOL_ROARAUDIO))
        return self->error = SHOUTERR_UNSUPPORTED;

    return self->error = try_connect(self);
}


int shout_close(shout_t *self)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (!self->connection)
        return self->error = SHOUTERR_UNCONNECTED;

    if (self->connection && self->connection->current_message_state == SHOUT_MSGSTATE_SENDING1 && self->close)
        self->close(self);

    shout_connection_unref(self->connection);
    self->starttime = 0;
    self->senttime = 0;

    return self->error = SHOUTERR_SUCCESS;
}

int shout_send(shout_t *self, const unsigned char *data, size_t len)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (!self->connection || self->connection->current_message_state != SHOUT_MSGSTATE_SENDING1)
        return self->error = SHOUTERR_UNCONNECTED;

    if (self->starttime <= 0)
        self->starttime = timing_get_time();

    if (!len)
        return shout_connection_iter(self->connection, self);

    return self->send(self, data, len);
}

ssize_t shout_send_raw(shout_t *self, const unsigned char *data, size_t len)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (!self->connection || self->connection->current_message_state != SHOUT_MSGSTATE_SENDING1)
        return SHOUTERR_UNCONNECTED;

    return shout_connection_send(self->connection, self, data, len);
}

ssize_t shout_queuelen(shout_t *self)
{
    if (!self)
        return SHOUTERR_INSANE;

    return shout_connection_get_sendq(self->connection, self);
}


void shout_sync(shout_t *self)
{
    int64_t sleep;

    if (!self)
        return;

    if (self->senttime == 0)
        return;

    sleep = self->senttime / 1000 - (timing_get_time() - self->starttime);
    if (sleep > 0)
        timing_sleep((uint64_t)sleep);

}

int shout_delay(shout_t *self)
{

    if (!self)
        return 0;

    if (self->senttime == 0)
        return 0;

    return self->senttime / 1000 - (timing_get_time() - self->starttime);
}

shout_metadata_t *shout_metadata_new(void)
{
    return _shout_util_dict_new();
}

void shout_metadata_free(shout_metadata_t *self)
{
    if (!self)
        return;

    _shout_util_dict_free(self);
}

int shout_metadata_add(shout_metadata_t *self, const char *name, const char *value)
{
    if (!self || !name)
        return SHOUTERR_INSANE;

    return _shout_util_dict_set(self, name, value);
}

int shout_set_metadata(shout_t *self, shout_metadata_t *metadata)
{
    shout_connection_t *connection;
    shout_http_plan_t plan;
    size_t param_len;
    char *param = NULL;
    char *encvalue;
    char *encpassword;
    char *encmount;
    const char *param_template;

    if (!self || !metadata)
        return SHOUTERR_INSANE;

    encvalue = _shout_util_dict_urlencode(metadata, '&');
    if (!encvalue)
        return self->error = SHOUTERR_MALLOC;

    memset(&plan, 0, sizeof(plan));

    plan.is_source = 0;

    switch (self->protocol) {
        case SHOUT_PROTOCOL_ICY:
            if (!(encpassword = _shout_util_url_encode(self->password))) {
                free(encvalue);
                return self->error = SHOUTERR_MALLOC;
            }

            param_template = "mode=updinfo&pass=%s&%s";
            param_len = strlen(param_template) + strlen(encvalue) + 1 + strlen(encpassword);
            param = malloc(param_len);
            if (!param) {
                free(encpassword);
                free(encvalue);
                return self->error = SHOUTERR_MALLOC;
            }
            snprintf(param, param_len, param_template, encpassword, encvalue);
            free(encpassword);

            plan.param = param;
            plan.fake_ua = 1;
            plan.auth = 0;
            plan.method = "GET";
            plan.resource = "/admin.cgi";
        break;
        case SHOUT_PROTOCOL_HTTP:
            if (!(encmount = _shout_util_url_encode(self->mount))) {
                free(encvalue);
                return self->error = SHOUTERR_MALLOC;
            }

            param_template = "mode=updinfo&mount=%s&%s";
            param_len = strlen(param_template) + strlen(encvalue) + 1 + strlen(encmount);
            param = malloc(param_len);
            if (!param) {
                free(encmount);
                free(encvalue);
                return self->error = SHOUTERR_MALLOC;
            }
            snprintf(param, param_len, param_template, encmount, encvalue);
            free(encmount);

            plan.param = param;
            plan.auth = 1;
            plan.resource = "/admin/metadata";
        break;
        default:
            if (!(encmount = _shout_util_url_encode(self->mount))) {
                free(encvalue);
                return self->error = SHOUTERR_MALLOC;
            }
            if (!(encpassword = _shout_util_url_encode(self->password))) {
                free(encmount);
                free(encvalue);
                return self->error = SHOUTERR_MALLOC;
            }

            param_template = "mode=updinfo&pass=%s&mount=%s&%s";
            param_len = strlen(param_template) + strlen(encvalue) + 1 + strlen(encpassword) + strlen(self->mount);
            param = malloc(param_len);
            if (!param) {
                free(encpassword);
                free(encmount);
                free(encvalue);
                return self->error = SHOUTERR_MALLOC;
            }
            snprintf(param, param_len, param_template, encpassword, encmount, encvalue);
            free(encpassword);
            free(encmount);

            plan.param = param;
            plan.auth = 0;
            plan.method = "GET";
            plan.resource = "/admin.cgi";
        break;
    }

    free(encvalue);

    connection = shout_connection_new(self, shout_http_impl, &plan);
    if (!connection) {
        free(param);
        return self->error = SHOUTERR_MALLOC;
    }

    shout_connection_select_tlsmode(connection, self->tls_mode);
    shout_connection_set_nonblocking(connection, 0);

    connection->target_message_state = SHOUT_MSGSTATE_PARSED_FINAL;

    shout_connection_connect(connection, self);

    shout_connection_iter(connection, self);

    shout_connection_unref(connection);

    free(param);

    return SHOUTERR_SUCCESS;
}

/* getters/setters */
const char *shout_version(int *major, int *minor, int *patch)
{
    if (major)
        *major = LIBSHOUT_MAJOR;
    if (minor)
        *minor = LIBSHOUT_MINOR;
    if (patch)
        *patch = LIBSHOUT_MICRO;

    return VERSION;
}

int shout_get_errno(shout_t *self)
{
    return self->error;
}

const char *shout_get_error(shout_t *self)
{
    if (!self)
        return "Invalid shout_t";

    switch (self->error) {
    case SHOUTERR_SUCCESS:
        return "No error";
    case SHOUTERR_INSANE:
        return "Nonsensical arguments";
    case SHOUTERR_NOCONNECT:
        return "Couldn't connect";
    case SHOUTERR_NOLOGIN:
        return "Login failed";
    case SHOUTERR_SOCKET:
        return "Socket error";
    case SHOUTERR_MALLOC:
        return "Out of memory";
    case SHOUTERR_CONNECTED:
        return "Cannot set parameter while connected";
    case SHOUTERR_UNCONNECTED:
        return "Not connected";
    case SHOUTERR_BUSY:
        return "Socket is busy";
    case SHOUTERR_UNSUPPORTED:
        return "This libshout doesn't support the requested option";
    case SHOUTERR_NOTLS:
        return "TLS requested but not supported by peer";
    case SHOUTERR_TLSBADCERT:
        return "TLS connection can not be established because of bad certificate";
    case SHOUTERR_RETRY:
        return "Please retry current operation.";
    default:
        return "Unknown error";
    }
}

/* Returns:
 *   SHOUTERR_CONNECTED if the connection is open,
 *   SHOUTERR_UNCONNECTED if it has not yet been opened,
 *   or an error from try_connect, including SHOUTERR_BUSY
 */
int shout_get_connected(shout_t *self)
{
    int rc;

    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection && self->connection->current_message_state == SHOUT_MSGSTATE_SENDING1)
        return SHOUTERR_CONNECTED;
    if (self->connection && self->connection->current_message_state != SHOUT_MSGSTATE_SENDING1) {
        if ((rc = try_connect(self)) == SHOUTERR_SUCCESS)
            return SHOUTERR_CONNECTED;
        return rc;
    }

    return SHOUTERR_UNCONNECTED;
}

int shout_set_host(shout_t *self, const char *host)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (self->host)
        free(self->host);

    if ( !(self->host = _shout_util_strdup(host)) )
        return self->error = SHOUTERR_MALLOC;

    return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_host(shout_t *self)
{
    if (!self)
        return NULL;

    return self->host;
}

int shout_set_port(shout_t *self, unsigned short port)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    self->port = port;

    return self->error = SHOUTERR_SUCCESS;
}

unsigned short shout_get_port(shout_t *self)
{
    if (!self)
        return 0;

    return self->port;
}

int shout_set_password(shout_t *self, const char *password)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (self->password)
        free(self->password);

    if ( !(self->password = _shout_util_strdup(password)) )
        return self->error = SHOUTERR_MALLOC;

    return self->error = SHOUTERR_SUCCESS;
}

const char* shout_get_password(shout_t *self)
{
    if (!self)
        return NULL;

    return self->password;
}

int shout_set_mount(shout_t *self, const char *mount)
{
    size_t len;

    if (!self || !mount)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (self->mount)
        free(self->mount);

    len = strlen(mount) + 1;
    if (mount[0] != '/')
        len++;

    if ( !(self->mount = malloc(len)) )
        return self->error = SHOUTERR_MALLOC;

    snprintf(self->mount, len, "%s%s", mount[0] == '/' ? "" : "/", mount);

    return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_mount(shout_t *self)
{
    if (!self)
        return NULL;

    return self->mount;
}

int shout_set_name(shout_t *self, const char *name)
{
    return shout_set_meta(self, "name", name);
}

const char *shout_get_name(shout_t *self)
{
    return shout_get_meta(self, "name");
}

int shout_set_url(shout_t *self, const char *url)
{
    return shout_set_meta(self, "url", url);
}

const char *shout_get_url(shout_t *self)
{
    return shout_get_meta(self, "url");
}

int shout_set_genre(shout_t *self, const char *genre)
{
    return shout_set_meta(self, "genre", genre);
}

const char *shout_get_genre(shout_t *self)
{
    return shout_get_meta(self, "genre");
}

int shout_set_agent(shout_t *self, const char *agent)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (self->useragent)
        free(self->useragent);

    if ( !(self->useragent = _shout_util_strdup(agent)) )
        return self->error = SHOUTERR_MALLOC;

    return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_agent(shout_t *self)
{
    if (!self)
        return NULL;

    return self->useragent;
}


int shout_set_user(shout_t *self, const char *username)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (self->user)
        free(self->user);

    if ( !(self->user = _shout_util_strdup(username)) )
        return self->error = SHOUTERR_MALLOC;

    return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_user(shout_t *self)
{
    if (!self)
        return NULL;

    return self->user;
}

int shout_set_description(shout_t *self, const char *description)
{
    return shout_set_meta(self, "description", description);
}

const char *shout_get_description(shout_t *self)
{
    return shout_get_meta(self, "description");
}

int shout_set_dumpfile(shout_t *self, const char *dumpfile)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return SHOUTERR_CONNECTED;

    if (self->dumpfile)
        free(self->dumpfile);

    if ( !(self->dumpfile = _shout_util_strdup(dumpfile)) )
        return self->error = SHOUTERR_MALLOC;

    return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_dumpfile(shout_t *self)
{
    if (!self)
        return NULL;

    return self->dumpfile;
}

int shout_set_audio_info(shout_t *self, const char *name, const char *value)
{
    if (!self)
        return SHOUTERR_INSANE;

    return self->error = _shout_util_dict_set(self->audio_info, name, value);
}

const char *shout_get_audio_info(shout_t *self, const char *name)
{
    if (!self)
        return NULL;

    return _shout_util_dict_get(self->audio_info, name);
}

int shout_set_meta(shout_t *self, const char *name, const char *value)
{
    size_t i;

    if (!self || !name)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    for (i = 0; name[i]; i++)
        if ((name[i] < 'a' || name[i] > 'z') && (name[i] < '0' || name[i] > '9'))
            return self->error = SHOUTERR_INSANE;

    return self->error = _shout_util_dict_set(self->meta, name, value);
}

const char *shout_get_meta(shout_t *self, const char *name)
{
    if (!self)
        return NULL;

    return _shout_util_dict_get(self->meta, name);
}

int shout_set_public(shout_t *self, unsigned int public)
{
    if (!self || (public != 0 && public != 1))
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    self->public = public;

    return self->error = SHOUTERR_SUCCESS;
}

unsigned int shout_get_public(shout_t *self)
{
    if (!self)
        return 0;

    return self->public;
}

int shout_set_format(shout_t *self, unsigned int format)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (format != SHOUT_FORMAT_OGG && format != SHOUT_FORMAT_MP3 &&
        format != SHOUT_FORMAT_WEBM && format != SHOUT_FORMAT_WEBMAUDIO) {
        return self->error = SHOUTERR_UNSUPPORTED;
    }

    self->format = format;

    return self->error = SHOUTERR_SUCCESS;
}

unsigned int shout_get_format(shout_t* self)
{
    if (!self)
        return 0;

    return self->format;
}

int shout_set_protocol(shout_t *self, unsigned int protocol)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (protocol != SHOUT_PROTOCOL_HTTP &&
        protocol != SHOUT_PROTOCOL_XAUDIOCAST &&
        protocol != SHOUT_PROTOCOL_ICY &&
        protocol != SHOUT_PROTOCOL_ROARAUDIO) {
        return self->error = SHOUTERR_UNSUPPORTED;
    }

    self->protocol = protocol;

    return self->error = SHOUTERR_SUCCESS;
}

unsigned int shout_get_protocol(shout_t *self)
{
    if (!self)
        return 0;

    return self->protocol;
}

int shout_set_nonblocking(shout_t *self, unsigned int nonblocking)
{
    if (!self || (nonblocking != 0 && nonblocking != 1))
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    self->nonblocking = nonblocking;

    return SHOUTERR_SUCCESS;
}

unsigned int shout_get_nonblocking(shout_t *self)
{
    if (!self)
        return 0;

    return self->nonblocking;
}

/* TLS functions */
#ifdef HAVE_OPENSSL
int shout_set_tls(shout_t *self, int mode)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (mode != SHOUT_TLS_DISABLED &&
        mode != SHOUT_TLS_AUTO &&
        mode != SHOUT_TLS_AUTO_NO_PLAIN &&
        mode != SHOUT_TLS_RFC2818 &&
        mode != SHOUT_TLS_RFC2817)
        return self->error = SHOUTERR_UNSUPPORTED;

    self->tls_mode = mode;
    return SHOUTERR_SUCCESS;
}
int shout_get_tls(shout_t *self)
{
    if (!self)
        return SHOUTERR_INSANE;

    return self->tls_mode;
}

int shout_set_ca_directory(shout_t *self, const char *directory)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (self->ca_directory)
        free(self->ca_directory);

    if (!(self->ca_directory = _shout_util_strdup(directory)))
        return self->error = SHOUTERR_MALLOC;

    return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_ca_directory(shout_t *self)
{
    if (!self)
        return NULL;

    return self->ca_directory;
}

int shout_set_ca_file(shout_t *self, const char *file)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (self->ca_file)
        free(self->ca_file);

    if (!(self->ca_file = _shout_util_strdup(file)))
        return self->error = SHOUTERR_MALLOC;

    return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_ca_file(shout_t *self)
{
    if (!self)
        return NULL;

    return self->ca_file;
}

int shout_set_allowed_ciphers(shout_t *self, const char *ciphers)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (self->allowed_ciphers)
        free(self->allowed_ciphers);

    if (!(self->allowed_ciphers = _shout_util_strdup(ciphers)))
        return self->error = SHOUTERR_MALLOC;

    return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_allowed_ciphers(shout_t *self)
{
    if (!self)
        return NULL;

    return self->allowed_ciphers;
}

int shout_set_client_certificate(shout_t *self, const char *certificate)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (self->connection)
        return self->error = SHOUTERR_CONNECTED;

    if (self->client_certificate)
        free(self->client_certificate);

    if (!(self->client_certificate = _shout_util_strdup(certificate)))
        return self->error = SHOUTERR_MALLOC;

    return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_client_certificate(shout_t *self)
{
    if (!self)
        return NULL;

    return self->client_certificate;
}
#else
int shout_set_tls(shout_t *self, int mode)
{
    if (!self)
        return SHOUTERR_INSANE;

    if (mode == SHOUT_TLS_DISABLED)
        return SHOUTERR_SUCCESS;

    return self->error = SHOUTERR_UNSUPPORTED;
}

int shout_get_tls(shout_t *self)
{
    return SHOUT_TLS_DISABLED;
}

int shout_set_ca_directory(shout_t *self, const char *directory)
{
    if (!self)
        return SHOUTERR_INSANE;

    return self->error = SHOUTERR_UNSUPPORTED;
}

const char *shout_get_ca_directory(shout_t *self)
{
    return NULL;
}

int shout_set_ca_file(shout_t *self, const char *file)
{
    if (!self)
        return SHOUTERR_INSANE;

    return self->error = SHOUTERR_UNSUPPORTED;
}

const char *shout_get_ca_file(shout_t *self)
{
    return NULL;
}

int shout_set_allowed_ciphers(shout_t *self, const char *ciphers)
{
    if (!self)
        return SHOUTERR_INSANE;

    return self->error = SHOUTERR_UNSUPPORTED;
}
const char *shout_get_allowed_ciphers(shout_t *self)
{
    return NULL;
}

int shout_set_client_certificate(shout_t *self, const char *certificate)
{
    if (!self)
        return SHOUTERR_INSANE;
    return self->error = SHOUTERR_UNSUPPORTED;
}

const char *shout_get_client_certificate(shout_t *self)
{
    return NULL;
}
#endif

/* -- static function definitions -- */
static int try_connect(shout_t *self)
{
    int ret;

    if (!self->connection) {
        const shout_protocol_impl_t *impl = NULL;

        switch (shout_get_protocol(self)) {
            case SHOUT_PROTOCOL_HTTP:
                impl = shout_http_impl;
                memset(&(self->source_plan.http), 0, sizeof(self->source_plan.http));
                self->source_plan.http.is_source = 1;
                self->source_plan.http.auth = 1;
                self->source_plan.http.resource = self->mount;
            break;
            case SHOUT_PROTOCOL_XAUDIOCAST:
                impl = shout_xaudiocast_impl;
            break;
            case SHOUT_PROTOCOL_ICY:
                impl = shout_icy_impl;
            break;
            case SHOUT_PROTOCOL_ROARAUDIO:
                impl = shout_roaraudio_impl;
            break;
        }

        self->connection = shout_connection_new(self, impl, &(self->source_plan));
        shout_connection_select_tlsmode(self->connection, self->tls_mode);
        self->connection->target_message_state = SHOUT_MSGSTATE_SENDING1;
        shout_connection_connect(self->connection, self);
    }

    ret = shout_connection_iter(self->connection, self);

    if (self->connection->current_message_state == SHOUT_MSGSTATE_SENDING1 && !self->send) {
        int rc;
        switch (self->format) {
            case SHOUT_FORMAT_OGG:
                rc = self->error = shout_open_ogg(self);
                break;
            case SHOUT_FORMAT_MP3:
                rc = self->error = shout_open_mp3(self);
                break;
            case SHOUT_FORMAT_WEBM:
            case SHOUT_FORMAT_WEBMAUDIO:
                rc = self->error = shout_open_webm(self);
                break;

            default:
                rc = SHOUTERR_INSANE;
                break;
        }
        if (rc != SHOUTERR_SUCCESS) {
            return ret;
        }
    }

    return ret;
}
