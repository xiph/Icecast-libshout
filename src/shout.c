/* shout.c: Implementation of public libshout interface shout.h */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "shout.h"
#include "shout_private.h"

#include "sock.h"
#include "timing.h"
#include "util.h"
#include "httpp/httpp.h"

/* -- local prototypes -- */
static int login_ice(shout_t *self);
static int login_xaudiocast(shout_t *self);
static int login_icy(shout_t *self);
static int login_http_basic(shout_t *self);

/* -- public functions -- */

shout_t *shout_new(void)
{
	shout_t *self;

	if (!(self = (struct shout *)calloc(1, sizeof(shout_t)))) {
		return NULL;
	}

	if (!(self->host = util_strdup(LIBSHOUT_DEFAULT_HOST))) {
		free(self);
		return NULL;
	}

	self->port = LIBSHOUT_DEFAULT_PORT;
	self->format = LIBSHOUT_DEFAULT_FORMAT;
	self->protocol = LIBSHOUT_DEFAULT_PROTOCOL;

	return self;
}

void shout_free(shout_t *self)
{
	if (!self) return;

	if (self->host) free(self->host);
	if (self->password) free(self->password);
	if (self->mount) free(self->mount);
	if (self->name) free(self->name);
	if (self->url) free(self->url);
	if (self->genre) free(self->genre);
	if (self->description) free(self->description);
	if (self->user) free(self->user);
    if (self->useragent) free(self->useragent);

	free(self);
}

int shout_open(shout_t *self)
{
	/* sanity check */
	if (!self)
		return SHOUTERR_INSANE;

	if (!self->host || !self->password || !self->port || self->connected)
		return self->error = SHOUTERR_INSANE;

	if (self->format == SHOUT_FORMAT_VORBIS && self->protocol != SHOUT_PROTOCOL_ICE && self->protocol != SHOUT_PROTOCOL_HTTP)
		return self->error = SHOUTERR_UNSUPPORTED;

    if(self->protocol != SHOUT_PROTOCOL_HTTP) {
    	self->socket = sock_connect(self->host, self->port);
	    if (self->socket <= 0)
		    return self->error = SHOUTERR_NOCONNECT;
    }

    if (self->protocol == SHOUT_PROTOCOL_HTTP) {
        if ((self->error = login_http_basic(self)) != SHOUTERR_SUCCESS)
            return self->error;
    }
    else if (self->protocol == SHOUT_PROTOCOL_ICE) {
		if ((self->error = login_ice(self)) != SHOUTERR_SUCCESS) {
			sock_close(self->socket);
			return self->error;
		}
	} else if (self->protocol == SHOUT_PROTOCOL_XAUDIOCAST) {
		if ((self->error = login_xaudiocast(self)) != SHOUTERR_SUCCESS) {
			sock_close(self->socket);
			return self->error;
		}
	} else if (self->protocol == SHOUT_PROTOCOL_ICY) {
		if ((self->error = login_icy(self)) != SHOUTERR_SUCCESS) {
			sock_close(self->socket);
			return self->error;
		}
		
	} else
		return self->error = SHOUTERR_INSANE;
  
	if (self->format == SHOUT_FORMAT_VORBIS) {
		if ((self->error = shout_open_vorbis(self)) != SHOUTERR_SUCCESS) {
			sock_close(self->socket);
			return self->error;
		}
	} else if (self->format == SHOUT_FORMAT_MP3) {
		if ((self->error = shout_open_mp3(self)) != SHOUTERR_SUCCESS) {
			sock_close(self->socket);
			return self->error;
		}
	} else {
		sock_close(self->socket);
		return self->error = SHOUTERR_INSANE;
	}

	self->connected = 1;

	return self->error;
}


int shout_close(shout_t *self)
{
	if (!self)
		return SHOUTERR_INSANE;

	if (!self->connected)
		return self->error = SHOUTERR_UNCONNECTED;

	if (self->close)
		self->close(self);

	sock_close(self->socket);
	self->connected = 0;

	return self->error = SHOUTERR_SUCCESS;
}

int shout_send(shout_t *self, const unsigned char *data, size_t len)
{
	if (!self)
		return SHOUTERR_INSANE;

	if (!self->connected)
		return self->error = SHOUTERR_UNCONNECTED;

	if (self->starttime <= 0)
		self->starttime = timing_get_time();

	return self->send(self, data, len);
}

ssize_t shout_send_raw(shout_t *self, const unsigned char *data, size_t len)
{
	ssize_t ret;
    size_t remaining = len;

	if (!self) 
		return -1;

	while(remaining) {
		ret = sock_write_bytes(self->socket, data, remaining);
        if(ret < (ssize_t)remaining || errno == EINTR) {
            remaining -= (ret>0)?ret:0;
            continue;
        }
        else if(ret < 0) {
            self->error = SHOUTERR_SOCKET;
            return -1;
        }
        remaining = 0;
	}

	self->error = SHOUTERR_SUCCESS;
	return len;
}

void shout_sync(shout_t *self)
{
	uint64_t sleep;

	if (!self)
		return;

	if (self->senttime == 0)
		return;

	sleep = ((double)self->senttime / 1000) - (timing_get_time() - self->starttime);

	if (sleep > 0)
		timing_sleep(sleep);
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
	case SHOUTERR_UNSUPPORTED:
		return "This libshout doesn't support the requested option";
	default:
		return "Unknown error";
	}
}

int shout_set_host(shout_t *self, const char *host)
{
	if (!self)
		return SHOUTERR_INSANE;

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (self->host)
		free(self->host);

	if (!(self->host = util_strdup(host)))
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

	if (self->connected)
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

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (self->password)
		free (self->password);

	if (!(self->password = util_strdup(password)))
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
	if (!self)
		return SHOUTERR_INSANE;

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (self->mount)
		free(self->mount);

	if (!(self->mount = util_strdup(mount)))
		return self->error = SHOUTERR_MALLOC;

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
	if (!self)
		return SHOUTERR_INSANE;

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (self->name)
		free(self->name);

	if (!(self->name = util_strdup(name)))
		return self->error = SHOUTERR_MALLOC;

	return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_name(shout_t *self)
{
	if (!self)
		return NULL;

	return self->name;
}

int shout_set_url(shout_t *self, const char *url)
{
	if (!self)
		return SHOUTERR_INSANE;

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (self->url)
		free(self->url);

	if (!(self->url = util_strdup(url)))
		return self->error = SHOUTERR_MALLOC;

	return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_url(shout_t *self)
{
	if (!self)
		return NULL;

	return self->url;
}

int shout_set_genre(shout_t *self, const char *genre)
{
	if (!self)
		return SHOUTERR_INSANE;

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (self->genre)
		free(self->genre);

	if (! (self->genre = util_strdup (genre)))
		return self->error = SHOUTERR_MALLOC;

	return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_genre(shout_t *self)
{
	if (!self)
		return NULL;

	return self->genre;
}

int shout_set_agent(shout_t *self, const char *agent)
{
	if (!self)
		return SHOUTERR_INSANE;

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (self->useragent)
		free(self->useragent);

	if (! (self->useragent = util_strdup (agent)))
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

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (self->user)
		free(self->user);

	if (! (self->user = util_strdup (username)))
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
	if (!self)
		return SHOUTERR_INSANE;

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (self->description)
		free(self->description);

	if (! (self->description = util_strdup (description)))
		return self->error = SHOUTERR_MALLOC;

	return self->error = SHOUTERR_SUCCESS;
}

const char *shout_get_description(shout_t *self)
{
	if (!self)
		return NULL;

	return self->description;
}

int shout_set_bitrate(shout_t *self, unsigned int bitrate)
{
	if (!self)
		return SHOUTERR_INSANE;

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	self->bitrate = bitrate;

	return self->error = SHOUTERR_SUCCESS;
}

unsigned int shout_get_bitrate(shout_t *self)
{
	if (!self)
		return 0;

	return self->bitrate;
}

int shout_set_public(shout_t *self, unsigned int public)
{
	if (!self || (public != 0 && public != 1))
		return SHOUTERR_INSANE;

	if (self->connected)
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

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (format != SHOUT_FORMAT_VORBIS && format != SHOUT_FORMAT_MP3)
		return self->error = SHOUTERR_UNSUPPORTED;

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

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;

	if (protocol != SHOUT_PROTOCOL_ICE &&
	    protocol != SHOUT_PROTOCOL_XAUDIOCAST &&
	    protocol != SHOUT_PROTOCOL_ICY &&
        protocol != SHOUT_PROTOCOL_HTTP)
		return self->error = SHOUTERR_UNSUPPORTED;

	self->protocol = protocol;

	return self->error = SHOUTERR_SUCCESS;
}

unsigned int shout_get_protocol(shout_t *self)
{
	if (!self)
		return 0;

	return self->protocol;
}

/* -- static function definitions -- */

static int send_http_request(shout_t *self, char *username, char *password)
{
    if (!sock_write(self->socket, "SOURCE %s HTTP/1.0\r\n", self->mount))
		return SHOUTERR_SOCKET;

	if (!sock_write(self->socket, "ice-name: %s\r\n", self->name != NULL ? self->name : "no name"))
		return SHOUTERR_SOCKET;
	if (self->url) {
		if (!sock_write(self->socket, "ice-url: %s\r\n", self->url))
			return SHOUTERR_SOCKET;
	}
	if (self->genre) {
		if (!sock_write(self->socket, "ice-genre: %s\r\n", self->genre))
			return SHOUTERR_SOCKET;
	}
	if (!sock_write(self->socket, "ice-bitrate: %d\r\n", self->bitrate))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "ice-public: %d\r\n", self->public))
		return SHOUTERR_SOCKET;
	if (self->description) {
		if (!sock_write(self->socket, "ice-description: %s\r\n", self->description))
			return SHOUTERR_SOCKET;
	}
    if (self->useragent) {
        if (!sock_write(self->socket, "User-Agent: %s\r\n", self->useragent))
            return SHOUTERR_SOCKET;
    }
	if (self->format == SHOUT_FORMAT_VORBIS) {
		if (!sock_write(self->socket, "Content-Type: application/x-ogg\r\n"))
			return SHOUTERR_SOCKET;
	} else if (self->format == SHOUT_FORMAT_MP3) {
		if (!sock_write(self->socket, "Content-Type: audio/mpeg\r\n"))
			return SHOUTERR_SOCKET;
	}
    if (username && password) {
        char *data;
        int len = strlen(username) + strlen(password) + 2;
        char *orig = malloc(len);
        strcpy(orig, username);
        strcat(orig, ":");
        strcat(orig, password);

        data = util_base64_encode(orig);

        if(!sock_write(self->socket, "Authorization: Basic %s\r\n", data)) {
            free(data);
            return SHOUTERR_SOCKET;
        }
        free(data);
    }

	if (!sock_write(self->socket, "\r\n"))
		return SHOUTERR_SOCKET;

	return SHOUTERR_SUCCESS;
}


static int login_http_basic(shout_t *self)
{
    char header[4096];
    http_parser_t *parser;
    int code;
    char *retcode, *realm;
    
    self->error = SHOUTERR_SOCKET;

   	self->socket = sock_connect(self->host, self->port);
    if (self->socket <= 0) {
	    return self->error = SHOUTERR_NOCONNECT;
    }

    if(send_http_request(self, NULL, NULL) != 0) {
        sock_close(self->socket);
        return self->error = SHOUTERR_SOCKET;
    }

    if (util_read_header(self->socket, header, 4096) == 0) {
        /* either we didn't get a complete header, or we timed out */
        sock_close(self->socket);
	    return self->error = SHOUTERR_SOCKET;
    }

    parser = httpp_create_parser();
    httpp_initialize(parser, NULL);
    if (httpp_parse_response(parser, header, strlen(header), self->mount)) {
        retcode = httpp_getvar(parser, HTTPP_VAR_ERROR_CODE);
        code = atoi(retcode);
        if(code >= 200 && code < 300) {
            httpp_destroy(parser);
	        return SHOUTERR_SUCCESS;
        }
        else if(code == 401) {
            /* Don't really use this right now other than to check that it's
             * present.
             */
            realm = httpp_getvar(parser, "www-authenticate");
            if(realm) {
                httpp_destroy(parser);
                sock_close(self->socket);

   	            self->socket = sock_connect(self->host, self->port);
                if (self->socket <= 0)
            	    return self->error = SHOUTERR_NOCONNECT;

                if(send_http_request(self, self->user, self->password) != 0) {
                    sock_close(self->socket);
                    return self->error = SHOUTERR_SOCKET;
                }

                if (util_read_header(self->socket, header, 4096) == 0) {
                    /* either we didn't get a complete header, or we timed out */
                    sock_close(self->socket);
	                return self->error = SHOUTERR_SOCKET;
                }
                parser = httpp_create_parser();
                httpp_initialize(parser, NULL);
                if (httpp_parse_response(parser, header, strlen(header), self->mount)) {
                    retcode = httpp_getvar(parser, HTTPP_VAR_ERROR_CODE);
                    code = atoi(retcode);
                    if(code >= 200 && code < 300) {
                        httpp_destroy(parser);
            	        return SHOUTERR_SUCCESS;
                    }
                }
            }
        }
    }

    httpp_destroy(parser);
    sock_close(self->socket);
    return self->error = SHOUTERR_REFUSED;
}

static int login_ice(shout_t *self)
{
	self->error = SHOUTERR_SOCKET;

	if (!sock_write(self->socket, "SOURCE %s ICE/1.0\n", self->mount))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "ice-password: %s\n", self->password))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "ice-name: %s\n", self->name != NULL ? self->name : "no name"))
		return SHOUTERR_SOCKET;
	if (self->url) {
		if (!sock_write(self->socket, "ice-url: %s\n", self->url))
			return SHOUTERR_SOCKET;
	}
	if (self->genre) {
		if (!sock_write(self->socket, "ice-genre: %s\n", self->genre))
			return SHOUTERR_SOCKET;
	}
	if (!sock_write(self->socket, "ice-bitrate: %d\n", self->bitrate))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "ice-public: %d\n", self->public))
		return SHOUTERR_SOCKET;
	if (self->description) {
		if (!sock_write(self->socket, "ice-description: %s\n", self->description))
			return SHOUTERR_SOCKET;
	}
	if (self->format == SHOUT_FORMAT_VORBIS) {
		if (!sock_write(self->socket, "Content-Type: application/x-ogg\n"))
			return SHOUTERR_SOCKET;
	} else if (self->format == SHOUT_FORMAT_MP3) {
		if (!sock_write(self->socket, "Content-Type: audio/mpeg\n"))
			return SHOUTERR_SOCKET;
	}

	if (!sock_write(self->socket, "\n"))
		return SHOUTERR_SOCKET;

	return SHOUTERR_SUCCESS;
}

static int login_xaudiocast(shout_t *self)
{
	char response[4096];

	if (!sock_write(self->socket, "SOURCE %s %s\n", self->password, self->mount))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-name: %s\n", self->name != NULL ? self->name : "unnamed"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-url: %s\n", self->url != NULL ? self->url : "http://www.icecast.org/"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-genre: %s\n", self->genre != NULL ? self->genre : "icecast"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-bitrate: %i\n", self->bitrate))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-public: %i\n", self->public))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-description: %s\n", self->description != NULL ? self->description : "Broadcasting with the icecast streaming media server!"))
		return SHOUTERR_SOCKET;

	if (!sock_write(self->socket, "\n"))
		return SHOUTERR_SOCKET;

	if (!sock_read_line(self->socket, response, sizeof(response)))
		return SHOUTERR_SOCKET;

	if (!strstr(response, "OK"))
		return SHOUTERR_NOLOGIN;

	return SHOUTERR_SUCCESS;
}

int login_icy(shout_t *self)
{
	char response[4096];

	if (!sock_write(self->socket, "%s\n", self->password))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-name:%s\n", self->name != NULL ? self->name : "unnamed"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-url:%s\n", self->url != NULL ? self->url : "http://www.icecast.org/"))
		return SHOUTERR_SOCKET;

#if 0
	/* Fields we don't use */
	if (!sock_write(self->socket, "icy-irc:%s\n", self->irc != NULL ? self->irc : ""))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-aim:%s\n", self->aim != NULL ? self->aim : ""))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-icq:%s\n", self->icq != NULL ? self->icq : ""))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-pub:%i\n", self->ispublic))
		return SHOUTERR_SOCKET;
#endif

	if (!sock_write(self->socket, "icy-genre:%s\n", self->genre != NULL ? self->genre : "icecast"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-br:%i\n", self->bitrate))
		return SHOUTERR_SOCKET;

	if (!sock_write(self->socket, "\n"))
		return SHOUTERR_SOCKET;

	if (!sock_read_line(self->socket, response, sizeof(response)))
		return SHOUTERR_SOCKET;

	if (!strstr(response, "OK"))
		return SHOUTERR_NOLOGIN;

	return SHOUTERR_SUCCESS;
}
