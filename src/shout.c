/* -*- c-basic-offset: 8; -*- */
/* shout.c: Implementation of public libshout interface shout.h */

#ifdef HAVE_CONFIG_H
 #include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <shout/shout.h>
#include <net/sock.h>
#include <timing/timing.h>
#include <httpp/httpp.h>

#include "shout_private.h"
#include "util.h"

/* -- local prototypes -- */
static int login_xaudiocast(shout_t *self);
static int login_icy(shout_t *self);
static int login_http_basic(shout_t *self);
char *http_basic_authorization(shout_t *self);

/* -- public functions -- */

shout_t *shout_new(void)
{
	shout_t *self;

	if (!(self = (shout_t *)calloc(1, sizeof(shout_t)))) {
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
	if (!(self->audio_info = util_dict_new())) {
		shout_free(self);

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
	if (self->audio_info) util_dict_free (self->audio_info);

	free(self);
}

int shout_open(shout_t *self)
{
	/* sanity check */
	if (!self)
		return SHOUTERR_INSANE;

	if (!self->host || !self->password || !self->port || self->connected)
		return self->error = SHOUTERR_INSANE;

	if (self->format == SHOUT_FORMAT_VORBIS && self->protocol != SHOUT_PROTOCOL_HTTP)
		return self->error = SHOUTERR_UNSUPPORTED;

	if(self->protocol != SHOUT_PROTOCOL_HTTP) {
		if (self->protocol == SHOUT_PROTOCOL_ICY)
			self->socket = sock_connect(self->host, self->port+1);
		else
			self->socket = sock_connect(self->host, self->port);
		if (self->socket <= 0)
			return self->error = SHOUTERR_NOCONNECT;
	}

	if (self->protocol == SHOUT_PROTOCOL_HTTP) {
		if ((self->error = login_http_basic(self)) != SHOUTERR_SUCCESS) {
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

	self->error = SHOUTERR_SUCCESS;

	while(remaining) {
		ret = sock_write_bytes(self->socket, data, remaining);
		if(ret == (ssize_t)remaining)
			return len;
		else if(ret < 0) {
			if(errno == EINTR)
				ret = 0;
			else {
				self->error = SHOUTERR_SOCKET;
				return -1;
			}
		}
		remaining -= ret;
	}

	return len;
}

void shout_sync(shout_t *self)
{
	int64_t sleep;

	if (!self)
		return;

	if (self->senttime == 0)
		return;

	sleep = ((double)self->senttime / 1000) - (timing_get_time() - self->starttime);

	if (sleep > 0)
		timing_sleep((uint64_t)sleep);
}

int shout_delay(shout_t *self)
{
	if (!self)
		return 0;

	if (self->senttime == 0)
		return 0;

	/* Is this cast to double needed? */
	return (double)self->senttime / 1000 - (timing_get_time() - self->starttime);
}
  
shout_metadata_t *shout_metadata_new(void)
{
	return util_dict_new();
}

void shout_metadata_free(shout_metadata_t *self)
{
	if (!self)
		return;

	util_dict_free(self);
}

int shout_metadata_add(shout_metadata_t *self, const char *name, const char *value)
{
	if (!self || !name)
		return SHOUTERR_INSANE;

	return util_dict_set(self, name, value);
}

/* open second socket to server, send HTTP request to change metadata.
 * TODO: prettier error-handling. */
int shout_set_metadata(shout_t *self, shout_metadata_t *metadata)
{
	sock_t socket;
	int rv;
	char *encvalue;

	if (!self || !metadata)
		return SHOUTERR_INSANE;

	if (!(encvalue = util_dict_urlencode(metadata, '&')))
		return SHOUTERR_MALLOC;

	if (!self->connected)
		return SHOUTERR_UNCONNECTED;
	if ((socket = sock_connect(self->host, self->port)) <= 0)
		return SHOUTERR_NOCONNECT;

	if (self->protocol == SHOUT_PROTOCOL_ICY)
		rv = sock_write(socket, "GET /admin.cgi?mode=updinfo&pass=%s&%s HTTP/1.0\r\nUser-Agent: %s (Mozilla compatible)\r\n\r\n",
		  self->password, encvalue, shout_get_agent(self));
	else if (self->protocol == SHOUT_PROTOCOL_HTTP) {
		char *auth = http_basic_authorization(self);

		rv = sock_write(socket, "GET /admin/metadata?mode=updinfo&mount=%s&%s HTTP/1.0\r\nUser-Agent: %s\r\n%s\r\n",
		  self->mount, encvalue, shout_get_agent(self), auth ? auth : "");
	} else
		rv = sock_write(socket, "GET /admin.cgi?mode=updinfo&pass=%s&mount=%s&%s HTTP/1.0\r\nUser-Agent: %s\r\n\r\n",
		  self->password, self->mount, encvalue, shout_get_agent(self));
	free(encvalue);
	if (!rv) {
		sock_close(socket);
		return SHOUTERR_SOCKET;
	}

	sock_close(socket);

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
	case SHOUTERR_UNSUPPORTED:
		return "This libshout doesn't support the requested option";
	default:
		return "Unknown error";
	}
}

int shout_get_connected(shout_t *self)
{
	if (self->connected)
		return SHOUTERR_CONNECTED;
	else
		return SHOUTERR_UNCONNECTED;
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
	size_t len;

	if (!self || !mount)
		return SHOUTERR_INSANE;

	if (self->connected)
		return self->error = SHOUTERR_CONNECTED;
	
	if (self->mount)
		free(self->mount);

	len = strlen (mount) + 1;
	if (mount[0] != '/')
		len++;

	if (!(self->mount = malloc(len)))
		return self->error = SHOUTERR_MALLOC;

	sprintf (self->mount, "%s%s", mount[0] == '/' ? "" : "/", mount);

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

int shout_set_dumpfile(shout_t *self, const char *dumpfile)
{
	if (!self)
		return SHOUTERR_INSANE;

	if (self->connected)
		return SHOUTERR_CONNECTED;

	if (self->dumpfile)
		free(self->dumpfile);

	if (! (self->dumpfile = util_strdup (dumpfile)))
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
	return self->error = util_dict_set(self->audio_info, name, value);
}

const char *shout_get_audio_info(shout_t *self, const char *name)
{
	return util_dict_get(self->audio_info, name);
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

	if (protocol != SHOUT_PROTOCOL_HTTP &&
	    protocol != SHOUT_PROTOCOL_XAUDIOCAST &&
	    protocol != SHOUT_PROTOCOL_ICY)
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
	char *auth;
	char *ai;

	if (!sock_write(self->socket, "SOURCE %s HTTP/1.0\r\n", self->mount))
		return SHOUTERR_SOCKET;

	if (self->password && (auth = http_basic_authorization(self))) {
		if (!sock_write(self->socket, auth)) {
			free(auth);
			return SHOUTERR_SOCKET;
		}
		free(auth);
	}

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
#if 0
	ai = shout_get_audio_info(self, SHOUT_AI_BITRATE);

	if (bitrate && !sock_write(self->socket, "ice-bitrate: %s\r\n", bitrate))
		return SHOUTERR_SOCKET;
#else
	if ((ai = util_dict_urlencode(self->audio_info, ';'))) {
		if (!sock_write(self->socket, "ice-audio-info: %s\r\n", ai)) {
			free(ai);
			return SHOUTERR_SOCKET;
		}
	}
#endif
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
		if (!sock_write(self->socket, "Content-Type: application/ogg\r\n"))
			return SHOUTERR_SOCKET;
	} else if (self->format == SHOUT_FORMAT_MP3) {
		if (!sock_write(self->socket, "Content-Type: audio/mpeg\r\n"))
			return SHOUTERR_SOCKET;
	}

	if (!sock_write(self->socket, "\r\n"))
		return SHOUTERR_SOCKET;

	return SHOUTERR_SUCCESS;
}

char *http_basic_authorization(shout_t *self)
{
	char *out, *in;
	int len;

	if (!self || !self->user || !self->password)
		return NULL;

	len = strlen(self->user) + strlen(self->password) + 2;
	if (!(in = malloc(len)))
		return NULL;
	sprintf(in, "%s:%s", self->user, self->password);
	out = util_base64_encode(in);
	free(in);

	len = strlen(out) + 24;
	if (!(in = malloc(len))) {
		free(out);
		return NULL;
	}
	sprintf(in, "Authorization: Basic %s\r\n", out);
	free(out);
	
	return in;
}

static int login_http_basic(shout_t *self)
{
	char header[4096];
	http_parser_t *parser;
	int code;
	char *retcode;
#if 0
	char *realm;
#endif
    
	self->error = SHOUTERR_SOCKET;

   	self->socket = sock_connect(self->host, self->port);
	if (self->socket < 0) {
		return self->error = SHOUTERR_NOCONNECT;
	}

#if 0
	if(send_http_request(self, NULL, NULL) != 0) {
#else
	/* assume we'll have to authenticate, saves round trips on basic */
	if(send_http_request(self, self->user, self->password) != 0) {
#endif
		return self->error = SHOUTERR_SOCKET;
	}

	if (util_read_header(self->socket, header, 4096) == 0) {
		/* either we didn't get a complete header, or we timed out */
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
#if 0
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
#endif
	}

	httpp_destroy(parser);
	return self->error = SHOUTERR_NOLOGIN;
}

static int login_xaudiocast(shout_t *self)
{
	char response[4096];
	const char *bitrate;

	bitrate = shout_get_audio_info(self, SHOUT_AI_BITRATE);
	if (!bitrate)
		bitrate = "0";

	if (!sock_write(self->socket, "SOURCE %s %s\n", self->password, self->mount))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-name: %s\n", self->name != NULL ? self->name : "unnamed"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-url: %s\n", self->url != NULL ? self->url : "http://www.icecast.org/"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-genre: %s\n", self->genre != NULL ? self->genre : "icecast"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-bitrate: %s\n", bitrate))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-public: %i\n", self->public))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "x-audiocast-description: %s\n", self->description != NULL ? self->description : "Broadcasting with the icecast streaming media server!"))
		return SHOUTERR_SOCKET;
	if (self->dumpfile && !sock_write(self->socket, "x-audiocast-dumpfile: %s\n", self->dumpfile))
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
	const char *bitrate;

	bitrate = shout_get_audio_info(self, SHOUT_AI_BITRATE);
	if (!bitrate)
		bitrate = "0";

	if (!sock_write(self->socket, "%s\n", self->password))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-name:%s\n", self->name != NULL ? self->name : "unnamed"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-url:%s\n", self->url != NULL ? self->url : "http://www.icecast.org/"))
		return SHOUTERR_SOCKET;

	/* Fields we don't use */
	if (!sock_write(self->socket, "icy-irc:\nicy-aim:\nicy-icq:\n"))
		return SHOUTERR_SOCKET;

	if (!sock_write(self->socket, "icy-pub:%i\n", self->public))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-genre:%s\n", self->genre != NULL ? self->genre : "icecast"))
		return SHOUTERR_SOCKET;
	if (!sock_write(self->socket, "icy-br:%s\n", bitrate))
		return SHOUTERR_SOCKET;

	if (!sock_write(self->socket, "\n"))
		return SHOUTERR_SOCKET;

	if (!sock_read_line(self->socket, response, sizeof(response)))
		return SHOUTERR_SOCKET;

	if (!strstr(response, "OK"))
		return SHOUTERR_NOLOGIN;

	return SHOUTERR_SUCCESS;
}
