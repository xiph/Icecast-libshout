/* shout.h: Private libshout data structures and declarations */

#ifndef __LIBSHOUT_SHOUT_PRIVATE_H__
#define __LIBSHOUT_SHOUT_PRIVATE_H__

#include <shout/shout.h>
#include <net/sock.h>
#include <timing/timing.h>
#include "util.h"

#include <sys/types.h>
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#elif defined (HAVE_INTTYPES_H)
#  include <inttypes.h>
#endif

#ifndef HAVE_C99_INTTYPES
#  if SIZEOF_SHORT == 4
typedef unsigned short uint32_t;
#  elif SIZEOF_INT == 4
typedef unsigned int uint32_t;
#  elif SIZEOF_LONG == 4
typedef unsigned long uint32_t;
#  endif
#  if SIZEOF_INT == 8
typedef unsigned int uint64_t;
#  elif SIZEOF_LONG == 8
typedef unsigned long uint64_t;
#  elif SIZEOF_LONG_LONG == 8
typedef unsigned long long uint64_t;
#  endif
#endif

#define LIBSHOUT_DEFAULT_HOST "localhost"
#define LIBSHOUT_DEFAULT_PORT 8000
#define LIBSHOUT_DEFAULT_FORMAT SHOUT_FORMAT_VORBIS
#define LIBSHOUT_DEFAULT_PROTOCOL SHOUT_PROTOCOL_HTTP
#define LIBSHOUT_DEFAULT_USER "source"
#define LIBSHOUT_DEFAULT_USERAGENT "libshout/" VERSION

struct shout {
	/* hostname or IP of icecast server */
	char *host;
	/* port of the icecast server */
	int port;
	/* login password for the server */
	char *password;
	/* server protocol to use */
	unsigned int protocol;
	/* type of data being sent */
	unsigned int format;
	/* audio encoding parameters */
	util_dict *audio_info;

	/* user-agent to use when doing HTTP login */
	char *useragent;
	/* mountpoint for this stream */
	char *mount;
	/* name of the stream */
	char *name;
	/* homepage of the stream */
	char *url;
	/* genre of the stream */
	char *genre;
	/* description of the stream */
	char *description;
	/* icecast 1.x dumpfile */
	char *dumpfile;
	/* username to use for HTTP auth. */
	char *user;
	/* is this stream private? */
	int public;

	/* are we connected to a server? */
	int connected;
	/* socket the connection is on */
	sock_t socket;

	void *format_data;
	int (*send)(shout_t* self, const unsigned char* buff, size_t len);
	void (*close)(shout_t* self);

	/* start of this period's timeclock */
	uint64_t starttime;
	/* amout of data we've sent (in milliseconds) */
	uint64_t senttime;

	int error;
};

int shout_open_vorbis(shout_t *self);
int shout_open_mp3(shout_t *self);

#endif /* __LIBSHOUT_SHOUT_PRIVATE_H__ */
