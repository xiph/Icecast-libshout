/*  shout.h
**
**  api for libshout, the streaming library for icecast
*/
#ifndef __LIBSHOUT_SHOUT_H__
#define __LIBSHOUT_SHOUT_H__

#ifdef _WIN32
typedef int64_t __int64
typedef uint64_t unsigned __int64
#else
# ifdef __GLIBC__
#  include <stdint.h>
# endif
#endif

#include <sys/types.h>

#include <ogg/ogg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHOUTERR_INSANE		1
#define SHOUTERR_NOCONNECT	2
#define SHOUTERR_NOLOGIN	3
#define SHOUTERR_SOCKET		4
#define SHOUTERR_MALLOC		5
#define SHOUTERR_METADATA	6

typedef struct {
	char *ip;		/* ip of the icecast server (NOT A HOSTNAME) */
	int port;		/* port of the icecast server */
	char *mount;		/* mountpoint for this stream */

	int connected;		/* are we connected to a server? */
	int _socket;		/* internal - socket the connection is on */

	char *password;		/* login password for the server */
	char *name;		/* name of the stream */
	char *url;		/* homepage of the stream */
	char *genre;		/* genre of the stream */
	char *description;	/* description of the stream */
	int bitrate;		/* bitrate of this stream */
	int ispublic;		/* is this stream private? */
	int error;
	int pages;		/* total pages broadcasted */

	uint64_t _starttime;	/* start of this period's timeclock */
	uint64_t _senttime;	/* amout of data we've sent (in milliseconds) */
	int _samples;	        /* the number of samples for the current page */
	int _oldsamples;
	int _samplerate;  	/* the samplerate of the stream */

	ogg_sync_state _oy;
	long _serialno;
} shout_conn_t;


/*
** shout_init_connection
**
** initializes the shout_conn_t structure
*/
void shout_init_connection(shout_conn_t *self);

/*
** shout_connect
**  
** opens a connection to an icecast server, and logs in
*/
int shout_connect(shout_conn_t *self);

/*
** shout_disconnect
**
** closes a connection to an icecast server
*/
int shout_disconnect(shout_conn_t *self);

/*
** shout_send_data
** 
** sends a block of data (buffsize bytes in buff) to the icecast
** server at the correct rate (calculated by the bitrate in the mp3
** frame headers
*/
int shout_send_data(shout_conn_t *self, unsigned char *buff, unsigned long len);

/*
** shout_sleep
**
** sleeps if need be
**
*/
void shout_sleep(shout_conn_t *self);

/*
** shout_strerror
**
** Formats the error code to a user readable string, like strerror()
** Returns pointer to namespace.
*/
char *shout_strerror(shout_conn_t *self, int error);

#ifdef __cplusplus
}
#endif

#endif /* __LIBSHOUT_SHOUT_H__ */
