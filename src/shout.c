#include <stdio.h>
#include <string.h>

#include <ogg/ogg.h>
#include <vorbis/codec.h>

#include "sock.h"

#include "shout.h"
#include "timing.h"

int _login(shout_conn_t *self)
{
	int res;

	res = sock_write(self->_socket, "SOURCE %s ICE/1.0\n", self->mount);
	if (!res) return 0;

	res = sock_write(self->_socket, "ice-password: %s\n", self->password);
	if (!res) return 0;

	res = sock_write(self->_socket, "ice-name: %s\n", self->name != NULL ? self->name : "no name");
	if (!res) return 0;

	if (self->url) {
		res = sock_write(self->_socket, "ice-url: %s\n", self->url);
		if (!res) return 0;
	}

	if (self->genre) {
		res = sock_write(self->_socket, "ice-genre: %s\n", self->genre);
		if (!res) return 0;
	}

	res = sock_write(self->_socket, "ice-bitrate: %d\n", self->bitrate);
	if (!res) return 0;

	res = sock_write(self->_socket, "ice-public: %d\n", self->ispublic);
	if (!res) return 0;

	if (self->description) {
		res = sock_write(self->_socket, "ice-description: %s\n", self->description);
		if (!res) return 0;
	}

	res = sock_write(self->_socket, "\n");
	if (!res) return 0;

	return 1;
}

void shout_init_connection(shout_conn_t *self)
{
	memset(self, 0, sizeof(shout_conn_t));
}

int shout_connect(shout_conn_t *self)
{
	/* sanity check */
	if ((self->ip == NULL) || (self->password == NULL) || (self->port <= 0) || self->connected) {
		self->error = SHOUTERR_INSANE;
		return 0;
	}

	self->_socket = sock_connect(self->ip, self->port);
	if (self->_socket <= 0) {
		self->error = SHOUTERR_NOCONNECT;
		return 0;
	}

	if (_login(self)) {
		self->connected = 1;
		ogg_sync_init(&self->_oy);
		return 1;
	}

	self->error = SHOUTERR_NOLOGIN;
	return 0;
}

int shout_disconnect(shout_conn_t *self)
{
	if (!sock_valid_socket(self->_socket)) {
		self->error = SHOUTERR_INSANE;
		return 0;
	}

	ogg_sync_clear(&self->_oy);

	self->connected = 0;
	sock_close(self->_socket);

	return 1;
}

int shout_send_data(shout_conn_t *self, unsigned char *buff, unsigned long len)
{
	int ret;
	char *buffer;
	ogg_stream_state os;
	ogg_page og;
	ogg_packet op;
	vorbis_info vi;
	vorbis_comment vc;

	if (self->_starttime == 0) 
		self->_starttime = timing_get_time();

	buffer = ogg_sync_buffer(&self->_oy, len);
	memcpy(buffer, buff, len);
	ogg_sync_wrote(&self->_oy, len);

	while (ogg_sync_pageout(&self->_oy, &og) == 1) {
		if (self->_serialno != ogg_page_serialno(&og)) {
			self->_serialno = ogg_page_serialno(&og);
			
			self->_oldsamples = 0;
			
			ogg_stream_init(&os, self->_serialno);
			ogg_stream_pagein(&os, &og);
			ogg_stream_packetout(&os, &op);

			vorbis_info_init(&vi);
			vorbis_comment_init(&vc);
			vorbis_synthesis_headerin(&vi, &vc, &op);
			
			self->_samplerate = vi.rate;
			
			vorbis_comment_clear(&vc);
			vorbis_info_clear(&vi);
			ogg_stream_clear(&os);
		}

		self->_samples = ogg_page_granulepos(&og) - self->_oldsamples;
		self->_oldsamples = ogg_page_granulepos(&og);

		
		self->_senttime += ((double)self->_samples * 1000000 / (double)self->_samplerate);
		
		ret = sock_write_bytes(self->_socket, og.header, og.header_len);
		if (ret != og.header_len) {
			self->error = SHOUTERR_SOCKET;
			return 0;
		}
		
		ret = sock_write_bytes(self->_socket, og.body, og.body_len);
		if (ret != og.body_len) {
			self->error = SHOUTERR_SOCKET;
			return 0;
		}
		
		self->pages++;
	}

	return 1;
}

void shout_sleep(shout_conn_t *self)
{
	uint64_t sleep;

	if (self->_senttime == 0) return;

	sleep = ((double)self->_senttime / 1000) - (timing_get_time() - self->_starttime);

	if (sleep > 0) timing_sleep(sleep);
}

char *shout_strerror(shout_conn_t *self, int error)
{
	switch (error) {
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
	default:
		return "Unknown error";
	}
}
