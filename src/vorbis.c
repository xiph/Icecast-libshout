/* -*- c-basic-offset: 8; -*- */
/* vorbis.c: Ogg Vorbis data handlers for libshout */

#ifdef HAVE_CONFIG_H
 #include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <ogg/ogg.h>
#include <vorbis/codec.h>

#include <shout/shout.h>
#include "shout_private.h"

/* -- local datatypes -- */
typedef struct {
	/* total pages broadcasted */
	unsigned int pages;

	unsigned int samplerate;

	ogg_sync_state oy;
	ogg_stream_state os;

	int headers;
	vorbis_info vi;
	vorbis_comment vc;
	int prevW;

	long serialno;
    int initialised;
} vorbis_data_t;

/* -- static prototypes -- */
static int send_vorbis(shout_t *self, const unsigned char *data, size_t len);
static void close_vorbis(shout_t *self);

int shout_open_vorbis(shout_t *self)
{
	vorbis_data_t *vorbis_data;

	if (!(vorbis_data = (vorbis_data_t *)calloc(1, sizeof(vorbis_data_t))))
		return SHOUTERR_MALLOC;
	self->format_data = vorbis_data;

	ogg_sync_init(&vorbis_data->oy);

	self->send = send_vorbis;
	self->close = close_vorbis;

	return SHOUTERR_SUCCESS;
}

static int blocksize(vorbis_data_t *vd, ogg_packet *p)
{
	int this = vorbis_packet_blocksize(&vd->vi, p);
	int ret = (this + vd->prevW)/4;

	if(!vd->prevW) {
		vd->prevW = this;
		return 0;
	}

	vd->prevW = this;
	return ret;
}

static int send_vorbis(shout_t *self, const unsigned char *data, size_t len)
{
	vorbis_data_t *vorbis_data = (vorbis_data_t *)self->format_data;
	int ret;
	char *buffer;
	ogg_page og;
	ogg_packet op;
	int samples;

	buffer = ogg_sync_buffer(&vorbis_data->oy, len);
	memcpy(buffer, data, len);
	ogg_sync_wrote(&vorbis_data->oy, len);

	while (ogg_sync_pageout(&vorbis_data->oy, &og) == 1) {
		if (vorbis_data->serialno != ogg_page_serialno(&og) || 
                !vorbis_data->initialised) 
        {
			/* Clear the old one - this is safe even if there was no previous
			 * stream */
			vorbis_comment_clear(&vorbis_data->vc);
			vorbis_info_clear(&vorbis_data->vi);
			ogg_stream_clear(&vorbis_data->os);

			vorbis_data->serialno = ogg_page_serialno(&og);

			ogg_stream_init(&vorbis_data->os, vorbis_data->serialno);

			vorbis_info_init(&vorbis_data->vi);
			vorbis_comment_init(&vorbis_data->vc);

            vorbis_data->initialised = 1;

			vorbis_data->headers = 1;
		}

		samples = 0;

		ogg_stream_pagein(&vorbis_data->os, &og);
		while(ogg_stream_packetout(&vorbis_data->os, &op) == 1) {
			int size;

			if(vorbis_data->headers > 0 && vorbis_data->headers <= 3) {
				vorbis_synthesis_headerin(&vorbis_data->vi, &vorbis_data->vc, 
							  &op);
				if(vorbis_data->headers == 1)
					vorbis_data->samplerate = vorbis_data->vi.rate;

				vorbis_data->headers++;
				continue;
			}

			vorbis_data->headers = 0;
			size = blocksize(vorbis_data, &op);
			samples += size;
		}

		self->senttime += ((double)samples * 1000000) / 
			((double)vorbis_data->samplerate);

		ret = sock_write_bytes(self->socket, og.header, og.header_len);
		if (ret != og.header_len)
			return self->error = SHOUTERR_SOCKET;

		ret = sock_write_bytes(self->socket, og.body, og.body_len);
		if (ret != og.body_len)
			return self->error = SHOUTERR_SOCKET;

		vorbis_data->pages++;
	}

	return self->error = SHOUTERR_SUCCESS;
}

static void close_vorbis(shout_t *self)
{
	vorbis_data_t *vorbis_data = (vorbis_data_t *)self->format_data;
	ogg_sync_clear(&vorbis_data->oy);
	free(vorbis_data);
}
