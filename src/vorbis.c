/* vorbis.c: Ogg Vorbis data handlers for libshout */

#include <stdlib.h>

#include <ogg/ogg.h>
#include <vorbis/codec.h>

#include "shout.h"
#include "shout_private.h"

/* -- local datatypes -- */
typedef struct {
	/* total pages broadcasted */
	unsigned int pages;
	/* the number of samples for the current page */
	unsigned int samples;

	unsigned int oldsamples;
	unsigned int samplerate;
	ogg_sync_state oy;
	long serialno;
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

static int send_vorbis(shout_t *self, const unsigned char *data, size_t len)
{
	vorbis_data_t *vorbis_data = (vorbis_data_t *)self->format_data;
	int ret;
	char *buffer;
	ogg_stream_state os;
	ogg_page og;
	ogg_packet op;
	vorbis_info vi;
	vorbis_comment vc;

	buffer = ogg_sync_buffer(&vorbis_data->oy, len);
	memcpy(buffer, data, len);
	ogg_sync_wrote(&vorbis_data->oy, len);

	while (ogg_sync_pageout(&vorbis_data->oy, &og) == 1) {
		if (vorbis_data->serialno != ogg_page_serialno(&og)) {
			vorbis_data->serialno = ogg_page_serialno(&og);

			vorbis_data->oldsamples = 0;

			ogg_stream_init(&os, vorbis_data->serialno);
			ogg_stream_pagein(&os, &og);
			ogg_stream_packetout(&os, &op);

			vorbis_info_init(&vi);
			vorbis_comment_init(&vc);
			vorbis_synthesis_headerin(&vi, &vc, &op);

			vorbis_data->samplerate = vi.rate;

			vorbis_comment_clear(&vc);
			vorbis_info_clear(&vi);
			ogg_stream_clear(&os);
		}

		vorbis_data->samples = ogg_page_granulepos(&og) - vorbis_data->oldsamples;
		vorbis_data->oldsamples = ogg_page_granulepos(&og);

		self->senttime += ((double)vorbis_data->samples * 1000000 / (double)vorbis_data->samplerate);

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
