/* -*- c-basic-offset: 8; -*- */
/* vorbis.c: Ogg Vorbis data handlers for libshout
 * $Id$
 *
 *  Copyright (C) 2002-2004 the Icecast team <team@icecast.org>
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
 #include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <ogg/ogg.h>
#include <vorbis/codec.h>
#ifdef HAVE_THEORA
#include <theora/theora.h>
#endif

#include <shout/shout.h>
#include "shout_private.h"

/* -- local datatypes -- */
typedef struct _ogg_codec_tag {
	ogg_stream_state os;

	unsigned int headers;
	uint64_t senttime;

	void *codec_data;
	int (*read_page)(struct _ogg_codec_tag *codec, ogg_page *page);
	void (*free_data)(void *codec_data);

	struct _ogg_codec_tag *next;
} ogg_codec_t;

typedef struct {
	ogg_sync_state oy;
	ogg_codec_t *codecs;
	char bos;
} ogg_data_t;

typedef struct {
	vorbis_info vi;
	vorbis_comment vc;
	int prevW;
} vorbis_data_t;

#ifdef HAVE_THEORA
typedef struct {
	theora_info ti;
	theora_comment tc;
	uint32_t granule_shift;
	double prev_time;
} theora_data_t;
#endif

/* -- static prototypes -- */
static int send_ogg(shout_t *self, const unsigned char *data, size_t len);
static void close_ogg(shout_t *self);
static int open_codec(ogg_codec_t *codec, ogg_page *page);
static void free_codec(ogg_codec_t *codec);
static void free_codecs(ogg_data_t *ogg_data);
static int send_page(shout_t *self, ogg_page *page);

/* vorbis handler */
static int open_vorbis(ogg_codec_t *codec, ogg_page *page);
static int read_vorbis_page(ogg_codec_t *codec, ogg_page *page);
static void free_vorbis_data(void *codec_data);
static int vorbis_blocksize(vorbis_data_t *vd, ogg_packet *p);

#ifdef HAVE_THEORA
/* theora handler */
static int open_theora(ogg_codec_t *codec, ogg_page *page);
static int read_theora_page(ogg_codec_t *codec, ogg_page *page);
static void free_theora_data(void *codec_data);
static int theora_ilog(unsigned int v);
#endif

typedef int (*codec_open_t)(ogg_codec_t *codec, ogg_page *page);
static codec_open_t codecs[] = {
	open_vorbis,
#ifdef HAVE_THEORA
	open_theora,
#endif
	NULL
};

int shout_open_ogg(shout_t *self)
{
	ogg_data_t *ogg_data;

	if (!(ogg_data = (ogg_data_t *)calloc(1, sizeof(ogg_data_t))))
		return self->error = SHOUTERR_MALLOC;
	self->format_data = ogg_data;

	ogg_sync_init(&ogg_data->oy);
	ogg_data->bos = 1;

	self->send = send_ogg;
	self->close = close_ogg;

	return SHOUTERR_SUCCESS;
}

static int send_ogg(shout_t *self, const unsigned char *data, size_t len)
{
	ogg_data_t *ogg_data = (ogg_data_t *)self->format_data;
	ogg_codec_t *codec;
	char *buffer;
	ogg_page page;

	buffer = ogg_sync_buffer(&ogg_data->oy, len);
	memcpy(buffer, data, len);
	ogg_sync_wrote(&ogg_data->oy, len);

	while (ogg_sync_pageout(&ogg_data->oy, &page) == 1) {
		if (ogg_page_bos (&page)) {
			if (! ogg_data->bos) {
				free_codecs(ogg_data);
				ogg_data->bos = 1;
			}

			ogg_codec_t *codec = calloc(1, sizeof(ogg_codec_t));
			if (! codec)
				return self->error = SHOUTERR_MALLOC;
			
			if ((self->error = open_codec(codec, &page)) != SHOUTERR_SUCCESS)
				return self->error;

			codec->headers = 1;
			codec->senttime = self->senttime;
			codec->next = ogg_data->codecs;
			ogg_data->codecs = codec;
		} else {
			ogg_data->bos = 0;

			codec = ogg_data->codecs;
			while (codec) {
				if (ogg_page_serialno(&page) == codec->os.serialno) {
					if (codec->read_page) {
						ogg_stream_pagein(&codec->os, &page);
						codec->read_page(codec, &page);

						if (self->senttime < codec->senttime)
							self->senttime = codec->senttime;
					}
					
					break;
				}

				codec = codec->next;
			}
		}

		if ((self->error = send_page(self, &page)) != SHOUTERR_SUCCESS)
			return self->error;
	}

	return self->error = SHOUTERR_SUCCESS;
}

static void close_ogg(shout_t *self)
{
	ogg_data_t *ogg_data = (ogg_data_t *)self->format_data;
	free_codecs(ogg_data);
	ogg_sync_clear(&ogg_data->oy);
	free(ogg_data);
}

static int open_codec(ogg_codec_t *codec, ogg_page *page)
{
	codec_open_t open_codec;
	int i = 0;

	while ((open_codec = codecs[i])) {
		ogg_stream_init(&codec->os, ogg_page_serialno(page));
		ogg_stream_pagein(&codec->os, page);

		if (open_codec(codec, page) == SHOUTERR_SUCCESS)
			return SHOUTERR_SUCCESS;

		ogg_stream_clear(&codec->os);
		i++;
	}
	
	/* if no handler is found, we currently just fall back to untimed send_raw */
	return SHOUTERR_SUCCESS;
}

static void free_codecs(ogg_data_t *ogg_data)
{
	ogg_codec_t *codec, *next;

	if (ogg_data == NULL)
		return;

	codec = ogg_data->codecs;
	while (codec) {
		next = codec->next;
		free_codec(codec);
		codec = next;
	}
	ogg_data->codecs = NULL;
}

static void free_codec(ogg_codec_t *codec)
{
	if (codec->free_data)
		codec->free_data(codec->codec_data);
	ogg_stream_clear(&codec->os);
	free(codec);
}

static int send_page(shout_t *self, ogg_page *page)
{
	int ret;

	ret = shout_send_raw(self, page->header, page->header_len);
	if (ret != page->header_len)
		return self->error = SHOUTERR_SOCKET;
	ret = shout_send_raw(self, page->body, page->body_len);
	if (ret != page->body_len)
		return self->error = SHOUTERR_SOCKET;

	return SHOUTERR_SUCCESS;
}

/* -- vorbis functions -- */
static int open_vorbis(ogg_codec_t *codec, ogg_page *page)
{
	vorbis_data_t *vorbis_data = calloc(1, sizeof(vorbis_data_t));
	ogg_packet packet;

	if (!vorbis_data)
		return SHOUTERR_MALLOC;

	vorbis_info_init(&vorbis_data->vi);
	vorbis_comment_init(&vorbis_data->vc);

	ogg_stream_packetout(&codec->os, &packet);

	if (vorbis_synthesis_headerin(&vorbis_data->vi, &vorbis_data->vc, &packet) < 0) {
		free_vorbis_data(vorbis_data);
		
		return SHOUTERR_UNSUPPORTED;
	}

	codec->codec_data = vorbis_data;
	codec->read_page = read_vorbis_page;
	codec->free_data = free_vorbis_data;

	return SHOUTERR_SUCCESS;
}

static int read_vorbis_page(ogg_codec_t *codec, ogg_page *page)
{
	ogg_packet packet;
	vorbis_data_t *vorbis_data = codec->codec_data;

	if (codec->headers < 3) {
		while (ogg_stream_packetout (&codec->os, &packet) > 0) {
			if (vorbis_synthesis_headerin(&vorbis_data->vi, &vorbis_data->vc, &packet) < 0)
				return SHOUTERR_INSANE;
			codec->headers++;
		}

		return SHOUTERR_SUCCESS;
	}

	uint64_t samples = 0;

	while (ogg_stream_packetout (&codec->os, &packet) > 0)
		samples += vorbis_blocksize(vorbis_data, &packet);

	codec->senttime += ((samples * 1000000) / vorbis_data->vi.rate);

	return SHOUTERR_SUCCESS;
}

static void free_vorbis_data(void *codec_data)
{
	vorbis_data_t *vorbis_data = (vorbis_data_t *)codec_data;

	vorbis_info_clear(&vorbis_data->vi);
	vorbis_comment_clear(&vorbis_data->vc);
	free(vorbis_data);
}

static int vorbis_blocksize(vorbis_data_t *vd, ogg_packet *p)
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

#ifdef HAVE_THEORA
/* theora handler */
static int open_theora(ogg_codec_t *codec, ogg_page *page)
{
	ogg_packet packet;

	theora_data_t *theora_data = calloc(1, sizeof(theora_data_t));
	if (! theora_data)
		return SHOUTERR_MALLOC;

	theora_info_init(&theora_data->ti);
	theora_comment_init(&theora_data->tc);

	ogg_stream_packetout(&codec->os, &packet);
	
	if (theora_decode_header(&theora_data->ti, &theora_data->tc, &packet) < 0) {
		free_theora_data(theora_data);

		return SHOUTERR_UNSUPPORTED;
	}

	codec->codec_data = theora_data;
	codec->read_page = read_theora_page;
	codec->free_data = free_theora_data;
	codec->headers = 1;

	return SHOUTERR_SUCCESS;
}

static int read_theora_page(ogg_codec_t *codec, ogg_page *page)
{
	theora_data_t *theora_data = codec->codec_data;
	ogg_packet packet;

	if (ogg_page_granulepos(page) == 0)
	{
		while (ogg_stream_packetout(&codec->os, &packet) > 0) {
			if (theora_decode_header(&theora_data->ti, &theora_data->tc, &packet) < 0)
				return SHOUTERR_INSANE;
			codec->headers++;
		}
		if (codec->headers == 3) {
			theora_data->prev_time = 0;
			theora_data->granule_shift = theora_ilog(theora_data->ti.keyframe_frequency_force - 1);
		}

		return SHOUTERR_SUCCESS;
	}

	double per_frame = (double)theora_data->ti.fps_denominator / theora_data->ti.fps_numerator * 1000000;
	double duration;
	ogg_int64_t granulepos = ogg_page_granulepos(page);

	if (granulepos > 0) {
		ogg_int64_t iframe = granulepos >> theora_data->granule_shift;
		ogg_int64_t pframe = granulepos - (iframe << theora_data->granule_shift);
		uint64_t frames = iframe + pframe;
		double new_time = (frames  * per_frame);

		duration = new_time - theora_data->prev_time;
		theora_data->prev_time = new_time;

		codec->senttime += (uint64_t)(duration + 0.5);
	}

	return SHOUTERR_SUCCESS;
}

static void free_theora_data(void *codec_data)
{
	theora_data_t *theora_data = (theora_data_t *)codec_data;

	theora_info_clear(&theora_data->ti);
	theora_comment_clear(&theora_data->tc);
	free(theora_data);
}

static int theora_ilog(unsigned int v)
{
	int ret = 0;
	while (v) {
		ret++;
		v >>= 1;
	}

	return ret;
}

#endif HAVE_THEORA
