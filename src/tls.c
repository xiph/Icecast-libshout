/* -*- c-basic-offset: 8; -*- */
/* tls.c: TLS support functions
 * $Id$
 *
 *  Copyright (C) 2015 Philipp Schafft <lion@lion.leolix.org>
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

#include <shout/shout.h>
#include "shout_private.h"

static inline int tls_setup(shout_t *self)
{
	SSL_METHOD *meth;

	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_all_algorithms();
 	SSLeay_add_ssl_algorithms();

	meth = TLSv1_client_method();
	if (!meth)
		goto error;

	self->ssl_ctx = SSL_CTX_new(meth);
	if (!self->ssl_ctx)
		goto error;

	SSL_CTX_set_default_verify_paths(self->ssl_ctx);
	SSL_CTX_load_verify_locations(self->ssl_ctx, self->ca_certificate, self->ca_directory);

	SSL_CTX_set_verify(self->ssl_ctx, SSL_VERIFY_NONE, NULL);

	if (self->client_certificate) {
		if (SSL_CTX_use_certificate_file(self->ssl_ctx, self->client_certificate, SSL_FILETYPE_PEM) != 1)
			goto error;
		if (SSL_CTX_use_PrivateKey_file(self->ssl_ctx, self->client_certificate, SSL_FILETYPE_PEM) != 1)
			goto error;
	}

	if (SSL_CTX_set_cipher_list(self->ssl_ctx, self->allowed_ciphers) <= 0)
		goto error;

	SSL_CTX_set_mode(self->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(self->ssl_ctx, SSL_MODE_AUTO_RETRY);

	self->ssl = SSL_new(self->ssl_ctx);
	if (!self->ssl)
		goto error;

	if (!SSL_set_fd(self->ssl, self->socket))
		goto error;

	SSL_set_connect_state(self->ssl);
	self->ssl_ret = SSL_connect(self->ssl);

	return SHOUTERR_SUCCESS;

	error:
		if (self->ssl)
			SSL_free(self->ssl);
		if (self->ssl_ctx)
			SSL_CTX_free(self->ssl_ctx);
		return SHOUTERR_UNSUPPORTED;
}

static inline int tls_setup_mode(shout_t *self)
{
	if (self->tls_mode == SHOUT_TLS_DISABLED)
		return SHOUTERR_SUCCESS;

	if (self->tls_mode == SHOUT_TLS_OVER_TLS)
		return tls_setup(self);

	return SHOUTERR_UNSUPPORTED;
}

static inline int tls_setup_process(shout_t *self)
{
	if (SSL_is_init_finished(self->ssl))
		return SHOUTERR_SUCCESS;
	self->ssl_ret = SSL_connect(self->ssl);
	if (SSL_is_init_finished(self->ssl))
		return SHOUTERR_SUCCESS;
	return SHOUTERR_BUSY;
}

int shout_tls_try_connect(shout_t *self)
{
	if (!self->ssl)
		tls_setup_mode(self);
	if (self->ssl)
		return tls_setup_process(self);
	return SHOUTERR_UNSUPPORTED;
}
int shout_tls_close(shout_t *self) {
	if (self->ssl) {
		SSL_shutdown(self->ssl);
		SSL_free(self->ssl);
	}
	if (self->ssl_ctx)
		SSL_CTX_free(self->ssl_ctx);
	return SHOUTERR_SUCCESS;
}

ssize_t shout_tls_read(shout_t *self, void *buf, size_t len)
{
	return self->ssl_ret = SSL_read(self->ssl, buf, len);
}

ssize_t shout_tls_write(shout_t *self, const void *buf, size_t len)
{
	return self->ssl_ret = SSL_write(self->ssl, buf, len);
}

int shout_tls_recoverable(shout_t *self)
{
	int error = SSL_get_error(self->ssl, self->ssl_ret);
	if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
		return 1;
	return 0;
}
