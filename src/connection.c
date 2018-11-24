/*
 *  Copyright (C) 2018      Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>
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
#   include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_INTTYPES_H
#   include <inttypes.h>
#endif

#include <shout/shout.h>
#include "shout_private.h"

shout_connection_t *shout_connection_new(shout_t *self);
int                 shout_connection_ref(shout_connection_t *con);
int                 shout_connection_unref(shout_connection_t *con);
int                 shout_connection_iter(shout_connection_t *con, shout_t *shout);
int                 shout_connection_select_tlsmode(shout_connection_t *con, int tlsmode);
int                 shout_connection_set_nonblocking(shout_connection_t *con, unsigned int nonblocking);
int                 shout_connection_set_next_timeout(shout_connection_t *con, shout_t *shout, uint32_t timeout /* [ms] */);
int                 shout_connection_connect(shout_connection_t *con, shout_t *shout);
