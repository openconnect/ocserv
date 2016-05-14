/*
 * Copyright (C) 2015 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef BASE64_HELPER_H
# define BASE64_HELPER_H

#include <nettle/base64.h>

/* Prototypes compatible with the gnulib's */

int
oc_base64_decode(const uint8_t *src, unsigned src_length,
	      uint8_t *dst, size_t *dst_length);

int oc_base64_decode_alloc(void *pool, const char *in, size_t inlen,
                           char **out, size_t *outlen);

void oc_base64_encode (const char *restrict in, size_t inlen,
                       char *restrict out, size_t outlen);

#endif
