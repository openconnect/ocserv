/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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
#ifndef COOKIES_H
#define COOKIES_H

#include <vpn.h>
#include <main.h>
#include <ipc.pb-c.h>

#define COOKIE_IV_SIZE 12 /* AES-GCM */
#define COOKIE_MAC_SIZE 12 /* 96-bits of AES-GCM */

/* The time after a disconnection the cookie is valid */
#define DEFAULT_COOKIE_RECON_TIMEOUT 120

int encrypt_cookie(void *pool, gnutls_datum_t *key, const Cookie *msg,
        uint8_t** ecookie, unsigned *ecookie_size);
int decrypt_cookie(ProtobufCAllocator *pa, gnutls_datum_t *key,
			uint8_t *cookie, unsigned cookie_size, 
			Cookie **msg);

#endif
