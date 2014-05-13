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

struct __attribute__ ((__packed__)) stored_cookie_st {
	char username[MAX_USERNAME_SIZE];
	char groupname[MAX_GROUPNAME_SIZE];
	char hostname[MAX_HOSTNAME_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID]; /* the DTLS one */
	uint32_t expiration;
	
	uint8_t ipv4_seed[4];
};

#define COOKIE_IV_SIZE 12 /* AES-GCM */
#define COOKIE_MAC_SIZE 12 /* 96-bits of AES-GCM */
#define COOKIE_SIZE (COOKIE_IV_SIZE + sizeof(struct stored_cookie_st) + COOKIE_MAC_SIZE)

int encrypt_cookie(gnutls_datum_t *key, const struct stored_cookie_st* sc,
        uint8_t* cookie, unsigned cookie_size);
int decrypt_cookie(gnutls_datum_t *key, const uint8_t* cookie, unsigned cookie_size, 
			struct stored_cookie_st* sc);

#endif
