/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

#include <ip-lease.h>
#include <main.h>
#include <cookies.h>

int decrypt_cookie(gnutls_datum_t *key, const uint8_t* cookie, unsigned cookie_size, 
			struct stored_cookie_st* sc)
{
gnutls_datum_t iv = { (void*)cookie, COOKIE_IV_SIZE };
int ret;
uint8_t tag[COOKIE_MAC_SIZE];
gnutls_cipher_hd_t h;

	if (cookie_size != COOKIE_SIZE)
		return -1;

	ret = gnutls_cipher_init(&h, GNUTLS_CIPHER_AES_128_GCM, key, &iv);
	if (ret < 0)
		return -1;
	
	cookie += COOKIE_IV_SIZE;
	
	ret = gnutls_cipher_decrypt2(h, cookie, sizeof(*sc), sc, sizeof(*sc));
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}
	
	ret = gnutls_cipher_tag(h, tag, sizeof(tag));
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}
	
	cookie += sizeof(*sc);
	if (memcmp(tag, cookie, COOKIE_MAC_SIZE) != 0) {
		ret = -1;
		goto cleanup;
	}

	ret = 0;

cleanup:
	gnutls_cipher_deinit(h);
	
	return ret;
}

int encrypt_cookie(gnutls_datum_t *key, const struct stored_cookie_st* sc,
        uint8_t* cookie, unsigned cookie_size)
{
uint8_t _iv[COOKIE_IV_SIZE];
gnutls_cipher_hd_t h;
gnutls_datum_t iv = { _iv, sizeof(_iv) };
int ret;

	if (cookie_size != COOKIE_SIZE)
		return -1;
	
	ret = gnutls_rnd(GNUTLS_RND_NONCE, _iv, sizeof(_iv));
	if (ret < 0)
		return -1;
	
	ret = gnutls_cipher_init(&h, GNUTLS_CIPHER_AES_128_GCM, key, &iv);
	if (ret < 0)
		return -1;

	memcpy(cookie, _iv, COOKIE_IV_SIZE);
	cookie += COOKIE_IV_SIZE;
	
	ret = gnutls_cipher_encrypt2(h, sc, sizeof(*sc), cookie, sizeof(*sc));
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}
	
	cookie += sizeof(*sc);
	
	ret = gnutls_cipher_tag(h, cookie, COOKIE_MAC_SIZE);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}
	
	ret = 0;
	
cleanup:
	gnutls_cipher_deinit(h);
	return ret;

}

