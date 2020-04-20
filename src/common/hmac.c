/*
 * Copyright (C) 2020 Microsoft Corporation
 *
 * Author: Alan Jowett
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or
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

#include <config.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <nettle/hmac.h>
#include <common.h>
#include <hmac.h>
#include <stdbool.h>

bool hmac_init_key(size_t key_length, uint8_t * key)
{
	return gnutls_rnd(GNUTLS_RND_RANDOM, key, key_length) == 0;
}

void generate_hmac(size_t key_length, const uint8_t * key, size_t component_count,
		  const hmac_component_st * components, uint8_t digest[HMAC_DIGEST_SIZE])
{
	struct hmac_sha256_ctx ctx;
	size_t i;

	hmac_sha256_set_key(&ctx, key_length, key);

	for (i = 0; i < component_count; i++) {

		if (components[i].data) {
			hmac_sha256_update(&ctx,
					   components[i].length,
					   (const uint8_t *)components[i].data);
		}
	}

	hmac_sha256_digest(&ctx, HMAC_DIGEST_SIZE, digest);

	safe_memset(&ctx, 0, sizeof(ctx));	
}
