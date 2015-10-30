/*
 * Copyright (C) 2015 Red Hat
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <nettle/base64.h>
#include <talloc.h>
#include "base64-helper.h"

void oc_base64_encode (const char *restrict in, size_t inlen,
                       char *restrict out, size_t outlen)
{
	unsigned raw = BASE64_ENCODE_RAW_LENGTH(inlen);
	if (outlen < raw+1) {
		snprintf(out, outlen, "(too long data)");
		return;
	}
	base64_encode_raw((uint8_t*)out, inlen, (uint8_t*)in);
	out[raw] = 0;
	return;
}

int
oc_base64_decode(const uint8_t *src, unsigned src_length,
	      uint8_t *dst, size_t *dst_length)
{
	struct base64_decode_ctx ctx;
	int ret;

	base64_decode_init(&ctx);

#ifdef NETTLE_OLD_BASE64_API
	{
		unsigned int len = *dst_length;
		ret = base64_decode_update(&ctx, &len, dst, src_length, src);
		if (ret != 0)
			*dst_length = len;
	}
#else
	ret = base64_decode_update(&ctx, dst_length, dst, src_length, src);
#endif

	if (ret == 0)
		return 0;

	return base64_decode_final(&ctx);
}

int oc_base64_decode_alloc(void *pool, const char *in, size_t inlen,
                           char **out, size_t *outlen)
{
	int len, ret;
	void *tmp;

	len = BASE64_DECODE_LENGTH(inlen);

	tmp = talloc_size(pool, len);
	if (tmp == NULL)
		return 0;

	*outlen = len;
	ret = oc_base64_decode((void*)in, inlen, tmp, outlen);
	if (ret == 0) {
		talloc_free(tmp);
		return 0;
	}

	*out = tmp;

	return 1;
}
