/*
 * Copyright (C) 2002-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
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
 *
 */

#include <config.h>
#include <c-ctype.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <minmax.h>
#include <str.h>
#include <main.h>

#define MEMSUB(x,y) ((ssize_t)((ptrdiff_t)x-(ptrdiff_t)y))

void str_clear(str_st * str)
{
	if (str == NULL || str->allocd == NULL)
		return;
	free(str->allocd);

	str->data = str->allocd = NULL;
	str->max_length = 0;
	str->length = 0;
}

#define MIN_CHUNK 64
/* This function always null terminates the string in dest.
 */
int str_append_data(str_st * dest, const void *data, size_t data_size)
{
	size_t tot_len = data_size + dest->length;

	if (data_size == 0)
		return 0;

	if (dest->max_length >= tot_len+1) {
		size_t unused = MEMSUB(dest->data, dest->allocd);

		if (dest->max_length - unused <= tot_len) {
			if (dest->length && dest->data)
				memmove(dest->allocd, dest->data,
					dest->length);

			dest->data = dest->allocd;
		}
		memmove(&dest->data[dest->length], data, data_size);
		dest->length = tot_len;
		dest->data[dest->length] = 0;

		return tot_len;
	} else {
		size_t unused = MEMSUB(dest->data, dest->allocd);
		size_t new_len =
		    MAX(data_size, MIN_CHUNK) + MAX(dest->max_length,
						    MIN_CHUNK);

		dest->allocd = realloc(dest->allocd, new_len+1);
		if (dest->allocd == NULL)
			return ERR_MEM;
		dest->max_length = new_len;
		dest->data = dest->allocd + unused;

		if (dest->length && dest->data)
			memmove(dest->allocd, dest->data, dest->length);
		dest->data = dest->allocd;

		memcpy(&dest->data[dest->length], data, data_size);
		dest->length = tot_len;
		dest->data[dest->length] = 0;

		return tot_len;
	}
}

/* Appends the provided string. The null termination byte is appended
 * but not included in length.
 */
int str_append_str(str_st * dest, const char *src)
{
	int ret;
	ret = str_append_data(dest, src, strlen(src) + 1);
	if (ret >= 0)
		dest->length--;

	return ret;
}
