/*
 * Copyright (C) 2002-2012 Free Software Foundation, Inc.
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <c-ctype.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <minmax.h>
#include <str.h>
#include <main.h>
#include "vasprintf.h"

#define MEMSUB(x,y) ((ssize_t)((ptrdiff_t)x-(ptrdiff_t)y))

void str_clear(str_st * str)
{
	if (str == NULL || str->allocd == NULL)
		return;
	talloc_free(str->allocd);

	str->data = str->allocd = NULL;
	str->max_length = 0;
	str->length = 0;
}

#define MIN_CHUNK 64
/* This function makes sure there is an additional byte in dest;
 */
int str_append_size(str_st * dest, size_t data_size)
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

		return tot_len;
	} else {
		size_t unused = MEMSUB(dest->data, dest->allocd);
		size_t new_len =
		    MAX(data_size, MIN_CHUNK) + MAX(dest->max_length,
						    MIN_CHUNK);

		dest->allocd = talloc_realloc_size(dest->pool, dest->allocd, new_len+1);
		if (dest->allocd == NULL)
			return ERR_MEM;
		dest->max_length = new_len;
		dest->data = dest->allocd + unused;

		if (dest->length && dest->data)
			memmove(dest->allocd, dest->data, dest->length);
		dest->data = dest->allocd;

		return tot_len;
	}
}

/* This function always null terminates the string in dest.
 */
int str_append_data(str_st * dest, const void *data, size_t data_size)
{
int ret;

	ret = str_append_size(dest, data_size);
	if (ret < 0)
		return ret;
	
	memcpy(&dest->data[dest->length], data, data_size);
	dest->length = data_size + dest->length;
	dest->data[dest->length] = 0;
	
	return 0;
}

int str_append_data_prefix1(str_st * dest, const void *data, size_t data_size)
{
	int ret;
	uint8_t prefix = data_size;

	ret = str_append_data(dest, &prefix, 1);
	if (ret >= 0) {
		ret = str_append_data(dest, data, data_size);
	}

	return ret;
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

int
str_append_printf(str_st *dest, const char *fmt, ...)
{
	va_list args;
	int len;
	char *str = NULL;

	va_start(args, fmt);
	len = vasprintf(&str, fmt, args);
	va_end(args);

	if (len < 0 || !str)
		return -1;

	len = str_append_str(dest, str);

	free(str);

	return len;
}

int str_replace_str(str_st *str, const char *what, const char *with)
{
	uint8_t *p, *final;
	unsigned what_len, final_len;
	int ret;

	what_len = strlen(what);

	p = memmem(str->data, str->length, what, what_len);
	if (p == NULL)
		return 0;

	p += what_len;
	final_len = str->length - (ptrdiff_t)(p-str->data);

	final = talloc_memdup(str->allocd, p, final_len);
	if (final == NULL)
		return -1;

	str->length -= final_len + what_len;

	ret = str_append_str(str, with);
	if (ret < 0) {
		talloc_free(final);
		return ret;
	}

	ret = str_append_data(str, final, final_len);
	talloc_free(final);

	if (ret < 0) {
		return ret;
	}

	/* allow multiple replacements */
	return str_replace_str(str, what, with);
}

