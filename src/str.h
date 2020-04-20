/*
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
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
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef GNUTLS_STR_H
#define GNUTLS_STR_H

#include <config.h>
#include <stdint.h>

#define STR_TAB_SET(i,pat,val) { \
	tab[i].pattern = pat; \
	tab[i].pattern_length = sizeof(pat)-1; \
	tab[i].rep_val = val; \
	}
#define STR_TAB_SET_FUNC(i,pat,func,funcinput) { \
	tab[i].pattern = pat; \
	tab[i].pattern_length = sizeof(pat)-1; \
	tab[i].rep_val = NULL; \
	tab[i].rep_func = func; \
	tab[i].rep_func_input = funcinput; \
	}
#define STR_TAB_TERM(i) tab[i].pattern = NULL

typedef char *(*str_get_func)(void *pool, const char *input);

typedef struct {
	const char *pattern;
	unsigned pattern_length;
	const char *rep_val;
	str_get_func rep_func;
	const void *rep_func_input;
} str_rep_tab;

typedef struct {
	uint8_t *allocd;	/* pointer to allocated data */
	uint8_t *data;		/* API: pointer to data to copy from */
	size_t max_length;
	size_t length;		/* API: current length */
	void *pool;
} str_st;

/* Initialize a buffer */
inline static void str_init(str_st * str, void *pool)
{
	str->data = str->allocd = NULL;
	str->max_length = 0;
	str->length = 0;
	str->pool = pool;
}

/* Free the data in a buffer */
void str_clear(str_st *);

/* Set the buffer data to be of zero length */
inline static void str_reset(str_st * buf)
{
	buf->data = buf->allocd;
	buf->length = 0;
}

void trim_trailing_whitespace(char *str);

int str_append_printf(str_st *dest, const char *fmt, ...);
int str_append_str(str_st *, const char *str);
int str_replace_str(str_st *, const str_rep_tab *tab);
int str_append_data(str_st *, const void *data, size_t data_size);
int str_append_size(str_st *, size_t data_size);
int str_append_data_prefix1(str_st *, const void *data, size_t data_size);

#define str_append_str_prefix1(s, str) (((str)==NULL)?str_append_data_prefix1(s, NULL, 0):str_append_data_prefix1(s, str, strlen(str)))

#endif
