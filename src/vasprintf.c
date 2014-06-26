/*
 * Copyright (C) 2014 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
#include <stdio.h>
#include "vasprintf.h"

#ifndef HAVE_VASPRINTF

#define MAX_BSIZE 1024
#define NO_MORE_MAX (16*MAX_BSIZE)

int _ocserv_vasprintf(char **strp, const char *fmt, va_list ap)
{
	char *buf;
	int ret, max;

	max = MAX_BSIZE / 2;

	do {
		max *= 2;

		buf = malloc(max);
		if (buf == NULL)
			return -1;

		ret = vsnprintf(buf, max, fmt, ap);
	}
	while (ret > max && max < NO_MORE_MAX);

	return ret;
}

#endif
