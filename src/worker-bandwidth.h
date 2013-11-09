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
#ifndef WORKER_BANDWIDTH_H
# define WORKER_BANDWIDTH_H

#include <gettime.h>
#include <time.h>
#include <unistd.h>

#define COUNT_UPDATE_MS 500

typedef struct bandwidth_st {
	struct timespec count_start;
	size_t transferred_bytes;
	size_t allowed_kb;

	/* only touched once */
	size_t allowed_kb_per_count;
	size_t kb_per_sec;
} bandwidth_st;

inline static void bandwidth_init(bandwidth_st* b, size_t kb_per_sec)
{
	memset(b, 0, sizeof(*b));
	b->kb_per_sec = kb_per_sec;
	b->allowed_kb_per_count = (b->kb_per_sec*COUNT_UPDATE_MS)/1000;
}

int _bandwidth_update(bandwidth_st* b, size_t bytes, size_t mtu, struct timespec* now);

/* returns true or false, depending on whether to send
 * the bytes */
inline static
int bandwidth_update(bandwidth_st* b, size_t bytes, size_t mtu, struct timespec* now)
{
	/* if bandwidth control is disabled */
	if (b->kb_per_sec == 0)
		return 1;

	return _bandwidth_update(b, bytes, mtu, now);
}


#endif
