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

#include <time.h>
#include <unistd.h>

typedef struct bandwidth_st {
	struct timespec count_start;
	size_t transferred_bytes;
	size_t allowed_bytes;

	size_t bytes_per_sec;
} bandwidth_st;

inline static void bandwidth_init(bandwidth_st* b, size_t bytes_per_sec)
{
	memset(b, 0, sizeof(*b));
	b->bytes_per_sec = bytes_per_sec;
}

/* returns true or false, depending on whether to send
 * the bytes */
int bandwidth_update(bandwidth_st* b, size_t bytes, size_t mtu);


#endif
