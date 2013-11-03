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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <config.h>

#include <vpn.h>
#include <worker.h>
#include <worker-bandwidth.h>
#include <gettime.h>

#include <stdio.h>

#define COUNT_UPDATE_MS 500

int bandwidth_update(bandwidth_st* b, size_t bytes, size_t mtu)
{
size_t sum;
struct timespec now;
ssize_t t, new_allowed_bytes, remain;
unsigned int diff;

	/* if bandwidth control is disabled */
	if (b->bytes_per_sec == 0)
		return 1;

	gettime(&now);

	diff = timespec_sub_ms(&now, &b->count_start);
	if (diff >= COUNT_UPDATE_MS) {
		b->transferred_bytes = (b->transferred_bytes*COUNT_UPDATE_MS)/diff;

		memcpy(&b->count_start, &now, sizeof(now));

		new_allowed_bytes = mtu - 1 + ((b->bytes_per_sec*COUNT_UPDATE_MS)/1000);

		remain = b->allowed_bytes - b->transferred_bytes;
		t = new_allowed_bytes + remain;

		b->allowed_bytes = MIN(t, new_allowed_bytes*1000/COUNT_UPDATE_MS);
		b->transferred_bytes = bytes;
		
		return 1;
	}
	
	sum = b->transferred_bytes + bytes;
	if (sum > b->allowed_bytes)
		return 0; /* NO */

	b->transferred_bytes = sum;
	
	return 1;
}

