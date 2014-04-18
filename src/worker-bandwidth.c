/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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

#include <vpn.h>
#include <worker.h>
#include <worker-bandwidth.h>
#include <gettime.h>

#include <stdio.h>


int _bandwidth_update(bandwidth_st* b, size_t bytes, size_t mtu, struct timespec *now)
{
size_t sum;
ssize_t t, remain;
unsigned int diff;
size_t transferred_kb;

	diff = timespec_sub_ms(now, &b->count_start);
	if (diff >= COUNT_UPDATE_MS) {
		transferred_kb = b->transferred_bytes / 1000;
		transferred_kb = (transferred_kb*COUNT_UPDATE_MS)/diff;

		memcpy(&b->count_start, now, sizeof(*now));

		remain = b->allowed_kb - transferred_kb;
		t = b->allowed_kb_per_count + remain;

		b->allowed_kb = MIN(t, b->kb_per_sec);
		b->transferred_bytes = bytes;
		
		return 1;
	}
	
	sum = b->transferred_bytes + bytes;
	if (sum > b->allowed_kb*1000)
		return 0; /* NO */

	b->transferred_bytes = sum;
	
	return 1;
}

