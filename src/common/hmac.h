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


#ifndef HMAC_H
#define HMAC_H
#include <stdbool.h>

#define HMAC_DIGEST_SIZE 32

bool hmac_init_key(size_t key_length, uint8_t * key);

typedef struct hmac_component_st  {
	size_t length;
	void * data;
} hmac_component_st;

void generate_hmac(size_t key_length, const uint8_t * key, size_t component_count,
		  const hmac_component_st * components, uint8_t digest[HMAC_DIGEST_SIZE]);

#endif
