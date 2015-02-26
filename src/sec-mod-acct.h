/*
 * Copyright (C) 2015 Red Hat, Inc.
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
#ifndef ACCT_H
# define ACCT_H

#include <main.h>
#include <sec-mod-auth.h>

typedef struct acct_mod_st {
	unsigned int type; /* ACCT_TYPE_ */
	unsigned int auth_types; /* or of the AUTH_TYPEs which are compatible with this */
	void (*global_init)(void *pool, void* additional);
	void (*global_deinit)(void);

	/* The context provided below is of the authentication method */
	int (*open_session)(unsigned auth_method, void *ctx, const common_auth_info_st *ai, const void *sid, unsigned sid_size); /* optional, may be null */
	void (*session_stats)(unsigned auth_method, void *ctx, const common_auth_info_st *ai, struct stats_st *stats); /* optional, may be null */
	void (*close_session)(unsigned auth_method, void *ctx, const common_auth_info_st *ai, struct stats_st *stats); /* optional may be null */
} acct_mod_st;

/* The accounting messages exchanged with the worker thread are shown in ipc.proto.
 */
#endif
