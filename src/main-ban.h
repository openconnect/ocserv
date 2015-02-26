/*
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
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
#ifndef MAIN_BAN_H
# define MAIN_BAN_H

# include "main.h"

typedef struct ban_entry_st {
	char ip[MAX_IP_STR];
	unsigned score;

	time_t last_reset; /* the time its score counting started */
	time_t expires; /* the time after the client is allowed to login */
} ban_entry_st;

void cleanup_banned_entries(main_server_st *s);
unsigned check_if_banned(main_server_st *s, struct sockaddr_storage *addr, socklen_t addr_size);
int add_ip_to_ban_list(main_server_st *s, const char *ip, unsigned score);
int remove_ip_from_ban_list(main_server_st *s, const char *ip);
unsigned main_ban_db_elems(main_server_st *s);
void main_ban_db_deinit(main_server_st *s);
void *main_ban_db_init(main_server_st *s);

#endif
