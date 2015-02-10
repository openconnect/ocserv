/*
 * Copyright (C) 2014 Red Hat
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
#ifndef PROC_SEARCH_H
# define PROC_SEARCH_H

#include <vpn.h>
#include <string.h>
#include <sys/socket.h>
#include <ccan/hash/hash.h>
#include <main.h>

struct proc_st *proc_search_ip(struct main_server_st *s,
			       struct sockaddr_storage *sockaddr,
			       unsigned sockaddr_size);
struct proc_st *proc_search_dtls_id(struct main_server_st *s, const uint8_t *id, unsigned id_size);
struct proc_st *proc_search_sid(struct main_server_st *s,
			        const uint8_t id[SID_SIZE]);

void proc_table_init(main_server_st *s);
void proc_table_deinit(main_server_st *s);
int proc_table_add(main_server_st *s, struct proc_st *proc);
void proc_table_del(main_server_st *s, struct proc_st *proc);

#endif
