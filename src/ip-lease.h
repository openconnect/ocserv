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
#ifndef IP_LEASE_H
# define IP_LEASE_H

#include <vpn.h>
#include <string.h>
#include <sys/socket.h>
#include <ccan/hash/hash.h>
#include <main.h>

struct ip_lease_st {
        struct sockaddr_storage rip;
        socklen_t rip_len;

        struct sockaddr_storage lip;
        socklen_t lip_len;
        unsigned prefix; /* in ipv6 */

        struct ip_lease_db_st* db;
};

void ip_lease_deinit(struct ip_lease_db_st* db);
void ip_lease_init(struct ip_lease_db_st* db);

void steal_ip_leases(struct proc_st* proc, struct proc_st *thief);

int get_ip_leases(struct main_server_st* s, struct proc_st* proc);
void remove_ip_leases(struct main_server_st* s, struct proc_st* proc);
void remove_ip_lease(main_server_st* s, struct ip_lease_st * lease);

#endif
