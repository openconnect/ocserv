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
#ifndef TUN_H
# define TUN_H

#include <vpn.h>
#include <string.h>
#include <ccan/list/list.h>

struct tun_lease_st {

	char name[IFNAMSIZ];

        /* this is used temporarily. */
	int fd;
};

ssize_t tun_write(int sockfd, const void *buf, size_t len);
ssize_t tun_read(int sockfd, void *buf, size_t len);

#endif
