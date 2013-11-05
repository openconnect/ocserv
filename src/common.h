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
#ifndef COMMON_H
# define COMMON_H

#include <sys/socket.h>

ssize_t force_write(int sockfd, const void *buf, size_t len);
ssize_t force_read(int sockfd, void *buf, size_t len);
int ip_cmp(const struct sockaddr_storage *s1, const struct sockaddr_storage *s2, size_t n);
char* ipv6_prefix_to_mask(unsigned prefix);

#endif

