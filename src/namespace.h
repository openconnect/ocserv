/*
 * Copyright (C) 2020 William Dauchy
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NAMESPACE_H
# define NAMESPACE_H

#include <config.h>

struct netns_fds {
	int default_fd;
	int listen_fd;
};

#if defined(LINUX_NAMESPACES)

int socket_netns(const struct netns_fds*, int domain, int type, int protocol);
int open_namespaces(struct netns_fds *netns, struct perm_cfg_st *config);
int close_namespaces(struct netns_fds *netns);

#else /* __linux__ */

#define open_namespaces(netns, config) (-1)
#define close_namespaces(netns) (-1)

static inline int socket_netns(__attribute__((unused)) const struct netns_fds* fds,
			       int domain, int type, int protocol)
{
        return socket(domain, type, protocol);
}

#endif /* __linux__ */

#endif
