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


#include <config.h>

#if defined(LINUX_NAMESPACES)

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <common-config.h>
#include <namespace.h>

/* get default namespace file descriptor to be able to place fd in a given
 * namespace
 */
static int init_default_namespace(void)
{
	char netns_path[PATH_MAX];
	pid_t pid;
	int error;
	int fd;

	pid = getpid();
	if (snprintf(netns_path, sizeof(netns_path), "/proc/%d/ns/net", pid) < 0)
		return -1;

	fd = open(netns_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		error = errno;
		fprintf(stderr, "could not open default namespace %s: %s\n",
			netns_path, strerror(error));
	}
	return fd;
}

/* opens namespace for outside communication */
static int init_listen_namespace(const char *ns_name)
{
	char netns_path[PATH_MAX];
	int error;
	int fd;

	if (snprintf(netns_path, sizeof(netns_path), "/var/run/netns/%s", ns_name) < 0)
		return -1;

	fd = open(netns_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		error = errno;
		fprintf(stderr, "could not open listen namespace %s: %s\n",
			netns_path, strerror(error));
	}
	return fd;
}

/* open default and listen namespaces */
int open_namespaces(struct netns_fds *netns, struct perm_cfg_st *config)
{
	netns->default_fd = init_default_namespace();
	if (netns->default_fd < 0)
		return -1;
	netns->listen_fd = init_listen_namespace(config->listen_netns_name);
	if (netns->listen_fd < 0)
		return -1;
	return 0;
}

/* close default and listen namespaces */
int close_namespaces(struct netns_fds *netns)
{
	int ret = 0;

	ret = close(netns->default_fd);
	if (ret)
		return ret;
	ret = close(netns->listen_fd);
	return ret;
}

/* opens a socket in the namespace described by <nsfd> */
int socket_netns(const struct netns_fds *fds, int domain, int type, int protocol)
{
	int sock;

	if (fds->default_fd >= 0 && fds->listen_fd && setns(fds->listen_fd, CLONE_NEWNET) == -1)
		return -1;

	sock = socket(domain, type, protocol);

	if (fds->default_fd >= 0 && fds->listen_fd && setns(fds->default_fd, CLONE_NEWNET) == -1) {
		if (sock >= 0)
			close(sock);
		return -1;
	}
	return sock;
}

#endif /* LINUX_NAMESPACES */
