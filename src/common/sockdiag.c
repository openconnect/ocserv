/*
 * Copyright (C) 2020 Microsoft Corporation
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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(ENABLE_ADAPTIVE_RATE_LIMIT_SUPPORT)

#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <netinet/tcp.h>
#include <sys/syslog.h>

static int send_query(int fd, int inode, int states, int show)
{
	int err;
	struct sockaddr_nl nladdr = {
		.nl_family = AF_NETLINK
	};
	struct {
		struct nlmsghdr nlh;
		struct unix_diag_req udr;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),.nlmsg_type =
			SOCK_DIAG_BY_FAMILY,.nlmsg_flags =
			NLM_F_REQUEST | (inode ? 0 : NLM_F_DUMP)
			}
		,.udr = {
			 .sdiag_family = AF_UNIX,.udiag_states =
			 states,.udiag_show = show,.udiag_ino = inode}
	};
	struct iovec iov = {
		.iov_base = &req,
		.iov_len = sizeof(req)
	};
	struct msghdr msg = {
		.msg_name = (void *)&nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1
	};

	for (;;) {
		if (sendmsg(fd, &msg, 0) < 0) {
			if (errno == EINTR)
				continue;
			err = errno;

			syslog(LOG_ERR, "sendmsg failed %s", strerror(err));
			return -1;
		}

		return 0;
	}
}

typedef int (*process_response)(const struct unix_diag_msg * diag,
				unsigned int len, void *context);

struct match_name_context {
	const char *name;
	int inode;
	struct unix_diag_rqlen rqlen;
};

static int match_name(const struct unix_diag_msg *diag, unsigned int len,
		      void *context)
{
	struct match_name_context *ctx = (struct match_name_context *)context;

	struct rtattr *attr;
	unsigned int rta_len = len - NLMSG_LENGTH(sizeof(*diag));
	size_t path_len = 0;
	char path[sizeof(((struct sockaddr_un *) 0)->sun_path) + 1];
	struct unix_diag_rqlen rqlen;
	int rqlen_valid = 0;

	for (attr = (struct rtattr *)(diag + 1);
	     RTA_OK(attr, rta_len); attr = RTA_NEXT(attr, rta_len)) {
		switch (attr->rta_type) {
		case UNIX_DIAG_NAME:
			if (!path_len) {
				path_len = RTA_PAYLOAD(attr);
				if (path_len > sizeof(path) - 1)
					path_len = sizeof(path) - 1;
				memcpy(path, RTA_DATA(attr), path_len);
				path[path_len] = '\0';
			}
			break;
		case UNIX_DIAG_RQLEN:
			if (RTA_PAYLOAD(attr) != sizeof(rqlen))
				return -1;
			memcpy(&rqlen, RTA_DATA(attr), sizeof(rqlen));
			rqlen_valid = 1;
			break;
		}
	}

	if (path_len == 0) {
		syslog(LOG_ERR, "UNIX_DIAG_NAME not present in response");
		return -1;
	}

	if (rqlen_valid == 0) {
		syslog(LOG_ERR, "UNIX_DIAG_RQLEN not present in response");
		return -1;
	}

	if (strcmp(path, ctx->name) == 0) {
		ctx->inode = diag->udiag_ino;
		ctx->rqlen = rqlen;
	}

	return 0;
}

static int receive_responses(int fd, process_response process, void *context)
{
	int err;
	long buf[8192 / sizeof(long)];
	struct sockaddr_nl nladdr = {
		.nl_family = AF_NETLINK
	};
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf)
	};
	int flags = 0;

	for (;;) {
		struct msghdr msg = {
			.msg_name = (void *)&nladdr,
			.msg_namelen = sizeof(nladdr),
			.msg_iov = &iov,
			.msg_iovlen = 1
		};

		ssize_t ret = recvmsg(fd, &msg, flags);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			err = errno;
			syslog(LOG_ERR, "recvmsg failed %s", strerror(err));
			return -1;
		}

		if (ret == 0) {
			syslog(LOG_ERR, "recvmsg returned empty response");
			return -1;
		}

		const struct nlmsghdr *h = (struct nlmsghdr *)buf;

		if (!NLMSG_OK(h, ret)) {
			syslog(LOG_ERR, "!NLMSG_OK");
			return -1;
		}

		for (; NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret)) {
			const struct unix_diag_msg *diag;

			if (h->nlmsg_type == NLMSG_DONE)
				return 0;

			if (h->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *err = NLMSG_DATA(h);

				if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
					syslog(LOG_ERR,
					       "nlmsg_type NLMSG_ERROR has short nlmsg_len %d",
					       h->nlmsg_len);
				} else {
					syslog(LOG_ERR, "NLM query failed %s",
					       strerror(-err->error));
				}

				return -1;
			}

			if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
				syslog(LOG_ERR, "unexpected nlmsg_type %u\n",
				       (unsigned)h->nlmsg_type);
				return -1;
			}

			diag = (const struct unix_diag_msg *)NLMSG_DATA(h);

			if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*diag))) {
				syslog(LOG_ERR,
				       "nlmsg_type SOCK_DIAG_BY_FAMILY has short nlmsg_len %d",
				       h->nlmsg_len);
				return -1;
			}

			if (diag->udiag_family != AF_UNIX) {
				syslog(LOG_ERR, "unexpected family %u\n",
				       diag->udiag_family);
				return -1;
			}

			if (process(diag, h->nlmsg_len, context))
				return -1;
		}
	}
}

int sockdiag_query_unix_domain_socket_queue_length(const char *socket_name,
						   int *sock_rqueue,
						   int *sock_wqueue)
{
	int err;
	int ret = -1;
	struct match_name_context ctx = {
		.name = socket_name,
		.inode = 0
	};

	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);

	if (fd < 0) {
		err = errno;
		syslog(LOG_ERR, "socket failed %s", strerror(err));
		goto cleanup;
	}

	if (send_query
	    (fd, 0, 1 << TCP_LISTEN, UDIAG_SHOW_NAME | UDIAG_SHOW_RQLEN))
		goto cleanup;

	if (receive_responses(fd, match_name, &ctx))
		goto cleanup;

	*sock_rqueue = ctx.rqlen.udiag_rqueue;
	*sock_wqueue = ctx.rqlen.udiag_wqueue;

	ret = 0;

 cleanup:
	if (fd >= 0) {
		close(fd);
	}
	return ret;
}
#else
int sockdiag_query_unix_domain_socket_queue_length(const char *socket_name,
						   int *sock_rqueue,
						   int *sock_wqueue)
{
	return -1;
}
#endif
