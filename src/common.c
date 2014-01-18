/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <vpn.h>
#include <sys/socket.h>
#include "common.h"

const char* cmd_request_to_str(unsigned _cmd)
{
cmd_request_t cmd = _cmd;

	switch(cmd) {
	case AUTH_INIT:
		return "auth init";
	case AUTH_REINIT:
		return "auth reinit";
	case AUTH_REP:
		return "auth reply";
	case AUTH_REQ:
		return "auth request";
	case AUTH_COOKIE_REQ:
		return "auth cookie request";
	case AUTH_MSG:
		return "auth msg";
	case RESUME_STORE_REQ:
		return "resume data store request";
	case RESUME_DELETE_REQ:
		return "resume data delete request";
	case RESUME_FETCH_REQ:
		return "resume data fetch request";
	case RESUME_FETCH_REP:
		return "resume data fetch reply";
	case CMD_UDP_FD:
		return "udp fd";
	case CMD_TUN_MTU:
		return "tun mtu change";
	case CMD_TERMINATE:
		return "terminate";
	case CMD_SESSION_INFO:
		return "session info";
	default:
		return "unknown";
	}
}

ssize_t force_write(int sockfd, const void *buf, size_t len)
{
int left = len;
int ret;
const uint8_t * p = buf;

	while(left > 0) {
		ret = write(sockfd, p, left);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EINTR)
				return ret;
		}
		
		if (ret > 0) {
			left -= ret;
			p += ret;
		}
	}
	
	return len;
}

ssize_t force_read(int sockfd, void *buf, size_t len)
{
int left = len;
int ret;
uint8_t * p = buf;

	while(left > 0) {
		ret = read(sockfd, p, left);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EINTR)
				return ret;
		}
		
		if (ret > 0) {
			left -= ret;
			p += ret;
		}
	}
	
	return len;
}

ssize_t force_read_timeout(int sockfd, void *buf, size_t len, unsigned sec)
{
int left = len;
int ret;
uint8_t * p = buf;
struct timeval tv;
fd_set set;

	tv.tv_sec = sec;
	tv.tv_usec = 0;
	
	FD_ZERO(&set);
	FD_SET(sockfd, &set);

	while(left > 0) {
		ret = select(sockfd + 1, &set, NULL, NULL, &tv);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == -1 || ret == 0) {
			errno = ETIMEDOUT;
			return -1;
		}

		ret = read(sockfd, p, left);
		if (ret == -1) {
			if (errno != EAGAIN && errno != EINTR)
				return ret;
		}
		
		if (ret > 0) {
			left -= ret;
			p += ret;
		}
	}
	
	return len;
}

int ip_cmp(const struct sockaddr_storage *s1, const struct sockaddr_storage *s2, size_t n)
{
	if (((struct sockaddr*)s1)->sa_family == AF_INET) {
		return memcmp(SA_IN_P(s1), SA_IN_P(s2), sizeof(struct in_addr));
	} else { /* inet6 */
		return memcmp(SA_IN6_P(s1), SA_IN6_P(s2), sizeof(struct in6_addr));
	}
}

/* returns an allocated string with the mask to apply for the prefix
 */
char* ipv6_prefix_to_mask(unsigned prefix)
{
	switch (prefix) {
		case 16:
			return strdup("FFFF::");
		case 32:
			return strdup("FFFF:FFFF::");
		case 48:
			return strdup("FFFF:FFFF:FFFF::");
		case 64:
			return strdup("FFFF:FFFF:FFFF:FFFF::");
		case 80:
			return strdup("FFFF:FFFF:FFFF:FFFF:FFFF::");
		case 96:
			return strdup("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::");
		case 112:
			return strdup("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::");
		case 128:
			return strdup("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF");
		default:
			return NULL;
	}
}

/* Sends message + socketfd */
int send_socket_msg(int fd, uint8_t cmd, 
		    int socketfd,
		    const void* msg, pack_size_func get_size, pack_func pack)
{
	struct iovec iov[3];
	struct msghdr hdr;
	union {
		struct cmsghdr    cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr  *cmptr;
	void* packed = NULL;
	uint16_t length;
	int ret;

	memset(&hdr, 0, sizeof(hdr));
	
	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	length = get_size(msg);

	iov[1].iov_base = &length;
	iov[1].iov_len = 2;

	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	if (length > 0) {
		packed = malloc(length);
		if (packed == NULL) {
			syslog(LOG_ERR, "%s:%u: memory error", __func__, __LINE__);
			return -1;
		}

		iov[2].iov_base = packed;
		iov[2].iov_len = length;

		ret = pack(msg, packed);
		if (ret == 0) {
			syslog(LOG_ERR, "%s:%u: packing error", __func__, __LINE__);
			ret = -1;
			goto cleanup;
		}

		hdr.msg_iovlen++;
	}

	if (socketfd != -1) {
		hdr.msg_control = control_un.control;
		hdr.msg_controllen = sizeof(control_un.control);
	
		cmptr = CMSG_FIRSTHDR(&hdr);
		cmptr->cmsg_len = CMSG_LEN(sizeof(int));
		cmptr->cmsg_level = SOL_SOCKET;
		cmptr->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmptr), &socketfd, sizeof(int));
	}

	ret = sendmsg(fd, &hdr, 0);
	if (ret < 0) {
		int e = errno;
		syslog(LOG_ERR, "%s:%u: %s", __func__, __LINE__, strerror(e));
	}

cleanup:
	free(packed);
	return ret;

}

int send_msg(int fd, uint8_t cmd, 
	    const void* msg, pack_size_func get_size, pack_func pack)
{
	return send_socket_msg(fd, cmd, -1, msg, get_size, pack);
}

int recv_socket_msg(int fd, uint8_t cmd, 
		     int* socketfd, void** msg, unpack_func unpack)
{
	struct iovec iov[3];
	uint16_t length;
	uint8_t rcmd;
	struct msghdr hdr;
	uint8_t* data = NULL;
	union {
		struct cmsghdr    cm;
		char              control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr  *cmptr;
	int ret;

	iov[0].iov_base = &rcmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = &length;
	iov[1].iov_len = 2;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	hdr.msg_control = control_un.control;
	hdr.msg_controllen = sizeof(control_un.control);

	do {
		ret = recvmsg( fd, &hdr, 0);
	} while (ret == -1 && errno == EINTR);
	if (ret == -1) {
		int e = errno;
		syslog(LOG_ERR, "%s:%u: recvmsg: %s", __func__, __LINE__, strerror(e));
		return ERR_BAD_COMMAND;
	}

	if (ret == 0) {
		syslog(LOG_ERR, "%s:%u: recvmsg returned zero", __func__, __LINE__);
		return ERR_WORKER_TERMINATED;
	}
	
	if (rcmd != cmd) {
		return ERR_BAD_COMMAND;
	}
	
	/* try to receive socket (if any) */
	if (socketfd != NULL) {
		if ( (cmptr = CMSG_FIRSTHDR(&hdr)) != NULL && cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
			if (cmptr->cmsg_level != SOL_SOCKET || cmptr->cmsg_type != SCM_RIGHTS) {
				syslog(LOG_ERR, "%s:%u: recvmsg returned invalid msg type", __func__, __LINE__);
				return ERR_BAD_COMMAND;
			}

			memcpy(socketfd, CMSG_DATA(cmptr), sizeof(int));
		} else {
			*socketfd = -1;
		}
	}

	if (length > 0) {
		data = malloc(length);
		if (data == NULL) {
			ret = ERR_MEM;
			goto cleanup;
		}

		ret = force_read(fd, data, length);
		if (ret < length) {
			int e = errno;
			syslog(LOG_ERR, "%s:%u: recvmsg: %s", __func__, __LINE__, strerror(e));
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		*msg = unpack(NULL, length, data);
		if (*msg == NULL) {
			syslog(LOG_ERR, "%s:%u: unpacking error", __func__, __LINE__);
			ret = ERR_MEM;
			goto cleanup;
		}
	}
	
	ret = 0;

cleanup:
	free(data);
	if (ret < 0 && socketfd != NULL && *socketfd != -1)
		close(*socketfd);
	return ret;
}

int recv_msg(int fd, uint8_t cmd, 
		void** msg, unpack_func unpack)
{
	return recv_socket_msg(fd, cmd, NULL, msg, unpack);
}
