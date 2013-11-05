/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <vpn.h>
#include "ipc.h"
#include <worker.h>
#include <cookies.h>
#include <tlslib.h>

int send_tun_mtu(worker_st *ws, unsigned int mtu)
{
	struct iovec iov[2];
	uint8_t cmd;
	struct msghdr hdr;
	struct cmd_tun_mtu_st data;

	memset(&hdr, 0, sizeof(hdr));
	
	cmd = CMD_TUN_MTU;
	data.mtu = mtu;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = (void*)&data;
	iov[1].iov_len = sizeof(data);
	
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	return(sendmsg(ws->cmd_fd, &hdr, 0));
}

int handle_worker_commands(struct worker_st *ws)
{
	struct iovec iov[2];
	uint8_t cmd;
	int e;
	struct msghdr hdr;
	union {
		char x[32];
		struct sockaddr_storage ss;
	} cmd_data;
	union {
		struct cmsghdr    cm;
		char              control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr  *cmptr;
	int ret;
	/*int cmd_data_len;*/

	memset(&cmd_data, 0, sizeof(cmd_data));
	
	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = &cmd_data;
	iov[1].iov_len = sizeof(cmd_data);
	
	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	hdr.msg_control = control_un.control;
	hdr.msg_controllen = sizeof(control_un.control);
	
	ret = recvmsg( ws->cmd_fd, &hdr, 0);
	if (ret == -1) {
		e = errno;
		oclog(ws, LOG_ERR, "cannot obtain data from command socket: %s", strerror(e));
		exit(1);
	}

	if (ret == 0) {
		oclog(ws, LOG_ERR, "parent terminated");
		exit(0);
	}

	/*cmd_data_len = ret - 1;*/
	
	switch(cmd) {
		case CMD_TERMINATE:
			exit(0);
		case CMD_UDP_FD:
			if (ws->udp_state != UP_WAIT_FD) {
				oclog(ws, LOG_INFO, "received another a UDP fd!");
			}

			if ( (cmptr = CMSG_FIRSTHDR(&hdr)) != NULL && cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
				if (cmptr->cmsg_level != SOL_SOCKET || cmptr->cmsg_type != SCM_RIGHTS) {
					oclog(ws, LOG_ERR, "received UDP fd message of wrong type");
					goto udp_fd_fail;
				}

				if (ws->udp_fd != -1) {
					close(ws->udp_fd);
				}

				memcpy(&ws->udp_fd, CMSG_DATA(cmptr), sizeof(int));
				ws->udp_state = UP_SETUP;

				oclog(ws, LOG_DEBUG, "received new UDP fd and connected to peer");
				return 0;
			} else {
				oclog(ws, LOG_ERR, "Could not receive peer's UDP fd");
				return -1;
			}
			break;
		default:
			oclog(ws, LOG_ERR, "unknown CMD 0x%x", (unsigned)cmd);
			exit(1);
	}
	
	return 0;

udp_fd_fail:
	if (ws->udp_fd == -1)
		ws->udp_state = UP_DISABLED;

	return -1;
}
