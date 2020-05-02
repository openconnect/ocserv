/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2016 Red Hat, Inc.
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

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include <vpn.h>
#include <worker.h>
#include <tlslib.h>

#ifdef HAVE_SIGALTSTACK
# include <signal.h>
# include <sys/mman.h>
#endif

/* recv from the new file descriptor and make sure we have a valid packet */
static unsigned recv_from_new_fd(struct worker_st *ws, int fd, UdpFdMsg **tmsg)
{
	int saved_fd, ret;
	UdpFdMsg *saved_tmsg;

	/* don't bother with anything if we are on uninitialized state */
	if (ws->dtls_session == NULL || ws->udp_state != UP_ACTIVE)
		return 1;

	saved_fd = ws->dtls_tptr.fd;
	saved_tmsg = ws->dtls_tptr.msg;

	ws->dtls_tptr.msg = *tmsg;
	ws->dtls_tptr.fd = fd;

	ret = gnutls_record_recv(ws->dtls_session, ws->buffer, ws->buffer_size);
	/* we receive GNUTLS_E_AGAIN in case the packet was discarded */
	if (ret > 0) {
		ret = 1;
		goto revert;
	}

	ret = 0;
 revert:
 	*tmsg = ws->dtls_tptr.msg;
 	ws->dtls_tptr.fd = saved_fd;
 	ws->dtls_tptr.msg = saved_tmsg;
 	return ret;
}

int handle_commands_from_main(struct worker_st *ws)
{
	uint8_t cmd;
	size_t length;
	UdpFdMsg *tmsg = NULL;
	int ret;
	int fd = -1;
	/*int cmd_data_len;*/

	memset(&ws->buffer, 0, sizeof(ws->buffer));

	ret = recv_msg_data(ws->cmd_fd, &cmd, ws->buffer, sizeof(ws->buffer), &fd);
	if (ret < 0) {
		oclog(ws, LOG_DEBUG, "cannot obtain data from command socket");
		exit_worker_reason(ws, REASON_SERVER_DISCONNECT);
	}

	if (ret == 0) {
		oclog(ws, LOG_ERR, "parent terminated");
		return ERR_NO_CMD_FD;
	}

	length = ret;

	oclog(ws, LOG_DEBUG, "worker received message %s of %u bytes\n", cmd_request_to_str(cmd), (unsigned)length);

	/*cmd_data_len = ret - 1;*/

	switch(cmd) {
		case CMD_TERMINATE:
			exit_worker_reason(ws, REASON_SERVER_DISCONNECT);
		case CMD_UDP_FD: {
			unsigned has_hello = 1;

			if (ws->udp_state != UP_WAIT_FD) {
				oclog(ws, LOG_DEBUG, "received another a UDP fd!");
			}

			tmsg = udp_fd_msg__unpack(NULL, length, ws->buffer);
			if (tmsg) {
				has_hello = tmsg->hello;
			}

			if (fd == -1) {
				oclog(ws, LOG_ERR, "received UDP fd message of wrong type");
				goto udp_fd_fail;
			}

			set_non_block(fd);
			if (has_hello == 0) {
				/* check if the first packet received is a valid one -
				 * if not discard the new fd */
				if (!recv_from_new_fd(ws, fd, &tmsg)) {
					oclog(ws, LOG_INFO, "received UDP fd message but its session has invalid data!");
					if (tmsg)
						udp_fd_msg__free_unpacked(tmsg, NULL);
					close(fd);
					return 0;
				}
			} else { /* received client hello */
				ws->udp_state = UP_SETUP;
			}

			if (ws->dtls_tptr.fd != -1)
				close(ws->dtls_tptr.fd);
			if (ws->dtls_tptr.msg != NULL)
				udp_fd_msg__free_unpacked(ws->dtls_tptr.msg, NULL);

			ws->dtls_tptr.msg = tmsg;
			ws->dtls_tptr.fd = fd;

			if (WSCONFIG(ws)->try_mtu == 0)
				set_mtu_disc(fd, ws->proto, 0);

			oclog(ws, LOG_DEBUG, "received new UDP fd and connected to peer");
			ws->udp_recv_time = time(0);

			return 0;

			}
			break;
		default:
			oclog(ws, LOG_ERR, "unknown CMD 0x%x", (unsigned)cmd);
			exit_worker_reason(ws, REASON_ERROR);
	}

	return 0;

udp_fd_fail:
	if (tmsg)
		udp_fd_msg__free_unpacked(tmsg, NULL);
	if (ws->dtls_tptr.fd == -1)
		ws->udp_state = UP_DISABLED;

	return -1;
}

/* Completes the VPN device information.
 * 
 * Returns 0 on success.
 */
int complete_vpn_info(worker_st * ws, struct vpn_st *vinfo)
{
	int ret, fd;
	struct ifreq ifr;

	if (vinfo->ipv4 == NULL && vinfo->ipv6 == NULL) {
		return -1;
	}

	if (WSCONFIG(ws)->default_mtu != 0) {
		vinfo->mtu = WSCONFIG(ws)->default_mtu;
	} else {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1)
			return -1;

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);
		ret = ioctl(fd, SIOCGIFMTU, (caddr_t) & ifr);
		if (ret < 0) {
			oclog(ws, LOG_INFO,
			      "cannot obtain MTU for %s. Assuming 1500",
			      vinfo->name);
			vinfo->mtu = 1500;
		} else {
			vinfo->mtu = ifr.ifr_mtu;
		}
		close(fd);
	}

	return 0;
}

void ocsigaltstack(struct worker_st *ws)
{
#if defined(HAVE_SIGALTSTACK) && defined(HAVE_POSIX_MEMALIGN)
	stack_t ss;
	int e;

	/* setup the stack for signal handlers */
	if (posix_memalign((void**)&ss.ss_sp, getpagesize(), SIGSTKSZ) != 0) {
		oclog(ws, LOG_ERR,
		      "could not allocate memory for signal stack");
		exit(1);
	}
	if (mprotect(ss.ss_sp, SIGSTKSZ, PROT_READ|PROT_WRITE) == -1) {
		e = errno;
		oclog(ws, LOG_ERR, "mprotect: %s\n", strerror(e));
		exit(1);
	}
	ss.ss_size = SIGSTKSZ;
	ss.ss_flags = 0;
	if (sigaltstack(&ss, NULL) == -1) {
		e = errno;
		oclog(ws, LOG_ERR, "sigaltstack: %s\n", strerror(e));
		exit(1);
	}
#endif
}
