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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#include <worker-auth.h>

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <list.h>

static int send_auth_reply(cmd_auth_reply_t r, struct proc_list_st* proc, struct lease_st* lease)
{
	struct iovec iov[4];
	uint8_t cmd[2];
	struct msghdr hdr;
	union {
		struct cmsghdr    cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr  *cmptr;	

	memset(&control_un, 0, sizeof(control_un));
	memset(&hdr, 0, sizeof(hdr));
	
	cmd[0] = AUTH_REP;
	cmd[1] = r;

	iov[0].iov_base = cmd;
	iov[0].iov_len = 2;
	hdr.msg_iovlen++;

	hdr.msg_iov = iov;

	if (r == REP_AUTH_OK && lease != NULL) {
		iov[1].iov_base = proc->cookie;
		iov[1].iov_len = sizeof(proc->cookie);
		hdr.msg_iovlen++;

		iov[2].iov_base = lease->name;
		iov[2].iov_len = sizeof(lease->name);
		hdr.msg_iovlen++;

		iov[3].iov_base = proc->username;
		iov[3].iov_len = MAX_USERNAME_SIZE;
		hdr.msg_iovlen++;

		/* Send the tun fd */
		hdr.msg_control = control_un.control;
		hdr.msg_controllen = sizeof(control_un.control);
	
		cmptr = CMSG_FIRSTHDR(&hdr);
		cmptr->cmsg_len = CMSG_LEN(sizeof(int));
		cmptr->cmsg_level = SOL_SOCKET;
		cmptr->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmptr), &lease->fd, sizeof(int));
	}
	
	return(sendmsg(proc->fd, &hdr, 0));
}

static int handle_auth_cookie_req(const struct cfg_st *config, struct tun_st *tun,
  			   const struct cmd_auth_cookie_req_st * req, struct lease_st **lease,
  			   char username[MAX_USERNAME_SIZE])
{
int ret;
struct stored_cookie_st sc;

	ret = retrieve_cookie(config, req->cookie, sizeof(req->cookie), &sc);
	if (ret < 0) {
		return -1;
	}
	
	ret = 0; /* cookie was found and valid */
	
	memcpy(username, sc.username, MAX_USERNAME_SIZE);
	
	ret = open_tun(config, tun, lease);
	if (ret < 0)
		ret = -1; /* sorry */
	
	return ret;
}

static
int generate_and_store_cookie(const struct cfg_st* config, uint8_t *cookie, unsigned cookie_size)
{
int ret;
struct stored_cookie_st sc;

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, cookie, cookie_size);
	if (ret < 0)
		return -2;
	
	memset(&sc, 0, sizeof(sc));
	sc.expiration = time(0) + config->cookie_validity;
	
	ret = store_cookie(config, cookie, cookie_size, &sc);
	if (ret < 0)
		return -1;
	
	return 0;
}

static int handle_auth_req(const struct cfg_st *config, struct tun_st *tun,
  			   const struct cmd_auth_req_st * req, struct lease_st **lease,
  			   char username[MAX_USERNAME_SIZE])
{
int ret;
#warning fix auth
	if (strcmp(req->user, "test") == 0 && strcmp(req->pass, "test") == 0)
		ret = 0;
	else
		ret = -1;
	
	memcpy(username, req->user, MAX_USERNAME_SIZE);

	if (ret == 0) { /* open tun */
		ret = open_tun(config, tun, lease);
		if (ret < 0)
		  ret = -1; /* sorry */
	}
	
	return ret;
}

int handle_commands(const struct cfg_st *config, struct tun_st *tun, 
			   struct proc_list_st* proc)
{
	struct iovec iov[2];
	char buf[128];
	uint8_t cmd;
	struct msghdr hdr;
	struct lease_st *lease;
	union {
		struct cmd_auth_req_st auth;
		struct cmd_auth_cookie_req_st cauth;
	} cmd_data;
	int ret, cmd_data_len;
	const char* peer_ip;

	peer_ip = human_addr((void*)&proc->remote_addr, proc->remote_addr_len, buf, sizeof(buf));
	
	memset(&cmd_data, 0, sizeof(cmd_data));
	
	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = &cmd_data;
	iov[1].iov_len = sizeof(cmd_data);
	
	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;
	
	ret = recvmsg( proc->fd, &hdr, 0);
	if (ret == -1) {
		syslog(LOG_ERR, "Cannot obtain data from command socket (pid: %d, peer: %s).", proc->pid, peer_ip);
		return -1;
	}

	if (ret == 0) {
		return -1;
	}

	cmd_data_len = ret - 1;
	
	switch(cmd) {
		case AUTH_REQ:
		case AUTH_COOKIE_REQ:
		
			if (cmd == AUTH_REQ) {
				if (cmd_data_len != sizeof(cmd_data.auth)) {
					syslog(LOG_ERR, "Error in received message length (pid: %d, peer: %s).", proc->pid, peer_ip);
					return -2;
				}

				ret = handle_auth_req(config, tun, &cmd_data.auth, &lease, proc->username);
			} else {
				if (cmd_data_len != sizeof(cmd_data.cauth)) {
					syslog(LOG_ERR, "Error in received message length (pid: %d, peer: %s).", proc->pid, peer_ip);
					return -2;
				}

				ret = handle_auth_cookie_req(config, tun, &cmd_data.cauth, &lease, proc->username);
			}

			if (ret == 0) {
				if (cmd == AUTH_REQ) {
					/* generate and store cookie */
					ret = generate_and_store_cookie(config, 
									proc->cookie, 
									COOKIE_SIZE);
					if (ret < 0)
						return -2;
				} else { /* copy cookie */
					memcpy(proc->cookie, cmd_data.cauth.cookie, 
						COOKIE_SIZE);
				}

				syslog(LOG_INFO, "User '%s' authenticated", proc->username);
				ret = send_auth_reply(REP_AUTH_OK, proc, lease);
				if (ret < 0) {
					syslog(LOG_ERR, "Could not send reply cmd (pid: %d, peer: %s).", proc->pid, peer_ip);
					return -2;
				}

				proc->lease = lease;
				proc->lease->in_use = 1;
				if (lease->fd >= 0)
					close(lease->fd);
				lease->fd = -1;
			} else {
				syslog(LOG_INFO, "Failed authentication attempt for user '%s'", proc->username);
				ret = send_auth_reply( REP_AUTH_FAILED, proc, NULL);
				if (ret < 0) {
					syslog(LOG_ERR, "Could not send reply cmd (pid: %d, peer: %s).", proc->pid, peer_ip);
					return -2;
				}
			}
			
			break;
		default:
			syslog(LOG_ERR, "Unknown CMD 0x%x (pid: %d, peer: %s).", (unsigned)cmd, proc->pid, peer_ip);
			return -2;
	}
	
	return 0;
}
