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
#include "ipc.h"

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <list.h>
#include "pam.h"

static int send_auth_reply(main_server_st* s, struct proc_list_st* proc,
				cmd_auth_reply_t r, struct lease_st* lease)
{
	struct iovec iov[6];
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

		iov[2].iov_base = proc->session_id;
		iov[2].iov_len = sizeof(proc->session_id);
		hdr.msg_iovlen++;

		iov[3].iov_base = lease->name;
		iov[3].iov_len = sizeof(lease->name);
		hdr.msg_iovlen++;

		iov[4].iov_base = proc->username;
		iov[4].iov_len = MAX_USERNAME_SIZE;
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

static int handle_auth_cookie_req(main_server_st* s, struct proc_list_st* proc,
  			   const struct cmd_auth_cookie_req_st * req, struct lease_st **lease)
{
int ret;
struct stored_cookie_st sc;

	ret = retrieve_cookie(s->config, req->cookie, sizeof(req->cookie), &sc);
	if (ret < 0) {
		return -1;
	}
	
	ret = 0; /* cookie was found and valid */
	
	memcpy(proc->cookie, req->cookie, sizeof(proc->cookie));
	memcpy(proc->username, sc.username, sizeof(proc->username));
	memcpy(proc->session_id, sc.session_id, sizeof(proc->session_id));
	
	ret = open_tun(s->config, s->tun, lease);
	if (ret < 0)
		ret = -1; /* sorry */
	
	return ret;
}

static
int generate_and_store_vals(main_server_st *s, struct proc_list_st* proc)
{
int ret;
struct stored_cookie_st sc;

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, proc->cookie, sizeof(proc->cookie));
	if (ret < 0)
		return -2;
	ret = gnutls_rnd(GNUTLS_RND_NONCE, proc->session_id, sizeof(proc->session_id));
	if (ret < 0)
		return -2;
	
	memset(&sc, 0, sizeof(sc));
	sc.expiration = time(0) + s->config->cookie_validity;
	
	memcpy(sc.username, proc->username, sizeof(sc.username));
	memcpy(sc.session_id, proc->session_id, sizeof(sc.session_id));
	
	ret = store_cookie(s->config, proc->cookie, sizeof(proc->cookie), &sc);
	if (ret < 0)
		return -1;
	
	return 0;
}

static int handle_auth_req(main_server_st *s, struct proc_list_st* proc,
  			   const struct cmd_auth_req_st * req, struct lease_st **lease)
{
int ret = -1;
unsigned username_set = 0;

	if (req->user_pass_present != 0 && s->config->auth_types & AUTH_TYPE_PAM) {
		ret = pam_auth_user(req->user, req->pass);
		if (ret != 0)
			ret = -1;

		memcpy(proc->username, req->user, MAX_USERNAME_SIZE);
		username_set = 1;
	}

	if (s->config->auth_types & AUTH_TYPE_CERTIFICATE) {
		if (req->tls_auth_ok != 0) {
			ret = 0;
		}
		
		if (username_set == 0)
			memcpy(proc->username, req->cert_user, MAX_USERNAME_SIZE);
		else {
			if (strcmp(proc->username, req->cert_user) != 0) {
				syslog(LOG_INFO, "User '%s' presented a certificate from user '%s'", proc->username, req->cert_user);
				ret = -1;
			}
		}
	}
	
	if (ret == 0) { /* open tun */
		ret = open_tun(s->config, s->tun, lease);
		if (ret < 0)
		  ret = -1; /* sorry */
	}
	
	return ret;
}

int handle_commands(main_server_st *s, struct proc_list_st* proc)
{
	struct iovec iov[2];
	char buf[128];
	int e;
	uint8_t cmd;
	struct msghdr hdr;
	struct lease_st *lease;
	union {
		struct cmd_auth_req_st auth;
		struct cmd_auth_cookie_req_st cauth;
		struct cmd_resume_store_req_st sresume;
		struct cmd_resume_fetch_req_st fresume;
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
		e = errno;
		syslog(LOG_ERR, "Cannot obtain data from command socket (pid: %d, peer: %s): %s", proc->pid, peer_ip, strerror(e));
		return -1;
	}

	if (ret == 0) {
		return -1;
	}

	cmd_data_len = ret - 1;
	
	switch(cmd) {
		case RESUME_STORE_REQ:
			if (cmd_data_len <= sizeof(cmd_data.sresume)-MAX_SESSION_DATA_SIZE) {
				syslog(LOG_ERR, "Error in received message length (pid: %d, peer: %s).", proc->pid, peer_ip);
				return -2;
			}
			ret = handle_resume_store_req(s, proc, &cmd_data.sresume);
			if (ret < 0) {
				syslog(LOG_DEBUG, "Could not store resumption data (pid: %d, peer: %s).", proc->pid, peer_ip);
			}
			
			break;
			
		case RESUME_DELETE_REQ:
			if (cmd_data_len != sizeof(cmd_data.fresume)) {
				syslog(LOG_ERR, "Error in received message length (pid: %d, peer: %s).", proc->pid, peer_ip);
				return -2;
			}
			ret = handle_resume_delete_req(s, proc, &cmd_data.fresume);
			if (ret < 0) {
				syslog(LOG_DEBUG, "Could not delete resumption data (pid: %d, peer: %s).", proc->pid, peer_ip);
			}

			break;
		case RESUME_FETCH_REQ: {
			struct cmd_resume_fetch_reply_st reply;

			if (cmd_data_len != sizeof(cmd_data.fresume)) {
				syslog(LOG_ERR, "Error in received message length (pid: %d, peer: %s).", proc->pid, peer_ip);
				return -2;
			}
			ret = handle_resume_fetch_req(s, proc, &cmd_data.fresume, &reply);
			if (ret < 0) {
				syslog(LOG_DEBUG, "Could not fetch resumption data (pid: %d, peer: %s).", proc->pid, peer_ip);
				ret = send_resume_fetch_reply(s, proc, REP_RESUME_FAILED, NULL);
			} else
				ret = send_resume_fetch_reply(s, proc, REP_RESUME_OK, &reply);
			}
			
			if (ret < 0) {
				syslog(LOG_ERR, "Could not send reply cmd (pid: %d, peer: %s).", proc->pid, peer_ip);
				return -2;
			}
			
			break;

		case AUTH_REQ:
		case AUTH_COOKIE_REQ:
		
			if (cmd == AUTH_REQ) {
				if (cmd_data_len != sizeof(cmd_data.auth)) {
					syslog(LOG_ERR, "Error in received message length (pid: %d, peer: %s).", proc->pid, peer_ip);
					return -2;
				}

				ret = handle_auth_req(s, proc, &cmd_data.auth, &lease);
			} else {
				if (cmd_data_len != sizeof(cmd_data.cauth)) {
					syslog(LOG_ERR, "Error in received message length (pid: %d, peer: %s).", proc->pid, peer_ip);
					return -2;
				}

				ret = handle_auth_cookie_req(s, proc, &cmd_data.cauth, &lease);
			}

			if (ret == 0) {
				ret = call_connect_script(s, proc, lease);
				if (ret < 0) {
					syslog(LOG_INFO, "User '%s' disconnected due to script", proc->username);
				}
			}

			if (ret == 0) {
				if (cmd == AUTH_REQ) {
					/* generate and store cookie */
					ret = generate_and_store_vals(s, proc);
					if (ret < 0)
						return -2;
				}
				

				syslog(LOG_INFO, "User '%s' authenticated", proc->username);
				ret = send_auth_reply(s, proc, REP_AUTH_OK, lease);
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
				ret = send_auth_reply( s, proc, REP_AUTH_FAILED, NULL);
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
