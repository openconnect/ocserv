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
#include <ccan/list/list.h>
#include "pam.h"

int send_auth_reply(main_server_st* s, struct proc_st* proc,
			cmd_auth_reply_t r, struct lease_st* lease)
{
	struct iovec iov[2];
	uint8_t cmd[2];
	struct msghdr hdr;
	union {
		struct cmsghdr    cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmd_auth_reply_st resp;
	struct cmsghdr  *cmptr;	

	memset(&control_un, 0, sizeof(control_un));
	memset(&hdr, 0, sizeof(hdr));
	
	hdr.msg_iov = iov;

	if (r == REP_AUTH_OK && lease != NULL) {
		cmd[0] = AUTH_REP;

		iov[0].iov_base = cmd;
		iov[0].iov_len = 1;
		hdr.msg_iovlen++;
		
		resp.reply = r;
		memcpy(resp.cookie, proc->cookie, COOKIE_SIZE);
		memcpy(resp.session_id, proc->session_id, sizeof(resp.session_id));
		memcpy(resp.vname, lease->name, sizeof(resp.vname));
		memcpy(resp.user, proc->username, sizeof(resp.user));

		iov[1].iov_base = &resp;
		iov[1].iov_len = sizeof(resp);
		hdr.msg_iovlen++;

		/* Send the tun fd */
		hdr.msg_control = control_un.control;
		hdr.msg_controllen = sizeof(control_un.control);
	
		cmptr = CMSG_FIRSTHDR(&hdr);
		cmptr->cmsg_len = CMSG_LEN(sizeof(int));
		cmptr->cmsg_level = SOL_SOCKET;
		cmptr->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmptr), &lease->fd, sizeof(int));
	} else {
		cmd[0] = AUTH_REP;
		cmd[1] = REP_AUTH_FAILED;
	
		iov[0].iov_base = cmd;
		iov[0].iov_len = 2;
		hdr.msg_iovlen++;
	}
	
	return(sendmsg(proc->fd, &hdr, 0));
}

int handle_auth_cookie_req(main_server_st* s, struct proc_st* proc,
 			   const struct cmd_auth_cookie_req_st * req, struct lease_st **lease)
{
int ret;
struct stored_cookie_st *sc;
time_t now = time(0);

	sc = malloc(sizeof(*sc));
	if (sc == NULL)
		return -1;

	ret = retrieve_cookie(s, req->cookie, sizeof(req->cookie), sc);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	if (sc->expiration < now) {
		ret = -1;
		goto cleanup;
	}
	
	memcpy(proc->cookie, req->cookie, sizeof(proc->cookie));
	memcpy(proc->username, sc->username, sizeof(proc->username));
	memcpy(proc->groupname, sc->groupname, sizeof(proc->groupname));
	memcpy(proc->hostname, sc->hostname, sizeof(proc->hostname));
	memcpy(proc->session_id, sc->session_id, sizeof(proc->session_id));
	proc->session_id_size = sizeof(proc->session_id);
	
	proc->username[sizeof(proc->username)-1] = 0;
	proc->groupname[sizeof(proc->groupname)-1] = 0;
	proc->hostname[sizeof(proc->hostname)-1] = 0;

	if (req->tls_auth_ok != 0) {
		if (strcmp(proc->username, req->cert_user) != 0) {
			mslog(s, proc, LOG_INFO, "user '%s' presented a certificate from user '%s'", proc->username, req->cert_user);
			ret = -1;
			goto cleanup;
		}
		if (strcmp(proc->groupname, req->cert_group) != 0) {
			mslog(s, proc, LOG_INFO, "user '%s' presented a certificate from group '%s' but he is member of '%s'", proc->username, req->cert_group, proc->groupname);
			ret = -1;
			goto cleanup;
		}
	}

	ret = open_tun(s, lease);
	if (ret < 0) {
		ret = -1; /* sorry */
		goto cleanup;
	}
	
	/* ok auth ok. Renew the cookie. */
	sc->expiration = time(0) + s->config->cookie_validity;
	ret = store_cookie(s, sc);
	if (ret < 0)
		goto cleanup;

	/* sc is freed in store_cookie() */
	
	return 0;
cleanup:
	free(sc);
	return ret;
}

int generate_and_store_vals(main_server_st *s, struct proc_st* proc)
{
int ret;
struct stored_cookie_st *sc;

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, proc->cookie, sizeof(proc->cookie));
	if (ret < 0)
		return -2;
	ret = gnutls_rnd(GNUTLS_RND_NONCE, proc->session_id, sizeof(proc->session_id));
	if (ret < 0)
		return -2;
	proc->session_id_size = sizeof( proc->session_id);
	
	sc = calloc(1, sizeof(*sc));
	if (sc == NULL)
		return -2;

	sc->expiration = time(0) + s->config->cookie_validity;
	
	memcpy(sc->cookie, proc->cookie, sizeof(proc->cookie));
	memcpy(sc->username, proc->username, sizeof(sc->username));
	memcpy(sc->groupname, proc->groupname, sizeof(sc->groupname));
	memcpy(sc->hostname, proc->hostname, sizeof(sc->hostname));
	memcpy(sc->session_id, proc->session_id, sizeof(sc->session_id));
	
	/* the sc pointer stays there */
	ret = store_cookie(s, sc);
	if (ret < 0) {
		free(sc);
		return -1;
	}
	
	return 0;
}

int handle_auth_req(main_server_st *s, struct proc_st* proc,
		   const struct cmd_auth_req_st * req, struct lease_st **lease)
{
int ret = -1;
unsigned username_set = 0;

#ifdef HAVE_PAM
	if (req->user_pass_present != 0 && s->config->auth_types & AUTH_TYPE_PAM) {
		ret = pam_auth_user(req->user, req->pass, proc->groupname, sizeof(proc->groupname));
		if (ret != 0)
			ret = -1;

		memcpy(proc->username, req->user, MAX_USERNAME_SIZE);
		username_set = 1;
	}
#endif

	if (s->config->auth_types & AUTH_TYPE_CERTIFICATE) {
		if (req->tls_auth_ok != 0) {
			ret = 0;
		}
		
		if (username_set == 0) {
			memcpy(proc->username, req->cert_user, sizeof(proc->username));
			memcpy(proc->groupname, req->cert_group, sizeof(proc->groupname));
		} else {
			if (strcmp(proc->username, req->cert_user) != 0) {
				mslog(s, proc, LOG_INFO, "user '%s' presented a certificate from user '%s'", proc->username, req->cert_user);
				ret = -1;
			}
			if (strcmp(proc->groupname, req->cert_group) != 0) {
				mslog(s, proc, LOG_INFO, "user '%s' presented a certificate from group '%s' but he is member of '%s'", proc->username, req->cert_group, proc->groupname);
				ret = -1;
			}
		}
	}

	if (ret == 0) { /* open tun */
		if (req->hostname[0] != 0)
			memcpy(proc->hostname, req->hostname, MAX_HOSTNAME_SIZE);

		proc->username[sizeof(proc->username)-1] = 0;
		proc->groupname[sizeof(proc->groupname)-1] = 0;
		proc->hostname[sizeof(proc->hostname)-1] = 0;

		ret = open_tun(s, lease);
		if (ret < 0)
		  ret = -1; /* sorry */
	}
	
	return ret;
}

int check_multiple_users(main_server_st *s, struct proc_st* proc)
{
struct proc_st *ctmp;
unsigned int entries = 1; /* that one */

	if (s->config->max_same_clients == 0)
		return 0; /* ok */

	list_for_each(&s->clist.head, ctmp, list) {

		if (ctmp != proc) {
			if (strcmp(proc->username, ctmp->username) == 0) {
				entries++;
			}
		}
	}
	
	if (entries > s->config->max_same_clients)
		return -1;
	
	return 0;
}

