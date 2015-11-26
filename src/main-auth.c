/*
 * Copyright (C) 2013, 2014, 2015 Nikos Mavrogiannopoulos
 * Copyright (C) 2014, 2015 Red Hat, Inc.
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
#include <script-list.h>
#include <ip-lease.h>
#include <proc-search.h>
#include "str.h"

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>
#include <common.h>

int send_cookie_auth_reply(main_server_st* s, struct proc_st* proc,
			AUTHREP r)
{
	AuthReplyMsg msg = AUTH_REPLY_MSG__INIT;
	int ret;

	if (r == AUTH__REP__OK && proc->tun_lease.name[0] != 0) {
		char ipv6[MAX_IP_STR];
		char ipv4[MAX_IP_STR];
		char ipv6_local[MAX_IP_STR];
		char ipv4_local[MAX_IP_STR];

		/* fill message */
		msg.reply = AUTH__REP__OK;

		msg.has_session_id = 1;
		msg.session_id.data = proc->dtls_session_id;
		msg.session_id.len = sizeof(proc->dtls_session_id);

		msg.sid.data = proc->sid;
		msg.sid.len = sizeof(proc->sid);

		msg.vname = proc->tun_lease.name;
		msg.user_name = proc->username;
		msg.group_name = proc->groupname;

		if (proc->ipv4 && proc->ipv4->rip_len > 0) {
			msg.ipv4 = human_addr2((struct sockaddr*)&proc->ipv4->rip, proc->ipv4->rip_len,
					ipv4, sizeof(ipv4), 0);
			msg.ipv4_local = human_addr2((struct sockaddr*)&proc->ipv4->lip, proc->ipv4->lip_len,
					ipv4_local, sizeof(ipv4_local), 0);
		}

		if (proc->ipv6 && proc->ipv6->rip_len > 0) {
			msg.ipv6 = human_addr2((struct sockaddr*)&proc->ipv6->rip, proc->ipv6->rip_len,
					ipv6, sizeof(ipv6), 0);
			msg.ipv6_local = human_addr2((struct sockaddr*)&proc->ipv6->lip, proc->ipv6->lip_len,
					ipv6_local, sizeof(ipv6_local), 0);
		}

		msg.config = proc->config;

		ret = send_socket_msg_to_worker(s, proc, AUTH_COOKIE_REP, proc->tun_lease.fd,
			 &msg,
			 (pack_size_func)auth_reply_msg__get_packed_size,
			 (pack_func)auth_reply_msg__pack);
	} else {
		msg.reply = AUTH__REP__FAILED;

		ret = send_msg_to_worker(s, proc, AUTH_COOKIE_REP,
			 &msg,
			 (pack_size_func)auth_reply_msg__get_packed_size,
			 (pack_func)auth_reply_msg__pack);
	}

	if (ret < 0) {
		int e = errno;
		mslog(s, proc, LOG_ERR, "send_msg: %s", strerror(e));
		return ret;
	}

	return 0;
}

int handle_auth_cookie_req(main_server_st* s, struct proc_st* proc,
 			   const AuthCookieRequestMsg * req)
{
int ret;
Cookie *cmsg;
gnutls_datum_t key = {s->cookie_key, sizeof(s->cookie_key)};
char str_ip[MAX_IP_STR+1];
PROTOBUF_ALLOCATOR(pa, proc);
struct proc_st *old_proc;

	if (req->cookie.len == 0) {
		mslog(s, proc, LOG_INFO, "error in cookie size");
		return -1;
	}

	ret = decrypt_cookie(&pa, &key, req->cookie.data, req->cookie.len, &cmsg);
	if (ret < 0 && s->prev_cookie_key_active) {
		/* try the old key */
		key.data = s->prev_cookie_key;
		key.size = sizeof(s->prev_cookie_key);
		ret = decrypt_cookie(&pa, &key, req->cookie.data, req->cookie.len, &cmsg);
		if (ret == 0)
			mslog(s, proc, LOG_INFO, "decrypted cookie with previous key");
	}

	if (ret < 0) {
		mslog(s, proc, LOG_INFO, "error decrypting cookie");
		return -1;
	}

	if (cmsg->username == NULL)
		return -1;
	strlcpy(proc->username, cmsg->username, sizeof(proc->username));

	if (cmsg->sid.len != sizeof(proc->sid))
		return -1;

	/* generate a new DTLS session ID for each connection, to allow
	 * openconnect of distinguishing when the DTLS key has switched. */
	ret = gnutls_rnd(GNUTLS_RND_NONCE, proc->dtls_session_id, sizeof(proc->dtls_session_id));
	if (ret < 0)
		return -1;
	proc->dtls_session_id_size = sizeof(proc->dtls_session_id);

	memcpy(proc->sid, cmsg->sid.data, cmsg->sid.len);

	/* override the group name in order to load the correct configuration in
	 * case his group is specified in the certificate */
	if (cmsg->groupname)
		strlcpy(proc->groupname, cmsg->groupname, sizeof(proc->groupname));

	/* loads sup config */
	ret = session_open(s, proc, req->cookie.data, req->cookie.len);
	if (ret < 0) {
		mslog(s, proc, LOG_INFO, "could not open session");
		return -1;
	}
	/* this hints to call session_close() */
	proc->active_sid = 1;

	/* Put into right cgroup */
        if (proc->config->cgroup != NULL) {
        	put_into_cgroup(s, proc->config->cgroup, proc->pid);
	}

	/* check whether the cookie IP matches */
	if (proc->config->deny_roaming != 0) {
		if (cmsg->ip == NULL) {
			return -1;
		}

		if (human_addr2((struct sockaddr *)&proc->remote_addr, proc->remote_addr_len,
					    str_ip, sizeof(str_ip), 0) == NULL)
			return -1;

		if (strcmp(str_ip, cmsg->ip) != 0) {
			mslog(s, proc, LOG_INFO, "user '%s' is re-using cookie from different IP (prev: %s, current: %s); rejecting",
				cmsg->username, cmsg->ip, str_ip);
			return -1;
		}
	}

	/* check for a user with the same sid as in the cookie */
	old_proc = proc_search_sid(s, cmsg->sid.data);
	if (old_proc != NULL) {
		mslog(s, old_proc, LOG_DEBUG, "disconnecting previous user session (%u) due to session re-use",
			(unsigned)old_proc->pid);

		if (strcmp(proc->username, old_proc->username) != 0) {
			mslog(s, old_proc, LOG_ERR, "the user of the new session doesn't match the old (new: %s)",
				proc->username);
			return -1;
		}

		/* steal its leases */
		steal_ip_leases(old_proc, proc);

		if (old_proc->pid > 0)
			kill(old_proc->pid, SIGTERM);
		mslog(s, proc, LOG_INFO, "re-using session");
	} else {
		mslog(s, proc, LOG_INFO, "new user session");
	}

	if (cmsg->hostname)
		strlcpy(proc->hostname, cmsg->hostname, sizeof(proc->hostname));

	memcpy(proc->ipv4_seed, &cmsg->ipv4_seed, sizeof(proc->ipv4_seed));

	/* add the links to proc hash */
	if (proc_table_add(s, proc) < 0) {
		mslog(s, proc, LOG_ERR, "failed to add proc hashes");
		return -1;
	}

	return 0;
}

/* Checks for multiple users. 
 * 
 * It returns a negative error code if more than the maximum allowed
 * users are found.
 * 
 * In addition this function will also check whether the cookie
 * used had been re-used before, and then disconnect the old session
 * (cookies are unique). 
 */
int check_multiple_users(main_server_st *s, struct proc_st* proc)
{
struct proc_st *ctmp = NULL, *cpos;
unsigned int entries = 1; /* that one */
unsigned max;

	if (proc->config->max_same_clients == 0)
		return 0;

	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		if (ctmp != proc && ctmp->pid != -1) {
			if (strcmp(proc->username, ctmp->username) == 0) {
				entries++;
			}
		}
	}

	max = proc->config->max_same_clients;

	if (max && entries > max)
		return -1;

	return 0;
}

