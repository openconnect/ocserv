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
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>
#include <common.h>

/* Puts the provided PIN into the config's cgroup */
void put_into_cgroup(main_server_st * s, const char *_cgroup, pid_t pid)
{
	char *name, *p, *savep;
	char cgroup[128];
	char file[_POSIX_PATH_MAX];
	FILE *fd;

	if (_cgroup == NULL)
		return;

#ifdef __linux__
	/* format: cpu,memory:cgroup-name */
	strlcpy(cgroup, _cgroup, sizeof(cgroup));

	name = strchr(cgroup, ':');
	if (name == NULL) {
		mslog(s, NULL, LOG_ERR, "error parsing cgroup name: %s",
		      cgroup);
		return;
	}
	name[0] = 0;
	name++;

	p = strtok_r(cgroup, ",", &savep);
	while (p != NULL) {
		mslog(s, NULL, LOG_DEBUG,
		      "putting process %u to cgroup '%s:%s'", (unsigned)pid, p,
		      name);

		snprintf(file, sizeof(file), "/sys/fs/cgroup/%s/%s/tasks", p,
			 name);

		fd = fopen(file, "w");
		if (fd == NULL) {
			mslog(s, NULL, LOG_ERR, "cannot open: %s", file);
			return;
		}

		if (fprintf(fd, "%u", (unsigned)pid) <= 0) {
			mslog(s, NULL, LOG_ERR, "could not write to: %s", file);
		}
		fclose(fd);
		p = strtok_r(NULL, ",", &savep);
	}

	return;
#else
	mslog(s, NULL, LOG_DEBUG,
	      "Ignoring cgroup option as it is not supported on this system");
#endif
}

int send_cookie_auth_reply(main_server_st* s, struct proc_st* proc,
			AUTHREP r)
{
	AuthCookieReplyMsg msg = AUTH_COOKIE_REPLY_MSG__INIT;
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
			 (pack_size_func)auth_cookie_reply_msg__get_packed_size,
			 (pack_func)auth_cookie_reply_msg__pack);
	} else {
		msg.reply = AUTH__REP__FAILED;

		ret = send_msg_to_worker(s, proc, AUTH_COOKIE_REP,
			 &msg,
			 (pack_size_func)auth_cookie_reply_msg__get_packed_size,
			 (pack_func)auth_cookie_reply_msg__pack);
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
struct proc_st *old_proc;

	if (req->cookie.data == NULL || req->cookie.len != sizeof(proc->sid))
		return -1;

	/* generate a new DTLS session ID for each connection, to allow
	 * openconnect of distinguishing when the DTLS key has switched. */
	ret = gnutls_rnd(GNUTLS_RND_NONCE, proc->dtls_session_id, sizeof(proc->dtls_session_id));
	if (ret < 0)
		return -1;
	proc->dtls_session_id_size = sizeof(proc->dtls_session_id);

	/* loads sup config and basic proc info (e.g., username) */
	ret = session_open(s, proc, req->cookie.data, req->cookie.len);
	if (ret < 0) {
		mslog(s, proc, LOG_INFO, "could not open session");
		return -1;
	}

	/* Put into right cgroup */
        if (proc->config->cgroup != NULL) {
        	put_into_cgroup(s, proc->config->cgroup, proc->pid);
	}

	/* check for a user with the same sid as in the cookie */
	old_proc = proc_search_sid(s, req->cookie.data);
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

	/* update the SID */
	memcpy(proc->sid, req->cookie.data, req->cookie.len);
	/* this also hints to call session_close() */
	proc->active_sid = 1;

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

	max = proc->config->max_same_clients;

	if (max == 0)
		return 0;

	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		if (ctmp != proc && ctmp->pid != -1) {
			if (strcmp(proc->username, ctmp->username) == 0) {
				entries++;

				if (entries > max)
					return -1;
			}
		}
	}

	return 0;
}

