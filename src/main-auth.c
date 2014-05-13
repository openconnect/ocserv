/*
 * Copyright (C) 2013, 2014 Nikos Mavrogiannopoulos
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
#include "str.h"

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>
#include <main-auth.h>
#include <plain.h>
#include <common.h>
#include <pam.h>

int send_cookie_auth_reply(main_server_st* s, struct proc_st* proc,
			AUTHREP r)
{
	AuthReplyMsg msg = AUTH_REPLY_MSG__INIT;
	unsigned i;
	int ret;

	if (proc->config.routes_size > MAX_ROUTES) {
		mslog(s, proc, LOG_INFO, "note that the routes sent to the client (%d) exceed the maximum allowed (%d). Truncating.", (int)proc->config.routes_size, (int)MAX_ROUTES);
		proc->config.routes_size = MAX_ROUTES;
	}

	if (r == AUTH__REP__OK && proc->tun_lease.name[0] != 0) {
		char ipv6[MAX_IP_STR];
		char ipv4[MAX_IP_STR];
		char ipv6_local[MAX_IP_STR];
		char ipv4_local[MAX_IP_STR];

		/* fill message */
		msg.reply = AUTH__REP__OK;
		msg.has_cookie = 1;
		msg.cookie.data = proc->cookie;
		msg.cookie.len = COOKIE_SIZE;

		msg.has_session_id = 1;
		msg.session_id.data = proc->dtls_session_id;
		msg.session_id.len = sizeof(proc->dtls_session_id);

		msg.vname = proc->tun_lease.name;
		msg.user_name = proc->username;

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

		msg.ipv4_netmask = proc->config.ipv4_netmask;
		msg.ipv6_netmask = proc->config.ipv6_netmask;
		msg.ipv6_prefix = proc->config.ipv6_prefix;
		if (proc->config.rx_per_sec != 0) {
			msg.has_rx_per_sec = 1;
			msg.rx_per_sec = proc->config.rx_per_sec;
		}

		if (proc->config.tx_per_sec != 0) {
			msg.has_tx_per_sec = 1;
			msg.tx_per_sec = proc->config.tx_per_sec;
		}

		if (proc->config.net_priority != 0) {
			msg.has_net_priority = 1;
			msg.net_priority = proc->config.net_priority;
		}

		if (proc->config.no_udp != 0) {
			msg.has_no_udp = 1;
			msg.no_udp = proc->config.no_udp;
		}

		msg.n_dns = proc->config.dns_size;
		for (i=0;i<proc->config.dns_size;i++) {
			mslog(s, proc, LOG_DEBUG, "sending dns '%s'", proc->config.dns[i]);
			msg.dns = proc->config.dns;
		}

		msg.n_nbns = proc->config.nbns_size;
		for (i=0;i<proc->config.nbns_size;i++) {
			mslog(s, proc, LOG_DEBUG, "sending nbns '%s'", proc->config.nbns[i]);
			msg.nbns = proc->config.nbns;
		}

		msg.n_routes = proc->config.routes_size;
		for (i=0;i<proc->config.routes_size;i++) {
			mslog(s, proc, LOG_DEBUG, "sending route '%s'", proc->config.routes[i]);
			msg.routes = proc->config.routes;
		}

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
struct stored_cookie_st sc;
time_t now = time(0);
gnutls_datum_t key = {s->cookie_key, sizeof(s->cookie_key)};

	if (req->cookie.len == 0 || req->cookie.len != sizeof(proc->cookie)) {
		mslog(s, proc, LOG_INFO, "error in cookie size");
		return -1;
	}

	ret = decrypt_cookie(&key, req->cookie.data, req->cookie.len, &sc);
	if (ret < 0) {
		mslog(s, proc, LOG_INFO, "error decrypting cookie");
		return -1;
	}

	if (sc.expiration < now)
		return -1;

	memcpy(proc->cookie, req->cookie.data, req->cookie.len);
	memcpy(proc->username, sc.username, sizeof(proc->username));
	memcpy(proc->groupname, sc.groupname, sizeof(proc->groupname));
	memcpy(proc->hostname, sc.hostname, sizeof(proc->hostname));
	memcpy(proc->dtls_session_id, sc.session_id, sizeof(proc->dtls_session_id));
	proc->dtls_session_id_size = sizeof(proc->dtls_session_id);

	proc->username[sizeof(proc->username)-1] = 0;
	proc->groupname[sizeof(proc->groupname)-1] = 0;
	proc->hostname[sizeof(proc->hostname)-1] = 0;

	memcpy(proc->ipv4_seed, sc.ipv4_seed, sizeof(proc->ipv4_seed));

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

	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		if (ctmp != proc && ctmp->pid != -1) {
			if (memcmp(proc->cookie, ctmp->cookie, sizeof(proc->cookie)) == 0) {
				mslog(s, ctmp, LOG_DEBUG, "disconnecting '%s' due to new cookie connection", ctmp->username);

				/* steal its leases */
				steal_ip_leases(ctmp, proc);

				kill(ctmp->pid, SIGTERM);
			} else if (strcmp(proc->username, ctmp->username) == 0) {
				entries++;
			}
		}
	}

	if (s->config->max_same_clients && entries > s->config->max_same_clients)
		return -1;

	return 0;
}

