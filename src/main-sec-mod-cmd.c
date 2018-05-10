/*
 * Copyright (C) 2015-2017 Red Hat, Inc.
 * Copyright (C) 2015-2017 Nikos Mavrogiannopoulos
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
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <system.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#include "common.h"
#include "str.h"
#include "setproctitle.h"
#include <sec-mod.h>
#include <ip-lease.h>
#include <route-add.h>
#include <ipc.pb-c.h>
#include <script-list.h>
#include <cloexec.h>

#include <vpn.h>
#include <main.h>
#include <main-ban.h>
#include <ccan/list/list.h>

#ifdef HAVE_MALLOC_TRIM
# include <malloc.h>
#endif

static void update_auth_failures(main_server_st * s, uint64_t auth_failures)
{
	if (s->stats.auth_failures + auth_failures < s->stats.auth_failures) {
		mslog(s, NULL, LOG_INFO, "overflow on updating authentication failures; resetting");
		s->stats.auth_failures = 0;
		return;
	}
	s->stats.auth_failures += auth_failures;
	s->stats.total_auth_failures += auth_failures;
}

int handle_sec_mod_commands(main_server_st * s)
{
	struct iovec iov[3];
	uint8_t cmd;
	struct msghdr hdr;
	uint32_t length;
	uint8_t *raw;
	int ret, raw_len, e;
	void *pool = talloc_new(s);
	PROTOBUF_ALLOCATOR(pa, pool);
	BanIpMsg *tmsg = NULL;

	if (pool == NULL)
		return -1;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = &length;
	iov[1].iov_len = 4;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	do {
		ret = recvmsg(s->sec_mod_fd, &hdr, 0);
	} while(ret == -1 && errno == EINTR);
	if (ret == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "cannot obtain metadata from sec-mod socket: %s",
		      strerror(e));
		return ERR_BAD_COMMAND;
	}

	if (ret == 0) {
		mslog(s, NULL, LOG_ERR, "command socket for sec-mod closed");
		return ERR_BAD_COMMAND;
	}

	if (ret < 5 || cmd <= MIN_SECM_CMD || cmd >= MAX_SECM_CMD) {
		mslog(s, NULL, LOG_ERR, "main received invalid message from sec-mod of %u bytes (cmd: %u)\n",
		      (unsigned)length, (unsigned)cmd);
		return ERR_BAD_COMMAND;
	}

	mslog(s, NULL, LOG_DEBUG, "main received message '%s' from sec-mod of %u bytes\n",
	      cmd_request_to_str(cmd), (unsigned)length);

	raw = talloc_size(pool, length);
	if (raw == NULL) {
		mslog(s, NULL, LOG_ERR, "memory error");
		return ERR_MEM;
	}

	raw_len = force_read_timeout(s->sec_mod_fd, raw, length, MAIN_SEC_MOD_TIMEOUT);
	if (raw_len != length) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "cannot obtain data of cmd %u with length %u from sec-mod socket: %s",
		      (unsigned)cmd, (unsigned)length, strerror(e));
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	switch (cmd) {
	case CMD_SECM_BAN_IP:{
			BanIpReplyMsg reply = BAN_IP_REPLY_MSG__INIT;

			tmsg = ban_ip_msg__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, NULL, LOG_ERR, "error unpacking sec-mod data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}
			ret = add_str_ip_to_ban_list(s, tmsg->ip, tmsg->score);
			if (ret < 0) {
				reply.reply =
				    AUTH__REP__FAILED;
			} else {
				/* no need to send a reply at all */
				ret = 0;
				goto cleanup;
			}

			reply.sid.data = tmsg->sid.data;
			reply.sid.len = tmsg->sid.len;
			reply.has_sid = tmsg->has_sid;

			mslog(s, NULL, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(CMD_SECM_BAN_IP_REPLY));

			ret = send_msg(NULL, s->sec_mod_fd, CMD_SECM_BAN_IP_REPLY,
				&reply, (pack_size_func)ban_ip_reply_msg__get_packed_size,
				(pack_func)ban_ip_reply_msg__pack);
			if (ret < 0) {
				mslog(s, NULL, LOG_ERR,
				      "could not send reply cmd %d.",
				      (unsigned)cmd);
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			safe_memset(tmsg->sid.data, 0, tmsg->sid.len);
			safe_memset(raw, 0, raw_len);
		}

		break;
	case CMD_SECM_STATS:{
			SecmStatsMsg *smsg = NULL;

			smsg = secm_stats_msg__unpack(&pa, raw_len, raw);
			if (smsg == NULL) {
				mslog(s, NULL, LOG_ERR, "error unpacking sec-mod data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			s->stats.secmod_client_entries = smsg->secmod_client_entries;
			s->stats.tlsdb_entries = smsg->secmod_tlsdb_entries;
			s->stats.max_auth_time = smsg->secmod_max_auth_time;
			s->stats.avg_auth_time = smsg->secmod_avg_auth_time;
			update_auth_failures(s, smsg->secmod_auth_failures);

		}

		break;
	default:
		mslog(s, NULL, LOG_ERR, "unknown CMD from sec-mod 0x%x.", (unsigned)cmd);
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	if (tmsg != NULL)
		ban_ip_msg__free_unpacked(tmsg, &pa);
	talloc_free(raw);
	talloc_free(pool);

	return ret;
}

static void append_routes(main_server_st *s, proc_st *proc, GroupCfgSt *gc)
{
	vhost_cfg_st *vhost = proc->vhost;

	/* if we have known_iroutes, we must append them to the routes list */
	if (vhost->perm_config.config->known_iroutes_size > 0 || vhost->perm_config.config->append_routes) {
		char **old_routes = gc->routes;
		unsigned old_routes_size = gc->n_routes;
		unsigned i, j, append;
		unsigned to_append = 0;

		to_append = vhost->perm_config.config->known_iroutes_size;
		if (vhost->perm_config.config->append_routes)
			to_append += vhost->perm_config.config->network.routes_size;

		gc->n_routes = 0;
		gc->routes = talloc_size(proc, sizeof(char*)*(old_routes_size+to_append));

		for (i=0;i<old_routes_size;i++) {
			gc->routes[i] = talloc_strdup(proc, old_routes[i]);
			if (gc->routes[i] == NULL)
				break;
			gc->n_routes++;
		}

		if (gc->routes) {
			/* Append any iroutes that are known and don't match the client's */
			for (i=0;i<vhost->perm_config.config->known_iroutes_size;i++) {
				append = 1;
				for (j=0;j<gc->n_iroutes;j++) {
					if (strcmp(gc->iroutes[j], vhost->perm_config.config->known_iroutes[i]) == 0) {
						append = 0;
						break;
					}
				}

				if (append) {
					gc->routes[gc->n_routes] = talloc_strdup(proc, vhost->perm_config.config->known_iroutes[i]);
					if (gc->routes[gc->n_routes] == NULL)
						break;
					gc->n_routes++;
				}
			}
		}

		if (vhost->perm_config.config->append_routes) {
			/* Append all global routes */
			if (gc->routes) {
				for (i=0;i<vhost->perm_config.config->network.routes_size;i++) {
					gc->routes[gc->n_routes] = talloc_strdup(proc, vhost->perm_config.config->network.routes[i]);
					if (gc->routes[gc->n_routes] == NULL)
						break;
					gc->n_routes++;
				}
			}

			/* Append no-routes */
			if (vhost->perm_config.config->network.no_routes_size == 0)
				return;

			old_routes = gc->no_routes;
			old_routes_size = gc->n_no_routes;

			gc->n_no_routes = 0;
			gc->no_routes = talloc_size(proc, sizeof(char*)*(old_routes_size+vhost->perm_config.config->network.no_routes_size));

			for (i=0;i<old_routes_size;i++) {
				gc->no_routes[i] = talloc_strdup(proc, old_routes[i]);
				if (gc->no_routes[i] == NULL)
					break;
				gc->n_no_routes++;
			}

			for (i=0;i<vhost->perm_config.config->network.no_routes_size;i++) {
				gc->no_routes[gc->n_no_routes] = talloc_strdup(proc, vhost->perm_config.config->network.no_routes[i]);
				if (gc->no_routes[gc->n_no_routes] == NULL)
					break;
				gc->n_no_routes++;
			}
		}
	}
}

static
void apply_default_config(main_server_st *s, proc_st *proc, GroupCfgSt *gc)
{
	vhost_cfg_st *vhost = proc->vhost;

	if (!gc->has_no_udp) {
		gc->no_udp = (vhost->perm_config.udp_port!=0)?0:1;
		gc->has_no_udp = 1;
	}

	if (gc->routes == NULL) {
		gc->routes = vhost->perm_config.config->network.routes;
		gc->n_routes = vhost->perm_config.config->network.routes_size;
	}

	append_routes(s, proc, gc);

	if (gc->no_routes == NULL) {
		gc->no_routes = vhost->perm_config.config->network.no_routes;
		gc->n_no_routes = vhost->perm_config.config->network.no_routes_size;
	}

	if (gc->dns == NULL) {
		gc->dns = vhost->perm_config.config->network.dns;
		gc->n_dns = vhost->perm_config.config->network.dns_size;
	}

	if (gc->nbns == NULL) {
		gc->nbns = vhost->perm_config.config->network.nbns;
		gc->n_nbns = vhost->perm_config.config->network.nbns_size;
	}

	if (!gc->has_interim_update_secs) {
		gc->interim_update_secs = vhost->perm_config.config->stats_report_time;
		gc->has_interim_update_secs = 1;
	}

	if (!gc->has_session_timeout_secs) {
		gc->session_timeout_secs = vhost->perm_config.config->session_timeout;
		gc->has_session_timeout_secs = 1;
	}

	if (!gc->has_deny_roaming) {
		gc->deny_roaming = vhost->perm_config.config->deny_roaming;
		gc->has_deny_roaming = 1;
	}

	if (!gc->ipv4_net) {
		gc->ipv4_net = vhost->perm_config.config->network.ipv4_network;
	}

	if (!gc->ipv4_netmask) {
		gc->ipv4_netmask = vhost->perm_config.config->network.ipv4_netmask;
	}

	if (!gc->ipv6_net) {
		gc->ipv6_net = vhost->perm_config.config->network.ipv6_network;
	}

	if (!gc->has_ipv6_prefix) {
		gc->ipv6_prefix = vhost->perm_config.config->network.ipv6_prefix;
		gc->has_ipv6_prefix = 1;
	}

	if (!gc->has_ipv6_subnet_prefix) {
		gc->ipv6_subnet_prefix = vhost->perm_config.config->network.ipv6_subnet_prefix;
		gc->has_ipv6_subnet_prefix = 1;
	}

	if (!gc->cgroup) {
		gc->cgroup = vhost->perm_config.config->cgroup;
	}

	if (!gc->xml_config_file) {
		gc->xml_config_file = vhost->perm_config.config->xml_config_file;
	}

	if (!gc->has_rx_per_sec) {
		gc->rx_per_sec = vhost->perm_config.config->rx_per_sec;
		gc->has_rx_per_sec = 1;
	}

	if (!gc->has_tx_per_sec) {
		gc->tx_per_sec = vhost->perm_config.config->tx_per_sec;
		gc->has_tx_per_sec = 1;
	}

	if (!gc->has_net_priority) {
		gc->net_priority = vhost->perm_config.config->net_priority;
		gc->has_net_priority = 1;
	}

	if (!gc->has_keepalive) {
		gc->keepalive = vhost->perm_config.config->keepalive;
		gc->has_keepalive = 1;
	}

	if (!gc->has_dpd) {
		gc->dpd = vhost->perm_config.config->dpd;
		gc->has_dpd = 1;
	}

	if (!gc->has_mobile_dpd) {
		gc->mobile_dpd = vhost->perm_config.config->mobile_dpd;
		gc->has_mobile_dpd = 1;
	}

	if (!gc->has_max_same_clients) {
		gc->max_same_clients = vhost->perm_config.config->max_same_clients;
		gc->has_max_same_clients = 1;
	}

	if (!gc->has_tunnel_all_dns) {
		gc->tunnel_all_dns = vhost->perm_config.config->tunnel_all_dns;
		gc->has_tunnel_all_dns = 1;
	}

	if (!gc->has_restrict_user_to_routes) {
		gc->restrict_user_to_routes = vhost->perm_config.config->restrict_user_to_routes;
		gc->has_restrict_user_to_routes = 1;
	}

	if (!gc->has_mtu) {
		gc->mtu = vhost->perm_config.config->network.mtu;
		gc->has_mtu = 1;
	}

	if (!gc->has_idle_timeout) {
		gc->idle_timeout = vhost->perm_config.config->idle_timeout;
		gc->has_idle_timeout = 1;
	}

	if (!gc->has_mobile_idle_timeout) {
		gc->mobile_idle_timeout = vhost->perm_config.config->mobile_idle_timeout;
		gc->has_mobile_idle_timeout = 1;
	}

	if (gc->n_fw_ports == 0 && vhost->perm_config.config->n_fw_ports > 0) {
		gc->n_fw_ports = vhost->perm_config.config->n_fw_ports;
		gc->fw_ports = vhost->perm_config.config->fw_ports;
	}

	/* since we keep pointers on s->config, increase its usage count */
	proc->config_usage_count = vhost->perm_config.config->usage_count;
	(*proc->config_usage_count)++;
}

int session_open(main_server_st *s, struct proc_st *proc, const uint8_t *cookie, unsigned cookie_size)
{
	int ret, e;
	SecmSessionOpenMsg ireq = SECM_SESSION_OPEN_MSG__INIT;
	SecmSessionReplyMsg *msg = NULL;
	char str_ipv4[MAX_IP_STR];
	char str_ipv6[MAX_IP_STR];
	char str_ip[MAX_IP_STR];

	if (cookie == NULL || cookie_size != SID_SIZE)
		return -1;

	ireq.sid.data = (void*)cookie;
	ireq.sid.len = cookie_size;

	if (proc->ipv4 && 
	    human_addr2((struct sockaddr *)&proc->ipv4->rip, proc->ipv4->rip_len,
	    str_ipv4, sizeof(str_ipv4), 0) != NULL) {
		ireq.ipv4 = str_ipv4;
	}

	if (proc->ipv6 && 
	    human_addr2((struct sockaddr *)&proc->ipv6->rip, proc->ipv6->rip_len,
	    str_ipv6, sizeof(str_ipv6), 0) != NULL) {
		ireq.ipv6 = str_ipv6;
	}

	mslog(s, proc, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(CMD_SECM_SESSION_OPEN));

	ret = send_msg(proc, s->sec_mod_fd_sync, CMD_SECM_SESSION_OPEN,
		&ireq, (pack_size_func)secm_session_open_msg__get_packed_size,
		(pack_func)secm_session_open_msg__pack);
	if (ret < 0) {
		mslog(s, proc, LOG_ERR,
		      "error sending message to sec-mod cmd socket");
		return -1;
	}

	ret = recv_msg(proc, s->sec_mod_fd_sync, CMD_SECM_SESSION_REPLY,
	       (void *)&msg, (unpack_func) secm_session_reply_msg__unpack, MAIN_SEC_MOD_TIMEOUT);
	if (ret < 0) {
		e = errno;
		mslog(s, proc, LOG_ERR, "error receiving auth reply message from sec-mod cmd socket: %s", strerror(e));
		return ret;
	}

	if (msg->reply != AUTH__REP__OK) {
		mslog(s, proc, LOG_DEBUG, "session initiation was rejected");
		update_auth_failures(s, 1);
		return -1;
	}

	if (msg->username == NULL) {
		mslog(s, proc, LOG_INFO, "no username present in session reply");
		return -1;
	}
	strlcpy(proc->username, msg->username, sizeof(proc->username));

	/* override the group name in order to load the correct configuration in
	 * case his group is specified in the certificate */
	if (msg->groupname)
		strlcpy(proc->groupname, msg->groupname, sizeof(proc->groupname));

	if (msg->config == NULL) {
		mslog(s, proc, LOG_INFO, "received invalid configuration for '%s'; could not initiate session", proc->username);
		return -1;
	}

	memcpy(proc->ipv4_seed, &msg->ipv4_seed, sizeof(proc->ipv4_seed));

	proc->config = msg->config;
	proc->vhost = find_vhost(s->vconfig, msg->vhost);

	apply_default_config(s, proc, proc->config);

	/* check whether the cookie IP matches */
	if (proc->config && proc->config->deny_roaming != 0) {
		if (msg->ip == NULL) {
			return -1;
		}

		if (human_addr2((struct sockaddr *)&proc->remote_addr, proc->remote_addr_len,
					    str_ip, sizeof(str_ip), 0) == NULL)
			return -1;

		if (strcmp(str_ip, msg->ip) != 0) {
			mslog(s, proc, LOG_INFO, "user '%s' is re-using cookie from different IP (prev: %s, current: %s); rejecting",
				proc->username, msg->ip, str_ip);
			return -1;
		}
	}

	return 0;
}

static void reset_stats(main_server_st *s, time_t now)
{
	mslog(s, NULL, LOG_INFO, "Start statistics block");
	mslog(s, NULL, LOG_INFO, "Total sessions handled: %lu", (unsigned long)s->stats.total_sessions_closed);
	mslog(s, NULL, LOG_INFO, "Sessions handled: %lu", (unsigned long)s->stats.sessions_closed);
	mslog(s, NULL, LOG_INFO, "Maximum session time: %lu min", (unsigned long)s->stats.max_session_mins);
	mslog(s, NULL, LOG_INFO, "Average session time: %lu min", (unsigned long)s->stats.avg_session_mins);
	mslog(s, NULL, LOG_INFO, "Closed due to timeout sessions: %lu", (unsigned long)s->stats.session_timeouts);
	mslog(s, NULL, LOG_INFO, "Closed due to timeout (idle) sessions: %lu", (unsigned long)s->stats.session_idle_timeouts);
	mslog(s, NULL, LOG_INFO, "Closed due to error sessions: %lu", (unsigned long)s->stats.session_errors);

	mslog(s, NULL, LOG_INFO, "Total authentication failures: %lu", (unsigned long)s->stats.total_auth_failures);
	mslog(s, NULL, LOG_INFO, "Authentication failures: %lu", (unsigned long)s->stats.auth_failures);
	mslog(s, NULL, LOG_INFO, "Maximum authentication time: %lu sec", (unsigned long)s->stats.max_auth_time);
	mslog(s, NULL, LOG_INFO, "Average authentication time: %lu sec", (unsigned long)s->stats.avg_auth_time);
	mslog(s, NULL, LOG_INFO, "Data in: %lu, out: %lu kbytes", (unsigned long)s->stats.kbytes_in, (unsigned long)s->stats.kbytes_out);
	mslog(s, NULL, LOG_INFO, "End of statistics block; resetting non-total stats");

	s->stats.session_idle_timeouts = 0;
	s->stats.session_timeouts = 0;
	s->stats.session_errors = 0;
	s->stats.sessions_closed = 0;
	s->stats.auth_failures = 0;
	s->stats.last_reset = now;
	s->stats.kbytes_in = 0;
	s->stats.kbytes_out = 0;
	s->stats.max_session_mins = 0;
	s->stats.max_auth_time = 0;
}

static void update_main_stats(main_server_st * s, struct proc_st *proc)
{
	uint64_t kb_in, kb_out;
	time_t now = time(0), stime;
	vhost_cfg_st *vhost = proc->vhost;

	if (vhost->perm_config.stats_reset_time != 0 &&
	    now - s->stats.last_reset > vhost->perm_config.stats_reset_time) {
		mslog(s, NULL, LOG_INFO, "resetting stats counters");
		reset_stats(s, now);
	}

	if (proc->discon_reason == REASON_IDLE_TIMEOUT)
		s->stats.session_idle_timeouts++;
	else if (proc->discon_reason == REASON_SESSION_TIMEOUT)
		s->stats.session_timeouts++;
	else if (proc->discon_reason == REASON_ERROR)
		s->stats.session_errors++;

	s->stats.sessions_closed++;
	s->stats.total_sessions_closed++;
	if (s->stats.sessions_closed == 0) { /* overflow */
		goto reset;
	}

	kb_in = proc->bytes_in/1000;
	kb_out = proc->bytes_out/1000;

	if (s->stats.kbytes_in + kb_in <  s->stats.kbytes_in)
		goto reset;

	if (s->stats.kbytes_out + kb_out <  s->stats.kbytes_out)
		goto reset;

	s->stats.kbytes_in += kb_in;
	s->stats.kbytes_out += kb_out;

	if (s->stats.min_mtu == 0 || proc->mtu < s->stats.min_mtu)
		s->stats.min_mtu = proc->mtu;
	if (s->stats.max_mtu == 0 || proc->mtu > s->stats.min_mtu)
		s->stats.max_mtu = proc->mtu;

	/* connection time in minutes */
	stime = (now - proc->conn_time)/60;
	if (stime > 0) {
		s->stats.avg_session_mins = ((s->stats.sessions_closed-1) * s->stats.avg_session_mins + stime) / s->stats.sessions_closed;
		if (stime > s->stats.max_session_mins)
			s->stats.max_session_mins = stime;
	}

	return;
 reset:
	mslog(s, NULL, LOG_INFO, "overflow on updating server statistics, resetting stats");
	reset_stats(s, now);
}

int session_close(main_server_st * s, struct proc_st *proc)
{
	int ret, e;
	SecmSessionCloseMsg ireq = SECM_SESSION_CLOSE_MSG__INIT;
	CliStatsMsg *msg = NULL;
	PROTOBUF_ALLOCATOR(pa, proc);

	ireq.uptime = time(0)-proc->conn_time;
	ireq.has_uptime = 1;
	ireq.bytes_in = proc->bytes_in;
	ireq.has_bytes_in = 1;
	ireq.bytes_out = proc->bytes_out;
	ireq.has_bytes_out = 1;
	ireq.sid.data = proc->sid;
	ireq.sid.len = sizeof(proc->sid);

	mslog(s, proc, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(CMD_SECM_SESSION_CLOSE));

	ret = send_msg(proc, s->sec_mod_fd_sync, CMD_SECM_SESSION_CLOSE,
		&ireq, (pack_size_func)secm_session_close_msg__get_packed_size,
		(pack_func)secm_session_close_msg__pack);
	if (ret < 0) {
		mslog(s, proc, LOG_ERR,
		      "error sending message to sec-mod cmd socket");
		return -1;
	}

	ret = recv_msg(proc, s->sec_mod_fd_sync, CMD_SECM_CLI_STATS,
	       (void *)&msg, (unpack_func) cli_stats_msg__unpack, MAIN_SEC_MOD_TIMEOUT);
	if (ret < 0) {
		e = errno;
		mslog(s, proc, LOG_ERR, "error receiving auth cli stats message from sec-mod cmd socket: %s", strerror(e));
		return ret;
	}

	proc->bytes_in = msg->bytes_in;
	proc->bytes_out = msg->bytes_out;
	if (msg->has_discon_reason) {
		proc->discon_reason = msg->discon_reason;
	}

	update_main_stats(s, proc);

	cli_stats_msg__free_unpacked(msg, &pa);

	return 0;
}

int secmod_reload(main_server_st * s)
{
	int ret, e;

	mslog(s, NULL, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(CMD_SECM_RELOAD));

	ret = send_msg(s->main_pool, s->sec_mod_fd_sync, CMD_SECM_RELOAD,
		       NULL, NULL, NULL);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR,
		      "error sending message to sec-mod cmd socket");
		return -1;
	}

	ret = recv_msg(s->main_pool, s->sec_mod_fd_sync, CMD_SECM_RELOAD_REPLY,
		       NULL, NULL, MAIN_SEC_MOD_TIMEOUT);
	if (ret < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "error receiving reload reply message from sec-mod cmd socket: %s", strerror(e));
		return ret;
	}

	return 0;
}

/* Creates a permanent filename to use for secmod to main communication
 */
const char *secmod_socket_file_name(struct perm_cfg_st *perm_config)
{
	unsigned int rnd;
	int ret;
	static char socket_file[_POSIX_PATH_MAX] = {0};

	if (socket_file[0] != 0)
		return socket_file;

	ret = gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(rnd));
	if (ret < 0)
		exit(1);

	/* make socket name */
	snprintf(socket_file, sizeof(socket_file), "%s.%x",
		 perm_config->socket_file_prefix, rnd);

	return socket_file;
}

static void clear_unneeded_mem(struct list_head *vconfig)
{
	vhost_cfg_st *vhost = NULL;

	/* deinitialize certificate credentials etc. */
	list_for_each_rev(vconfig, vhost, list) {
		tls_vhost_deinit(vhost);
	}
}

/* Returns two file descriptors to be used for communication with sec-mod.
 * The sync_fd is used by main to send synchronous commands- commands which
 * expect a reply immediately.
 */
int run_sec_mod(main_server_st *s, int *sync_fd)
{
	int e, fd[2], ret;
	int sfd[2];
	pid_t pid;
	const char *p;

	/* fills s->socket_file */
	strlcpy(s->socket_file, secmod_socket_file_name(GETPCONFIG(s)), sizeof(s->socket_file));
	mslog(s, NULL, LOG_DEBUG, "created sec-mod socket file (%s)", s->socket_file);

	if (GETPCONFIG(s)->chroot_dir != NULL) {
		ret = snprintf(s->full_socket_file, sizeof(s->full_socket_file), "%s/%s",
			       GETPCONFIG(s)->chroot_dir, s->socket_file);
		if (ret != strlen(s->full_socket_file)) {
			mslog(s, NULL, LOG_ERR, "too long chroot path; cannot create socket: %s", s->full_socket_file);
			exit(1);
		}
	} else {
		strlcpy(s->full_socket_file, s->socket_file, sizeof(s->full_socket_file));
	}

	p = s->full_socket_file;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "error creating sec-mod command socket");
		exit(1);
	}

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sfd);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "error creating sec-mod sync command socket");
		exit(1);
	}

	pid = fork();
	if (pid == 0) {		/* child */
		clear_lists(s);
		kill_on_parent_kill(SIGTERM);

#ifdef HAVE_MALLOC_TRIM
		/* try to return all the pages we've freed to
		 * the operating system. */
		malloc_trim(0);
#endif
		setproctitle(PACKAGE_NAME "-sm");
		close(fd[1]);
		close(sfd[1]);
		set_cloexec_flag (fd[0], 1);
		set_cloexec_flag (sfd[0], 1);
		clear_unneeded_mem(s->vconfig);
		sec_mod_server(s->main_pool, s->config_pool, s->vconfig, p, fd[0], sfd[0]);
		exit(0);
	} else if (pid > 0) {	/* parent */
		close(fd[0]);
		close(sfd[0]);
		s->sec_mod_pid = pid;
		set_cloexec_flag (fd[1], 1);
		set_cloexec_flag (sfd[1], 1);
		*sync_fd = sfd[1];
		return fd[1];
	} else {
		e = errno;
		mslog(s, NULL, LOG_ERR, "error in fork(): %s", strerror(e));
		exit(1);
	}
}

