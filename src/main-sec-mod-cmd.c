/*
 * Copyright (C) 2015 Red Hat, Inc.
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
#include <route-add.h>
#include <ipc.pb-c.h>
#include <script-list.h>

#include <vpn.h>
#include <main.h>
#include <main-ban.h>
#include <ccan/list/list.h>

int handle_sec_mod_commands(main_server_st * s)
{
	struct iovec iov[3];
	uint8_t cmd;
	struct msghdr hdr;
	uint16_t length;
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
	iov[1].iov_len = 2;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	ret = recvmsg(s->sec_mod_fd, &hdr, 0);
	if (ret == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "cannot obtain metadata from command socket: %s",
		      strerror(e));
		return ERR_BAD_COMMAND;
	}

	if (ret == 0) {
		mslog(s, NULL, LOG_DEBUG, "command socket closed");
		return ERR_BAD_COMMAND;
	}

	if (ret < 3) {
		mslog(s, NULL, LOG_ERR, "command error");
		return ERR_BAD_COMMAND;
	}

	mslog(s, NULL, LOG_DEBUG, "main received message '%s' from sec-mod of %u bytes\n",
	      cmd_request_to_str(cmd), (unsigned)length);

	raw = talloc_size(pool, length);
	if (raw == NULL) {
		mslog(s, NULL, LOG_ERR, "memory error");
		return ERR_MEM;
	}

	raw_len = force_read_timeout(s->sec_mod_fd, raw, length, 2);
	if (raw_len != length) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "cannot obtain data from command socket: %s",
		      strerror(e));
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	switch (cmd) {
	case SM_CMD_AUTH_BAN_IP:{
			BanIpReplyMsg reply = BAN_IP_REPLY_MSG__INIT;

			tmsg = ban_ip_msg__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, NULL, LOG_ERR, "error unpacking sec-mod data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}
			ret = add_ip_to_ban_list(s, tmsg->ip, tmsg->score);
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

			mslog(s, NULL, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(SM_CMD_AUTH_BAN_IP_REPLY));

			ret = send_msg(NULL, s->sec_mod_fd, SM_CMD_AUTH_BAN_IP_REPLY,
				&reply, (pack_size_func)ban_ip_reply_msg__get_packed_size,
				(pack_func)ban_ip_reply_msg__pack);
			if (ret < 0) {
				mslog(s, NULL, LOG_ERR,
				      "could not send reply cmd %d.",
				      (unsigned)cmd);
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}
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

int session_open(main_server_st * s, struct proc_st *proc, const uint8_t *cookie, unsigned cookie_size)
{
	int ret, e;
	SecAuthSessionMsg ireq = SEC_AUTH_SESSION_MSG__INIT;
	SecAuthSessionReplyMsg *msg = NULL;
	unsigned i;
	PROTOBUF_ALLOCATOR(pa, proc);

	ireq.uptime = time(0)-proc->conn_time;
	ireq.has_uptime = 1;
	ireq.bytes_in = proc->bytes_in;
	ireq.has_bytes_in = 1;
	ireq.bytes_out = proc->bytes_out;
	ireq.has_bytes_out = 1;
	ireq.sid.data = proc->sid;
	ireq.sid.len = sizeof(proc->sid);

	if (cookie) {
		ireq.cookie.data = (void*)cookie;
		ireq.cookie.len = cookie_size;
		ireq.has_cookie = 1;
	}

	mslog(s, proc, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(SM_CMD_AUTH_SESSION_OPEN));

	ret = send_msg(proc, s->sec_mod_fd, SM_CMD_AUTH_SESSION_OPEN,
		&ireq, (pack_size_func)sec_auth_session_msg__get_packed_size,
		(pack_func)sec_auth_session_msg__pack);
	if (ret < 0) {
		mslog(s, proc, LOG_ERR,
		      "error sending message to sec-mod cmd socket");
		return -1;
	}

	ret = recv_msg(proc, s->sec_mod_fd, SM_CMD_AUTH_SESSION_REPLY,
	       (void *)&msg, (unpack_func) sec_auth_session_reply_msg__unpack);
	if (ret < 0) {
		e = errno;
		mslog(s, proc, LOG_ERR, "error receiving auth reply message from sec-mod cmd socket: %s", strerror(e));
		return ret;
	}

	if (msg->reply != AUTH__REP__OK) {
		mslog(s, proc, LOG_INFO, "could not initiate session for '%s'", proc->username);
		return -1;
	}

	/* fill in group_cfg_st */
	if (msg->has_no_udp)
		proc->config.no_udp = msg->no_udp;

	if (msg->has_deny_roaming)
		proc->config.deny_roaming = msg->deny_roaming;

	if (msg->has_ipv6_prefix)
		proc->config.ipv6_prefix = msg->ipv6_prefix;

	if (msg->rx_per_sec)
		proc->config.rx_per_sec = msg->rx_per_sec;
	if (msg->tx_per_sec)
		proc->config.tx_per_sec = msg->tx_per_sec;

	if (msg->net_priority)
		proc->config.net_priority = msg->net_priority;

	if (msg->ipv4_net) {
		proc->config.ipv4_network = talloc_strdup(proc, msg->ipv4_net);
	}
	if (msg->ipv4_netmask) {
		proc->config.ipv4_netmask = talloc_strdup(proc, msg->ipv4_netmask);
	}
	if (msg->ipv6_net) {
		proc->config.ipv6_network = talloc_strdup(proc, msg->ipv6_net);
	}

	if (msg->cgroup) {
		proc->config.cgroup = talloc_strdup(proc, msg->cgroup);
	}

	if (msg->xml_config_file) {
		proc->config.xml_config_file = talloc_strdup(proc, msg->xml_config_file);
	}

	if (msg->explicit_ipv4) {
		proc->config.explicit_ipv4 = talloc_strdup(proc, msg->explicit_ipv4);
	}

	if (msg->explicit_ipv6) {
		proc->config.explicit_ipv6 = talloc_strdup(proc, msg->explicit_ipv6);
	}

	if (msg->n_routes > 0) {
		proc->config.routes = talloc_size(proc, sizeof(char*)*msg->n_routes);
		for (i=0;i<msg->n_routes;i++) {
			proc->config.routes[i] = talloc_strdup(proc, msg->routes[i]);
		}
		proc->config.routes_size = msg->n_routes;
	}

	if (msg->n_no_routes > 0) {
		proc->config.no_routes = talloc_size(proc, sizeof(char*)*msg->n_no_routes);
		for (i=0;i<msg->n_no_routes;i++) {
			proc->config.no_routes[i] = talloc_strdup(proc, msg->no_routes[i]);
		}
		proc->config.no_routes_size = msg->n_no_routes;
	}

	if (msg->n_iroutes > 0) {
		proc->config.iroutes = talloc_size(proc, sizeof(char*)*msg->n_iroutes);
		for (i=0;i<msg->n_iroutes;i++) {
			proc->config.iroutes[i] = talloc_strdup(proc, msg->iroutes[i]);
		}
		proc->config.iroutes_size = msg->n_iroutes;
	}

	if (msg->n_dns > 0) {
		proc->config.dns = talloc_size(proc, sizeof(char*)*msg->n_dns);
		for (i=0;i<msg->n_dns;i++) {
			proc->config.dns[i] = talloc_strdup(proc, msg->dns[i]);
		}
		proc->config.dns_size = msg->n_dns;
	}

	if (msg->n_nbns > 0) {
		proc->config.nbns = talloc_size(proc, sizeof(char*)*msg->n_nbns);
		for (i=0;i<msg->n_nbns;i++) {
			proc->config.nbns[i] = talloc_strdup(proc, msg->nbns[i]);
		}
		proc->config.nbns_size = msg->n_nbns;
	}
	sec_auth_session_reply_msg__free_unpacked(msg, &pa);

	return 0;
}

int session_close(main_server_st * s, struct proc_st *proc)
{
	int ret, e;
	SecAuthSessionMsg ireq = SEC_AUTH_SESSION_MSG__INIT;
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

	mslog(s, proc, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(SM_CMD_AUTH_SESSION_CLOSE));

	ret = send_msg(proc, s->sec_mod_fd, SM_CMD_AUTH_SESSION_CLOSE,
		&ireq, (pack_size_func)sec_auth_session_msg__get_packed_size,
		(pack_func)sec_auth_session_msg__pack);
	if (ret < 0) {
		mslog(s, proc, LOG_ERR,
		      "error sending message to sec-mod cmd socket");
		return -1;
	}

	ret = recv_msg(proc, s->sec_mod_fd, SM_CMD_AUTH_CLI_STATS,
	       (void *)&msg, (unpack_func) cli_stats_msg__unpack);
	if (ret < 0) {
		e = errno;
		mslog(s, proc, LOG_ERR, "error receiving auth cli stats message from sec-mod cmd socket: %s", strerror(e));
		return ret;
	}

	proc->bytes_in = msg->bytes_in;
	proc->bytes_out = msg->bytes_out;
	if (msg->has_secmod_client_entries)
		s->secmod_client_entries = msg->secmod_client_entries;

	cli_stats_msg__free_unpacked(msg, &pa);

	return 0;
}
