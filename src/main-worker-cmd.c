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
#include <sys/un.h>
#include <cloexec.h>
#include "common.h"
#include "str.h"
#include "setproctitle.h"
#include <sec-mod.h>
#include <route-add.h>
#include <ip-lease.h>
#include <proc-search.h>
#include <ipc.pb-c.h>
#include <script-list.h>
#include <inttypes.h>
#include <ev.h>

#ifdef HAVE_MALLOC_TRIM
# include <malloc.h>
#endif

#include <vpn.h>
#include <tun.h>
#include <main.h>
#include <main-ban.h>
#include <ccan/list/list.h>

int set_tun_mtu(main_server_st * s, struct proc_st *proc, unsigned mtu)
{
	int fd, ret, e;
	struct ifreq ifr;
	const char *name;

	if (proc->tun_lease.name[0] == 0)
		return -1;

	name = proc->tun_lease.name;

	mslog(s, proc, LOG_DEBUG, "setting %s MTU to %u", name, mtu);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_mtu = mtu;

	ret = ioctl(fd, SIOCSIFMTU, &ifr);
	if (ret != 0) {
		e = errno;
		mslog(s, proc, LOG_INFO, "ioctl SIOCSIFMTU(%d) error: %s",
		      mtu, strerror(e));
		ret = -1;
		goto fail;
	}
	proc->mtu = mtu;

	ret = 0;
 fail:
	close(fd);
	return ret;
}

int handle_script_exit(main_server_st *s, struct proc_st *proc, int code)
{
	int ret;

	if (code == 0) {
		ret = send_cookie_auth_reply(s, proc, AUTH__REP__OK);
		if (ret < 0) {
			mslog(s, proc, LOG_ERR,
			      "could not send auth reply cmd.");
			ret = ERR_BAD_COMMAND;
			goto fail;
		}

		ret = apply_iroutes(s, proc);
		if (ret < 0) {
			mslog(s, proc, LOG_ERR,
			      "could not apply routes for user; denying access.");
			ret = ERR_BAD_COMMAND;
			goto fail;
		}

		proc->status = PS_AUTH_COMPLETED;
		mslog(s, proc, LOG_INFO, "user logged in");
	} else {
		mslog(s, proc, LOG_INFO,
		      "failed authentication attempt for user '%s'",
		      proc->username);
		ret =
		    send_cookie_auth_reply(s, proc, AUTH__REP__FAILED);
		if (ret < 0) {
			mslog(s, proc, LOG_ERR,
			      "could not send reply auth cmd.");
			ret = ERR_BAD_COMMAND;
			goto fail;
		}
	}
	ret = 0;

 fail:
	/* we close the lease tun fd both on success and failure.
	 * The parent doesn't need to keep the tunfd, and if it does,
	 * it causes issues to client.
	 */
	if (proc->tun_lease.fd >= 0)
		close(proc->tun_lease.fd);
	proc->tun_lease.fd = -1;

	return ret;
}

/* This is the function after which proc is populated */
static int accept_user(main_server_st * s, struct proc_st *proc, unsigned cmd)
{
	int ret;
	const char *group;

	/* check for multiple connections */
	ret = check_multiple_users(s, proc);
	if (ret < 0) {
		mslog(s, proc, LOG_INFO,
		      "user tried to connect more than %u times",
		      proc->config->max_same_clients);
		return ret;
	}

	ret = open_tun(s, proc);
	if (ret < 0) {
		return -1;
	}

	if (proc->groupname[0] == 0)
		group = "[unknown]";
	else
		group = proc->groupname;

	if (cmd == AUTH_COOKIE_REQ) {
		mslog(s, proc, LOG_DEBUG,
		      "user of group '%s' authenticated (using cookie)",
		      group);
	} else {
		mslog(s, proc, LOG_INFO,
		      "user of group '%s' authenticated but from unknown state! rejecting.",
		      group);
		return ERR_BAD_COMMAND;
	}

	/* do scripts and utmp */
	ret = user_connected(s, proc);
	if (ret < 0 && ret != ERR_WAIT_FOR_SCRIPT) {
		mslog(s, proc, LOG_INFO, "user disconnected due to script");
	}

	return ret;
}

/* Performs the required steps based on the result from the 
 * authentication function (e.g. handle_auth_init).
 *
 * @cmd: the command received
 * @result: the auth result
 */
static int handle_cookie_auth_res(main_server_st *s, struct proc_st *proc,
			   unsigned cmd, int result)
{
	int ret;

	if (result == 0) {
		ret = accept_user(s, proc, cmd);
		if (ret < 0) {
			proc->status = PS_AUTH_FAILED;
			goto finished;
		}
		proc->status = PS_AUTH_COMPLETED;
	} else if (result < 0) {
		proc->status = PS_AUTH_FAILED;
		ret = result;
	} else {
		proc->status = PS_AUTH_FAILED;
		mslog(s, proc, LOG_ERR, "unexpected auth result: %d\n", result);
		ret = ERR_BAD_COMMAND;
	}

 finished:
	if (ret == ERR_WAIT_FOR_SCRIPT) {
		/* we will wait for script termination to send our reply.
		 * The notification of peer will be done in handle_script_exit().
		 */
		ret = 0;
	} else {
		/* no script was called. Handle it as a successful script call. */
		ret = handle_script_exit(s, proc, ret);
		if (ret < 0)
			proc->status = PS_AUTH_FAILED;
	}

	return ret;
}

int handle_worker_commands(main_server_st * s, struct proc_st *proc)
{
	uint8_t cmd;
	AuthCookieRequestMsg *auth_cookie_req;
	size_t length;
	uint8_t *raw;
	int ret, raw_len, e;
	PROTOBUF_ALLOCATOR(pa, proc);

	ret = recv_msg_headers(proc->fd, &cmd, MAX_WAIT_SECS);
	if (ret < 0) {
		if (ret == ERR_PEER_TERMINATED)
			mslog(s, proc, LOG_DEBUG,
			      "worker terminated");
		else
			mslog(s, proc, LOG_DEBUG,
			      "cannot obtain metadata from worker's command socket");
		return ret;
	}

	length = ret;

	if (length > MAX_MSG_SIZE) {
		mslog(s, proc, LOG_DEBUG,
		      "received too big message (%d)", (int)length);
		ret = ERR_BAD_COMMAND;
		return ret;
	}

	mslog(s, proc, LOG_DEBUG, "main received worker's message '%s' of %u bytes\n",
	      cmd_request_to_str(cmd), (unsigned)length);

	raw = talloc_size(proc, length);
	if (raw == NULL) {
		mslog(s, proc, LOG_ERR, "memory error");
		return ERR_MEM;
	}

	raw_len = force_read_timeout(proc->fd, raw, length, MAX_WAIT_SECS);
	if (raw_len != length) {
		e = errno;
		mslog(s, proc, LOG_DEBUG,
		      "cannot obtain data from worker's command socket: %s",
		      strerror(e));
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	switch (cmd) {
	case CMD_BAN_IP:{
			BanIpMsg *tmsg;
			BanIpReplyMsg reply = BAN_IP_REPLY_MSG__INIT;
			char remote_address[MAX_IP_STR];

			tmsg = ban_ip_msg__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, NULL, LOG_ERR, "error unpacking worker data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			human_addr2((struct sockaddr *)&proc->remote_addr, proc->remote_addr_len, remote_address, sizeof(remote_address), 0);

			ret = add_str_ip_to_ban_list(s, remote_address, tmsg->score);

			ban_ip_msg__free_unpacked(tmsg, &pa);

			if (ret < 0) {
				reply.reply =
				    AUTH__REP__FAILED;
			} else {
				reply.reply =
				    AUTH__REP__OK;
			}

			ret =
			    send_msg_to_worker(s, proc, CMD_BAN_IP_REPLY, &reply,
					       (pack_size_func)
					       ban_ip_reply_msg__get_packed_size,
					       (pack_func)
					       ban_ip_reply_msg__pack);

			if (ret < 0) {
				mslog(s, NULL, LOG_ERR,
				      "could not send reply cmd %d.",
				      (unsigned)cmd);
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}
		}
		break;
	case CMD_TUN_MTU:{
			TunMtuMsg *tmsg;
			unsigned minimum_mtu = RFC_791_MTU;
			unsigned maximum_mtu =
			    proc->vhost->perm_config.config->default_mtu != 0 ?
			    proc->vhost->perm_config.config->default_mtu :
			    MAX_DTLS_MTU;

			if (proc->status != PS_AUTH_COMPLETED) {
				mslog(s, proc, LOG_ERR,
				      "received TUN MTU in unauthenticated state.");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			tmsg = tun_mtu_msg__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			if (tmsg->mtu < minimum_mtu || tmsg->mtu > maximum_mtu) {
				mslog(s, proc, LOG_ERR,
				      "worker process invalid MTU %d", (int)tmsg->mtu);
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			set_tun_mtu(s, proc, tmsg->mtu);

			tun_mtu_msg__free_unpacked(tmsg, &pa);
		}

		break;
	case CMD_SESSION_INFO:{
			SessionInfoMsg *tmsg;

			tmsg = session_info_msg__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking session info data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			if (tmsg->tls_ciphersuite)
				strlcpy(proc->tls_ciphersuite, tmsg->tls_ciphersuite,
					 sizeof(proc->tls_ciphersuite));
			if (tmsg->dtls_ciphersuite)
				strlcpy(proc->dtls_ciphersuite, tmsg->dtls_ciphersuite,
					 sizeof(proc->dtls_ciphersuite));
			if (tmsg->cstp_compr)
				strlcpy(proc->cstp_compr, tmsg->cstp_compr,
					 sizeof(proc->cstp_compr));
			if (tmsg->dtls_compr)
				strlcpy(proc->dtls_compr, tmsg->dtls_compr,
					 sizeof(proc->dtls_compr));

			if (proc->hostname[0] != 0) {
				user_hostname_update(s, proc);
			}

			if (GETCONFIG(s)->listen_proxy_proto) {
				if (tmsg->has_remote_addr && tmsg->remote_addr.len <= sizeof(struct sockaddr_storage)) {
					proc_table_update_ip(s, proc, (struct sockaddr_storage*)tmsg->remote_addr.data, tmsg->remote_addr.len);

					/* If the address is in the BAN list, terminate it */
					if (check_if_banned(s, &proc->remote_addr, proc->remote_addr_len) != 0) {
						if (proc->pid != -1 && proc->pid != 0) {
							kill_proc(proc);
						}
					}
				}

				if (tmsg->has_our_addr && tmsg->our_addr.len <= sizeof(struct sockaddr_storage) &&
				    tmsg->our_addr.len > 0) {
					memcpy(&proc->our_addr, tmsg->our_addr.data, tmsg->our_addr.len);
					proc->our_addr_len = tmsg->our_addr.len;
				}

			}

			session_info_msg__free_unpacked(tmsg, &pa);
		}

		break;
	case AUTH_COOKIE_REQ:
		if (proc->status != PS_AUTH_INACTIVE) {
			mslog(s, proc, LOG_ERR,
			      "received unexpected cookie authentication.");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		auth_cookie_req =
		    auth_cookie_request_msg__unpack(&pa, raw_len, raw);
		if (auth_cookie_req == NULL) {
			mslog(s, proc, LOG_ERR, "error unpacking cookie data");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		proc->sec_mod_instance_index = auth_cookie_req->cookie.data[0] % s->sec_mod_instance_count;

		ret = handle_auth_cookie_req(&s->sec_mod_instances[proc->sec_mod_instance_index], proc, auth_cookie_req);

		safe_memset(raw, 0, raw_len);
		safe_memset(auth_cookie_req->cookie.data, 0, auth_cookie_req->cookie.len);

		auth_cookie_request_msg__free_unpacked(auth_cookie_req, &pa);

		ret = handle_cookie_auth_res(s, proc, cmd, ret);
		if (ret < 0) {
			goto cleanup;
		}

		break;

#if defined(CAPTURE_LATENCY_SUPPORT)
	case CMD_LATENCY_STATS_DELTA:{
			LatencyStatsDelta * tmsg;
 
			if (proc->status != PS_AUTH_COMPLETED) {
				mslog(s, proc, LOG_ERR,
					"received LATENCY STATS DELTA in unauthenticated state.");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			tmsg = latency_stats_delta__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking latency stats delta data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}
			
			s->stats.delta_latency_stats.median_total += tmsg->median_delta;
			s->stats.delta_latency_stats.rms_total += tmsg->rms_delta;
			s->stats.delta_latency_stats.sample_count += tmsg->sample_count_delta;

			latency_stats_delta__free_unpacked(tmsg, &pa);
		}
		break;
#endif
	default:
		mslog(s, proc, LOG_ERR, "unknown CMD from worker: 0x%x", (unsigned)cmd);
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	talloc_free(raw);

	return ret;
}

