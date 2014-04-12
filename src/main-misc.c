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
#include <ipc.pb-c.h>
#include <script-list.h>

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>
#include "pam.h"

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
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	ifr.ifr_mtu = mtu;

	ret = ioctl(fd, SIOCSIFMTU, &ifr);
	if (ret != 0) {
		e = errno;
		mslog(s, proc, LOG_INFO, "ioctl SIOCSIFMTU error: %s",
		      strerror(e));
		ret = -1;
		goto fail;
	}

	ret = 0;
 fail:
	close(fd);
	return ret;
}

int handle_script_exit(main_server_st * s, struct proc_st *proc, int code, unsigned need_sid)
{
	int ret;

	if (code == 0) {
		proc->status = PS_AUTH_COMPLETED;

		ret = send_auth_reply(s, proc, AUTH_REPLY_MSG__AUTH__REP__OK, need_sid);
		if (ret < 0) {
			mslog(s, proc, LOG_ERR,
			      "could not send auth reply cmd.");
			ret = ERR_BAD_COMMAND;
			goto fail;
		}

		apply_iroutes(s, proc);
	} else {
		mslog(s, proc, LOG_INFO,
		      "failed authentication attempt for user '%s'",
		      proc->username);
		ret =
		    send_auth_reply(s, proc, AUTH_REPLY_MSG__AUTH__REP__FAILED, need_sid);
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
	 * The parent doesn't need to keep the tunfd. Note that
	 * the reason we don't close the tun_fd when there is a
	 * disconnect script set, is so that it can gather statistics
	 * from it.
	 */
	if (proc->tun_lease.name[0] != 0 && s->config->disconnect_script == NULL) {
		if (proc->tun_lease.fd >= 0)
			close(proc->tun_lease.fd);
		proc->tun_lease.fd = -1;
	}

	return ret;
}

static int read_additional_config_file(main_server_st * s, struct proc_st *proc,
				       const char *file, const char *type)
{
	struct group_cfg_st cfg;
	int ret;
	unsigned i;

	if (access(file, R_OK) == 0) {
		mslog(s, proc, LOG_DEBUG, "Loading %s configuration '%s'", type,
		      file);

		ret = parse_group_cfg_file(s, file, &cfg);
		if (ret < 0)
			return ERR_READ_CONFIG;

		if (cfg.routes_size > 0) {
			if (proc->config.routes == NULL) {
				proc->config.routes = cfg.routes;
				proc->config.routes_size = cfg.routes_size;

				cfg.routes = NULL;
				cfg.routes_size = 0;
			} else {
				proc->config.routes =
				    safe_realloc(proc->config.routes,
						 (proc->config.routes_size +
						  cfg.routes_size) *
						 sizeof(proc->config.
							routes[0]));
				if (proc->config.routes == NULL)
					return ERR_MEM;

				for (i = 0; i < cfg.routes_size; i++) {
					proc->config.routes[proc->config.
							    routes_size] =
					    cfg.routes[i];
					cfg.routes[i] = NULL;
					proc->config.routes_size++;
				}
			}
		}

		if (proc->config.iroutes == NULL) {
			proc->config.iroutes = cfg.iroutes;
			proc->config.iroutes_size = cfg.iroutes_size;

			cfg.iroutes = NULL;
			cfg.iroutes_size = 0;
		}

		if (proc->config.dns == NULL) {
			proc->config.dns = cfg.dns;
			proc->config.dns_size = cfg.dns_size;

			cfg.dns = NULL;
			cfg.dns_size = 0;
		}

		if (proc->config.nbns == NULL) {
			proc->config.nbns = cfg.nbns;
			proc->config.nbns_size = cfg.nbns_size;

			cfg.nbns = NULL;
			cfg.nbns_size = 0;
		}

		if (proc->config.ipv4_network == NULL) {
			proc->config.ipv4_network = cfg.ipv4_network;
			cfg.ipv4_network = NULL;
		}

		if (proc->config.ipv6_network == NULL) {
			proc->config.ipv6_network = cfg.ipv6_network;
			cfg.ipv6_network = NULL;
		}

		if (proc->config.ipv4_netmask == NULL) {
			proc->config.ipv4_netmask = cfg.ipv4_netmask;
			cfg.ipv4_netmask = NULL;
		}

		if (proc->config.ipv6_netmask == NULL) {
			proc->config.ipv6_netmask = cfg.ipv6_netmask;
			cfg.ipv6_netmask = NULL;
		}

		if (proc->config.ipv6_prefix != 0) {
			proc->config.ipv6_prefix = cfg.ipv6_prefix;
		}

		if (proc->config.cgroup == NULL) {
			proc->config.cgroup = cfg.cgroup;
			cfg.cgroup = NULL;
		}

		if (proc->config.rx_per_sec == 0) {
			proc->config.rx_per_sec = cfg.rx_per_sec;
		}

		if (proc->config.tx_per_sec == 0) {
			proc->config.tx_per_sec = cfg.tx_per_sec;
		}

		if (proc->config.net_priority == 0) {
			proc->config.net_priority = cfg.net_priority;
		}

		del_additional_config(&cfg);

	} else
		mslog(s, proc, LOG_DEBUG, "No %s configuration for '%s'", type,
		      proc->username);

	return 0;
}

static int read_additional_config(struct main_server_st *s,
				  struct proc_st *proc)
{
	char file[_POSIX_PATH_MAX];
	int ret;

	memset(&proc->config, 0, sizeof(proc->config));

	if (s->config->per_user_dir != NULL) {
		snprintf(file, sizeof(file), "%s/%s", s->config->per_user_dir,
			 proc->username);

		ret = read_additional_config_file(s, proc, file, "user");
		if (ret < 0)
			return ret;
	}

	if (s->config->per_group_dir != NULL && proc->groupname[0] != 0) {
		snprintf(file, sizeof(file), "%s/%s", s->config->per_group_dir,
			 proc->groupname);

		ret = read_additional_config_file(s, proc, file, "group");
		if (ret < 0)
			return ret;
	}

	if (proc->config.cgroup != NULL) {
		put_into_cgroup(s, proc->config.cgroup, proc->pid);
	}

	return 0;
}

/* k: whether to kill the process
 */
void remove_proc(main_server_st * s, struct proc_st *proc, unsigned k)
{
	mslog(s, proc, LOG_DEBUG, "removing client '%s' with id '%d'", proc->username, (int)proc->pid);

	remove_from_script_list(s, proc);

	if (k && proc->pid != -1 && proc->pid != 0) {
		kill(proc->pid, SIGTERM);
	}

	/* close the intercomm fd */
	if (proc->fd >= 0)
		close(proc->fd);

	proc->fd = -1;
	proc->pid = -1;

	if (proc->status == PS_AUTH_COMPLETED) {
		user_disconnected(s, proc);

		if (s->config->disconnect_script) {
			/* give time to disconnect script to gather
			 * statistics from the device or so */
			proc->status = PS_AUTH_DEAD;
			return;
		}
	}

	list_del(&proc->list);
	s->active_clients--;

	remove_iroutes(s, proc);
	del_additional_config(&proc->config);

	if (proc->auth_ctx != NULL)
		proc_auth_deinit(s, proc);

	remove_ip_leases(s, proc);

	if (proc->tun_lease.fd >= 0)
		close(proc->tun_lease.fd);

	free(proc);
}

void proc_to_zombie(main_server_st * s, struct proc_st *proc)
{
	proc->status = PS_AUTH_ZOMBIE;

	mslog_hex(s, proc, LOG_INFO, "client disconnected, became zombie", proc->sid, sizeof(proc->sid), 1);

	/* close the intercomm fd */
	if (proc->fd >= 0)
		close(proc->fd);
	proc->fd = -1;
	proc->pid = -1;
}

/* This is the function after which proc is populated */
static int accept_user(main_server_st * s, struct proc_st *proc, unsigned cmd)
{
	int ret;
	const char *group;

	mslog(s, proc, LOG_DEBUG, "accepting user '%s'", proc->username);
	proc_auth_deinit(s, proc);

	/* check for multiple connections */
	ret = check_multiple_users(s, proc);
	if (ret < 0) {
		mslog(s, proc, LOG_INFO,
		      "user '%s' tried to connect more than %u times",
		      proc->username, s->config->max_same_clients);
		return ret;
	}

	ret = read_additional_config(s, proc);
	if (ret < 0) {
		mslog(s, proc, LOG_ERR,
		      "error reading additional configuration");
		return ERR_READ_CONFIG;
	}

	ret = open_tun(s, proc);
	if (ret < 0) {
		return -1;
	}

	if (proc->groupname[0] == 0)
		group = "[unknown]";
	else
		group = proc->groupname;

	if (cmd == AUTH_REQ || cmd == AUTH_INIT || cmd == AUTH_REINIT) {
		/* generate cookie */
		ret = generate_cookie(s, proc);
		if (ret < 0) {
			return ret;
		}
		mslog(s, proc, LOG_INFO,
		      "user '%s' of group '%s' authenticated", proc->username,
		      group);
	} else if (cmd == AUTH_COOKIE_REQ) {
		mslog(s, proc, LOG_INFO,
		      "user '%s' of group '%s' re-authenticated (using cookie)",
		      proc->username, group);
	} else {
		mslog(s, proc, LOG_INFO,
		      "user '%s' of group '%s' authenticated but from unknown state!",
		      proc->username, group);
		return ERR_BAD_COMMAND;
	}

	/* do scripts and utmp */
	ret = user_connected(s, proc);
	if (ret < 0 && ret != ERR_WAIT_FOR_SCRIPT) {
		mslog(s, proc, LOG_INFO, "user '%s' disconnected due to script",
		      proc->username);
	}

	return ret;
}

/* Performs the required steps based on the result from the 
 * authentication function (e.g. handle_auth_init).
 *
 * @cmd: the command received
 * @result: the auth result
 */
static int handle_auth_res(main_server_st * s, struct proc_st *proc,
			   unsigned cmd, int result)
{
	int ret;
	unsigned need_sid = 0;
	unsigned can_cont = 1;

	/* we use seeds only in AUTH_REINIT */
	if (cmd == AUTH_REINIT)
		need_sid = 1;

	/* no point to allow ERR_AUTH_CONTINUE in cookie auth */
	if (cmd == AUTH_COOKIE_REQ)
		can_cont = 0;

	if (can_cont != 0 && result == ERR_AUTH_CONTINUE) {
		ret = send_auth_reply_msg(s, proc, need_sid);
		if (ret < 0) {
			proc->status = PS_AUTH_FAILED;
			mslog(s, proc, LOG_ERR,
			      "could not send reply auth cmd.");
			return ret;
		}
		return 0;	/* wait for another command */
	} else if (result == 0) {
		ret = accept_user(s, proc, cmd);
		if (ret < 0) {
			proc->status = PS_AUTH_FAILED;
			goto finished;
		}
		proc->status = PS_AUTH_COMPLETED;
	} else if (result < 0) {
		proc->status = PS_AUTH_FAILED;
		add_to_ip_ban_list(s, &proc->remote_addr,
				   proc->remote_addr_len);
		ret = result;
	} else {
		proc->status = PS_AUTH_FAILED;
		mslog(s, proc, LOG_ERR, "unexpected auth result: %d\n", result);
		ret = ERR_BAD_COMMAND;
	}

 finished:
	if (ret == ERR_WAIT_FOR_SCRIPT)
		ret = 0;
	else {
		/* no script was called. Handle it as a successful script call. */
		ret = handle_script_exit(s, proc, ret, need_sid);
		if (ret < 0)
			proc->status = PS_AUTH_FAILED;
	}

	return ret;
}

int handle_commands(main_server_st * s, struct proc_st *proc)
{
	struct iovec iov[3];
	uint8_t cmd;
	struct msghdr hdr;
	AuthInitMsg *auth_init;
	AuthReinitMsg *auth_reinit;
	AuthCookieRequestMsg *auth_cookie_req;
	AuthRequestMsg *auth_req;
	uint16_t length;
	uint8_t *raw;
	int ret, raw_len, e;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = &length;
	iov[1].iov_len = 2;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	ret = recvmsg(proc->fd, &hdr, 0);
	if (ret == -1) {
		e = errno;
		mslog(s, proc, LOG_ERR,
		      "cannot obtain metadata from command socket: %s",
		      strerror(e));
		return ERR_BAD_COMMAND;
	}

	if (ret == 0) {
		mslog(s, proc, LOG_ERR, "command socket closed");
		return ERR_WORKER_TERMINATED;
	}

	if (ret < 3) {
		mslog(s, proc, LOG_ERR, "command error");
		return ERR_BAD_COMMAND;
	}

	mslog(s, proc, LOG_DEBUG, "main received message '%s' of %u bytes\n",
	      cmd_request_to_str(cmd), (unsigned)length);

	raw = malloc(length);
	if (raw == NULL) {
		mslog(s, proc, LOG_ERR, "memory error");
		return ERR_MEM;
	}

	raw_len = force_read_timeout(proc->fd, raw, length, 2);
	if (raw_len != length) {
		e = errno;
		mslog(s, proc, LOG_ERR,
		      "cannot obtain data from command socket: %s",
		      strerror(e));
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	switch (cmd) {
	case CMD_TUN_MTU:{
			TunMtuMsg *tmsg;

			if (proc->status != PS_AUTH_COMPLETED) {
				mslog(s, proc, LOG_ERR,
				      "received TUN MTU in unauthenticated state.");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			tmsg = tun_mtu_msg__unpack(NULL, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			set_tun_mtu(s, proc, tmsg->mtu);

			tun_mtu_msg__free_unpacked(tmsg, NULL);
		}

		break;
	case CMD_SESSION_INFO:{
			SessionInfoMsg *tmsg;

			tmsg = session_info_msg__unpack(NULL, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			if (tmsg->tls_ciphersuite)
				snprintf(proc->tls_ciphersuite,
					 sizeof(proc->tls_ciphersuite), "%s",
					 tmsg->tls_ciphersuite);
			if (tmsg->dtls_ciphersuite)
				snprintf(proc->dtls_ciphersuite,
					 sizeof(proc->dtls_ciphersuite), "%s",
					 tmsg->dtls_ciphersuite);
			if (tmsg->user_agent)
				snprintf(proc->user_agent,
					 sizeof(proc->user_agent), "%s",
					 tmsg->user_agent);

			session_info_msg__free_unpacked(tmsg, NULL);

		}

		break;
	case RESUME_STORE_REQ:{
			SessionResumeStoreReqMsg *smsg;

			smsg =
			    session_resume_store_req_msg__unpack(NULL, raw_len,
								 raw);
			if (smsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			ret = handle_resume_store_req(s, proc, smsg);

			session_resume_store_req_msg__free_unpacked(smsg, NULL);

			if (ret < 0) {
				mslog(s, proc, LOG_DEBUG,
				      "could not store resumption data");
			}
		}

		break;

	case RESUME_DELETE_REQ:{
			SessionResumeFetchMsg *fmsg;

			fmsg =
			    session_resume_fetch_msg__unpack(NULL, raw_len,
							     raw);
			if (fmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			ret = handle_resume_delete_req(s, proc, fmsg);

			session_resume_fetch_msg__free_unpacked(fmsg, NULL);

			if (ret < 0) {
				mslog(s, proc, LOG_DEBUG,
				      "could not delete resumption data.");
			}

		}

		break;
	case RESUME_FETCH_REQ:{
			SessionResumeReplyMsg msg =
			    SESSION_RESUME_REPLY_MSG__INIT;
			SessionResumeFetchMsg *fmsg;

			fmsg =
			    session_resume_fetch_msg__unpack(NULL, raw_len,
							     raw);
			if (fmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			ret = handle_resume_fetch_req(s, proc, fmsg, &msg);

			session_resume_fetch_msg__free_unpacked(fmsg, NULL);

			if (ret < 0) {
				msg.reply =
				    SESSION_RESUME_REPLY_MSG__RESUME__REP__FAILED;
				mslog(s, proc, LOG_DEBUG,
				      "could not fetch resumption data.");
			} else {
				msg.reply =
				    SESSION_RESUME_REPLY_MSG__RESUME__REP__OK;
			}

			ret =
			    send_msg_to_worker(s, proc, RESUME_FETCH_REP, &msg,
					       (pack_size_func)
					       session_resume_reply_msg__get_packed_size,
					       (pack_func)
					       session_resume_reply_msg__pack);

			if (ret < 0) {
				mslog(s, proc, LOG_ERR,
				      "could not send reply cmd %d.",
				      (unsigned)cmd);
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

		}

		break;

	case AUTH_INIT:
		if (proc->status != PS_AUTH_INACTIVE) {
			mslog(s, proc, LOG_ERR,
			      "received authentication init when complete.");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		auth_init = auth_init_msg__unpack(NULL, raw_len, raw);
		if (auth_init == NULL) {
			mslog(s, proc, LOG_ERR, "error unpacking data");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		ret = handle_auth_init(s, proc, auth_init);

		auth_init_msg__free_unpacked(auth_init, NULL);

		proc->status = PS_AUTH_INIT;

		ret = handle_auth_res(s, proc, cmd, ret);
		if (ret < 0) {
			goto cleanup;
		}

		break;

	case AUTH_REINIT:
		if (proc->status != PS_AUTH_INACTIVE
		    || s->config->cisco_client_compat == 0) {
			mslog(s, proc, LOG_ERR,
			      "received authentication reinit when complete.");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		auth_reinit = auth_reinit_msg__unpack(NULL, raw_len, raw);
		if (auth_reinit == NULL) {
			mslog(s, proc, LOG_ERR, "error unpacking data");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		/* note that it may replace proc on success */
		ret = handle_auth_reinit(s, &proc, auth_reinit);

		auth_reinit_msg__free_unpacked(auth_reinit, NULL);

		proc->status = PS_AUTH_INIT;

		ret = handle_auth_res(s, proc, cmd, ret);
		if (ret < 0) {
			goto cleanup;
		}

		/* handle_auth_reinit() has succeeded so the current proc
		 * is in dead state and unused. Terminate it.
		 */
		ret = ERR_WORKER_TERMINATED;
		goto cleanup;

	case AUTH_REQ:
		if (proc->status != PS_AUTH_INIT) {
			mslog(s, proc, LOG_ERR,
			      "received authentication request when not initialized.");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		proc->auth_reqs++;
		if (proc->auth_reqs > MAX_AUTH_REQS) {
			mslog(s, proc, LOG_ERR,
			      "received too many authentication requests.");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		auth_req = auth_request_msg__unpack(NULL, raw_len, raw);
		if (auth_req == NULL) {
			mslog(s, proc, LOG_ERR, "error unpacking data");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		ret = handle_auth_req(s, proc, auth_req);

		auth_request_msg__free_unpacked(auth_req, NULL);

		proc->status = PS_AUTH_INIT;

		ret = handle_auth_res(s, proc, cmd, ret);
		if (ret < 0) {
			goto cleanup;
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
		    auth_cookie_request_msg__unpack(NULL, raw_len, raw);
		if (auth_cookie_req == NULL) {
			mslog(s, proc, LOG_ERR, "error unpacking data");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		ret = handle_auth_cookie_req(s, proc, auth_cookie_req);

		auth_cookie_request_msg__free_unpacked(auth_cookie_req, NULL);

		ret = handle_auth_res(s, proc, cmd, ret);
		if (ret < 0) {
			goto cleanup;
		}

		break;

	default:
		mslog(s, proc, LOG_ERR, "unknown CMD 0x%x.", (unsigned)cmd);
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	free(raw);

	return ret;
}

int check_if_banned(main_server_st * s, struct sockaddr_storage *addr,
		    socklen_t addr_len)
{
	time_t now = time(0);
	struct banned_st *btmp = NULL, *bpos;

	if (s->config->min_reauth_time == 0)
		return 0;

	list_for_each_safe(&s->ban_list.head, btmp, bpos, list) {
		if (now - btmp->failed_time > s->config->min_reauth_time) {
			/* invalid entry. Clean it up */
			list_del(&btmp->list);
			free(btmp);
		} else {
			if (SA_IN_SIZE(btmp->addr_len) == SA_IN_SIZE(addr_len)
			    &&
			    memcmp(SA_IN_P_GENERIC(&btmp->addr, btmp->addr_len),
				   SA_IN_P_GENERIC(addr, addr_len),
				   SA_IN_SIZE(btmp->addr_len)) == 0) {
				return -1;
			}
		}
	}

	return 0;
}

void expire_banned(main_server_st * s)
{
	time_t now = time(0);
	struct banned_st *btmp = NULL, *bpos;

	if (s->config->min_reauth_time == 0)
		return;

	list_for_each_safe(&s->ban_list.head, btmp, bpos, list) {
		if (now - btmp->failed_time > s->config->min_reauth_time) {
			/* invalid entry. Clean it up */
			list_del(&btmp->list);
			free(btmp);
		}
	}

	return;
}

void add_to_ip_ban_list(main_server_st * s, struct sockaddr_storage *addr,
			socklen_t addr_len)
{
	struct banned_st *btmp;

	if (s->config->min_reauth_time == 0)
		return;

	btmp = malloc(sizeof(*btmp));
	if (btmp == NULL)
		return;

	btmp->failed_time = time(0);
	memcpy(&btmp->addr, addr, addr_len);
	btmp->addr_len = addr_len;

	list_add(&s->ban_list.head, &(btmp->list));
}

void expire_zombies(main_server_st * s)
{
	time_t now = time(0);
	struct proc_st *ctmp = NULL, *cpos;

	/* In CISCO compatibility mode we could have proc_st in
	 * mode INACTIVE or ZOMBIE that need to be cleaned up.
	 */
	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		if ((ctmp->status == PS_AUTH_ZOMBIE || ctmp->status == PS_AUTH_DEAD) &&
		    now - ctmp->conn_time > MAX_ZOMBIE_SECS) {
			remove_proc(s, ctmp, 0);
		}
	}

	return;
}

void run_sec_mod(main_server_st * s)
{
	int e;
	pid_t pid;
	char file[_POSIX_PATH_MAX];
	const char *p;

	/* make socket name */
	snprintf(s->socket_file, sizeof(s->socket_file), "%s.%u",
		 s->config->socket_file_prefix, (unsigned)getpid());
	p = s->socket_file;
	if (s->config->chroot_dir != NULL) {
		snprintf(file, sizeof(file), "%s/%s.%u",
			 s->config->chroot_dir, s->config->socket_file_prefix,
			 (unsigned)getpid());
		p = file;
	}

	pid = fork();
	if (pid == 0) {		/* child */
		clear_lists(s);
		kill_on_parent_kill(SIGTERM);
		setproctitle(PACKAGE_NAME "-secmod");

		sec_mod_server(s->config, p);
		exit(0);
	} else if (pid > 0) {	/* parent */
		s->sec_mod_pid = pid;
	} else {
		e = errno;
		mslog(s, NULL, LOG_ERR, "error in fork(): %s", strerror(e));
		exit(1);
	}
}

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
	snprintf(cgroup, sizeof(cgroup), "%s", _cgroup);

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
