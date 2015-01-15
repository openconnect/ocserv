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
#include <proc-search.h>
#include <ipc.pb-c.h>
#include <script-list.h>

#ifdef HAVE_MALLOC_TRIM
# include <malloc.h>
#endif

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
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
		mslog(s, proc, LOG_INFO, "ioctl SIOCSIFMTU error: %s",
		      strerror(e));
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
		proc->status = PS_AUTH_COMPLETED;

		ret = send_cookie_auth_reply(s, proc, AUTH__REP__OK);
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

struct proc_st *new_proc(main_server_st * s, pid_t pid, int cmd_fd,
			struct sockaddr_storage *remote_addr, socklen_t remote_addr_len,
			uint8_t *sid, size_t sid_size)
{
struct proc_st *ctmp;

	ctmp = talloc_zero(s, struct proc_st);
	if (ctmp == NULL)
		return NULL;

	ctmp->pid = pid;
	ctmp->tun_lease.fd = -1;
	ctmp->fd = cmd_fd;
	set_cloexec_flag (cmd_fd, 1);
	ctmp->conn_time = time(0);

	memcpy(&ctmp->remote_addr, remote_addr, remote_addr_len);
	ctmp->remote_addr_len = remote_addr_len;

	list_add(&s->proc_list.head, &(ctmp->list));
	put_into_cgroup(s, s->config->cgroup, pid);
	s->active_clients++;

	return ctmp;
}

static
int session_cmd(main_server_st * s, struct proc_st *proc, unsigned open)
{
	int sd, ret, e;
	SecAuthSessionMsg ireq = SEC_AUTH_SESSION_MSG__INIT;
	SecAuthSessionReplyMsg *msg = NULL;
	unsigned type, i;
	PROTOBUF_ALLOCATOR(pa, proc);

	if (open)
		type = SM_CMD_AUTH_SESSION_OPEN;
	else
		type = SM_CMD_AUTH_SESSION_CLOSE;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		mslog(s, proc, LOG_ERR, "error opening unix socket (for sec-mod) %s",
		      strerror(e));
		return -1;
	}

	ret =
	    connect(sd, (struct sockaddr *)&s->secmod_addr,
		    s->secmod_addr_len);
	if (ret < 0) {
		e = errno;
		close(sd);
		mslog(s, proc, LOG_ERR,
		      "error connecting to sec-mod socket '%s': %s",
		      s->secmod_addr.sun_path, strerror(e));
		return -1;
	}

	ireq.uptime = time(0)-proc->conn_time;
	ireq.has_uptime = 1;
	ireq.bytes_in = proc->bytes_in;
	ireq.has_bytes_in = 1;
	ireq.bytes_out = proc->bytes_out;
	ireq.has_bytes_out = 1;
	ireq.sid.data = proc->sid;
	ireq.sid.len = sizeof(proc->sid);

	mslog(s, proc, LOG_DEBUG, "sending msg %s to sec-mod", cmd_request_to_str(type));

	ret = send_msg(proc, sd, type,
		&ireq, (pack_size_func)sec_auth_session_msg__get_packed_size,
		(pack_func)sec_auth_session_msg__pack);
	if (ret < 0) {
		close(sd);
		mslog(s, proc, LOG_ERR,
		      "error sending message to sec-mod socket '%s'",
		      s->secmod_addr.sun_path);
		return -1;
	}

	if (open) {
		ret = recv_msg(proc, sd, SM_CMD_AUTH_SESSION_REPLY,
		       (void *)&msg, (unpack_func) sec_auth_session_reply_msg__unpack);
		close(sd);
		if (ret < 0) {
			mslog(s, proc, LOG_ERR, "error receiving auth reply message");
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

		if (msg->has_require_cert)
			proc->config.require_cert = msg->require_cert;

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
	} else {
		close(sd);
	}

	return 0;
}

int session_open(main_server_st * s, struct proc_st *proc)
{
	return session_cmd(s, proc, 1);
}

int session_close(main_server_st * s, struct proc_st *proc)
{
	return session_cmd(s, proc, 0);
}

/* k: whether to kill the process
 */
void remove_proc(main_server_st * s, struct proc_st *proc, unsigned k)
{
	mslog(s, proc, LOG_DEBUG, "removing client '%s' with id '%d'", proc->username, (int)proc->pid);

	list_del(&proc->list);
	s->active_clients--;

	if (k && proc->pid != -1 && proc->pid != 0)
		kill(proc->pid, SIGTERM);

	remove_from_script_list(s, proc);
	if (proc->status == PS_AUTH_COMPLETED) {
		user_disconnected(s, proc);
	}

	/* close any pending sessions */
	if (proc->active_sid) {
		session_close(s, proc);
	}

	/* close the intercomm fd */
	if (proc->fd >= 0)
		close(proc->fd);
	proc->fd = -1;
	proc->pid = -1;

	remove_iroutes(s, proc);

	if (proc->ipv4 || proc->ipv6)
		remove_ip_leases(s, proc);

	/* expire any available cookies */
	if (proc->cookie_ptr) {
		proc->cookie_ptr->proc = NULL;
		/* if we use session control and we closed the session we 
		 * need to invalidate the cookie, so that a new session is 
		 * used on the next connection */
		proc->cookie_ptr->expiration = 1;
	}

	close_tun(s, proc);
	proc_table_del(s, proc);

	talloc_free(proc);
}

/* This is the function after which proc is populated */
static int accept_user(main_server_st * s, struct proc_st *proc, unsigned cmd)
{
	int ret;
	const char *group;

	mslog(s, proc, LOG_DEBUG, "accepting user");

	/* check for multiple connections */
	ret = check_multiple_users(s, proc);
	if (ret < 0) {
		mslog(s, proc, LOG_INFO,
		      "user '%s' tried to connect more than %u times",
		      proc->username, s->config->max_same_clients);
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
		mslog(s, proc, LOG_INFO,
		      "user '%s' of group '%s' authenticated (using cookie)",
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

int handle_commands(main_server_st * s, struct proc_st *proc)
{
	struct iovec iov[3];
	uint8_t cmd;
	struct msghdr hdr;
	AuthCookieRequestMsg *auth_cookie_req;
	uint16_t length;
	uint8_t *raw;
	int ret, raw_len, e;
	PROTOBUF_ALLOCATOR(pa, proc);

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

	raw = talloc_size(proc, length);
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

			tmsg = tun_mtu_msg__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			set_tun_mtu(s, proc, tmsg->mtu);

			tun_mtu_msg__free_unpacked(tmsg, &pa);
		}

		break;
	case CMD_CLI_STATS:{
			CliStatsMsg *tmsg;

			if (proc->status != PS_AUTH_COMPLETED) {
				mslog(s, proc, LOG_ERR,
				      "received CLI STATS in unauthenticated state.");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			tmsg = cli_stats_msg__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			proc->bytes_in = tmsg->bytes_in;
			proc->bytes_out = tmsg->bytes_out;

			cli_stats_msg__free_unpacked(tmsg, &pa);
		}

		break;
	case CMD_SESSION_INFO:{
			SessionInfoMsg *tmsg;

			tmsg = session_info_msg__unpack(&pa, raw_len, raw);
			if (tmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
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
			if (tmsg->user_agent)
				strlcpy(proc->user_agent, tmsg->user_agent,
					 sizeof(proc->user_agent));

			session_info_msg__free_unpacked(tmsg, &pa);
		}

		break;
	case RESUME_STORE_REQ:{
			SessionResumeStoreReqMsg *smsg;

			smsg =
			    session_resume_store_req_msg__unpack(&pa, raw_len,
								 raw);
			if (smsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			ret = handle_resume_store_req(s, proc, smsg);

			/* zeroize the data */
			safe_memset(raw, 0, raw_len);
			safe_memset(smsg->session_data.data, 0, smsg->session_data.len);

			session_resume_store_req_msg__free_unpacked(smsg, &pa);

			if (ret < 0) {
				mslog(s, proc, LOG_DEBUG,
				      "could not store resumption data");
			}
		}

		break;

	case RESUME_DELETE_REQ:{
			SessionResumeFetchMsg *fmsg;

			fmsg =
			    session_resume_fetch_msg__unpack(&pa, raw_len,
							     raw);
			if (fmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			ret = handle_resume_delete_req(s, proc, fmsg);

			session_resume_fetch_msg__free_unpacked(fmsg, &pa);

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

			if (proc->resume_reqs > 0) {
				mslog(s, proc, LOG_ERR, "too many resumption requests");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}
			proc->resume_reqs++;

			fmsg =
			    session_resume_fetch_msg__unpack(&pa, raw_len,
							     raw);
			if (fmsg == NULL) {
				mslog(s, proc, LOG_ERR, "error unpacking data");
				ret = ERR_BAD_COMMAND;
				goto cleanup;
			}

			ret = handle_resume_fetch_req(s, proc, fmsg, &msg);

			session_resume_fetch_msg__free_unpacked(fmsg, &pa);

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
			mslog(s, proc, LOG_ERR, "error unpacking data");
			ret = ERR_BAD_COMMAND;
			goto cleanup;
		}

		ret = handle_auth_cookie_req(s, proc, auth_cookie_req);

		safe_memset(raw, 0, raw_len);
		safe_memset(auth_cookie_req->cookie.data, 0, auth_cookie_req->cookie.len);

		auth_cookie_request_msg__free_unpacked(auth_cookie_req, &pa);

		ret = handle_cookie_auth_res(s, proc, cmd, ret);
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
	talloc_free(raw);

	return ret;
}

void run_sec_mod(main_server_st * s)
{
	int e;
	pid_t pid;
	const char *p;

	/* make socket name */
	snprintf(s->socket_file, sizeof(s->socket_file), "%s.%u",
		 s->config->socket_file_prefix, (unsigned)getpid());

	if (s->config->chroot_dir != NULL) {
		snprintf(s->full_socket_file, sizeof(s->full_socket_file), "%s/%s",
			 s->config->chroot_dir, s->socket_file);
	} else {
		strlcpy(s->full_socket_file, s->socket_file, sizeof(s->full_socket_file));
	}
	p = s->full_socket_file;

	pid = fork();
	if (pid == 0) {		/* child */
		clear_lists(s);
		kill_on_parent_kill(SIGTERM);

#ifdef HAVE_MALLOC_TRIM
		/* try to return all the pages we've freed to
		 * the operating system. */
		malloc_trim(0);
#endif
		setproctitle(PACKAGE_NAME "-secmod");

		sec_mod_server(s->main_pool, s->config, p, s->cookie_key);
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
