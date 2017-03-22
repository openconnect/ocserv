/*
 * Copyright (C) 2014-2016 Red Hat
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/un.h>
#include <main.h>
#include <vpn.h>
#include <cloexec.h>
#include <ip-lease.h>

#include <errno.h>
#include <system.h>
#include <main-ctl.h>
#include <main-ban.h>
#include <ccan/container_of/container_of.h>

#include <ctl.pb-c.h>
#include <str.h>

typedef struct method_ctx {
	main_server_st *s;
	void *pool;
} method_ctx;

static void method_top(method_ctx *ctx, int cfd, uint8_t * msg,
			      unsigned msg_size);
static void method_status(method_ctx *ctx, int cfd, uint8_t * msg,
			  unsigned msg_size);
static void method_list_users(method_ctx *ctx, int cfd, uint8_t * msg,
			      unsigned msg_size);
static void method_disconnect_user_name(method_ctx *ctx, int cfd,
					uint8_t * msg, unsigned msg_size);
static void method_disconnect_user_id(method_ctx *ctx, int cfd,
				      uint8_t * msg, unsigned msg_size);
static void method_unban_ip(method_ctx *ctx, int cfd,
				      uint8_t * msg, unsigned msg_size);
static void method_stop(method_ctx *ctx, int cfd, uint8_t * msg,
			unsigned msg_size);
static void method_reload(method_ctx *ctx, int cfd, uint8_t * msg,
			  unsigned msg_size);
static void method_user_info(method_ctx *ctx, int cfd, uint8_t * msg,
			     unsigned msg_size);
static void method_id_info(method_ctx *ctx, int cfd, uint8_t * msg,
			   unsigned msg_size);
static void method_list_banned(method_ctx *ctx, int cfd, uint8_t * msg,
			   unsigned msg_size);
static void method_list_cookies(method_ctx *ctx, int cfd, uint8_t * msg,
			   unsigned msg_size);

typedef void (*method_func) (method_ctx *ctx, int cfd, uint8_t * msg,
			     unsigned msg_size);

typedef struct {
	char *name;
	unsigned cmd;
	method_func func;
	unsigned indefinite; /* session remains open */
} ctl_method_st;

#define ENTRY(cmd, func) \
	{#cmd, cmd, func, 0}

#define ENTRY_INDEF(cmd, func) \
	{#cmd, cmd, func, 1}

static const ctl_method_st methods[] = {
	ENTRY_INDEF(CTL_CMD_TOP, method_top),
	ENTRY(CTL_CMD_STATUS, method_status),
	ENTRY(CTL_CMD_RELOAD, method_reload),
	ENTRY(CTL_CMD_STOP, method_stop),
	ENTRY(CTL_CMD_LIST, method_list_users),
	ENTRY(CTL_CMD_LIST_BANNED, method_list_banned),
	ENTRY(CTL_CMD_LIST_COOKIES, method_list_cookies),
	ENTRY(CTL_CMD_USER_INFO, method_user_info),
	ENTRY(CTL_CMD_ID_INFO, method_id_info),
	ENTRY(CTL_CMD_UNBAN_IP, method_unban_ip),
	ENTRY(CTL_CMD_DISCONNECT_NAME, method_disconnect_user_name),
	ENTRY(CTL_CMD_DISCONNECT_ID, method_disconnect_user_id),
	{NULL, 0, NULL}
};

void ctl_handler_deinit(main_server_st * s)
{
	if (s->config->use_occtl == 0)
		return;

	if (s->ctl_fd >= 0) {
		/*mslog(s, NULL, LOG_DEBUG, "closing unix socket connection");*/
		close(s->ctl_fd);
		/*remove(OCSERV_UNIX_NAME); */
	}
}

/* Initializes unix socket and stores the fd.
 */
int ctl_handler_init(main_server_st * s)
{
	int ret;
	struct sockaddr_un sa;
	int sd, e;

	if (s->config->use_occtl == 0 || s->perm_config->occtl_socket_file == NULL) {
		mslog(s, NULL, LOG_INFO, "not using control unix socket");
		return 0;
	}

	mslog(s, NULL, LOG_DEBUG, "initializing control unix socket: %s", s->perm_config->occtl_socket_file);
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, s->perm_config->occtl_socket_file, sizeof(sa.sun_path));
	remove(s->perm_config->occtl_socket_file);

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "could not create socket '%s': %s",
		      s->perm_config->occtl_socket_file, strerror(e));
		return -1;
	}

	umask(066);
	ret = bind(sd, (struct sockaddr *)&sa, SUN_LEN(&sa));
	if (ret == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "could not bind socket '%s': %s",
		      s->perm_config->occtl_socket_file, strerror(e));
		return -1;
	}

	ret = chown(s->perm_config->occtl_socket_file, s->perm_config->uid, s->perm_config->gid);
	if (ret == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "could not chown socket '%s': %s",
		      s->perm_config->occtl_socket_file, strerror(e));
	}

	ret = listen(sd, 1024);
	if (ret == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "could not listen to socket '%s': %s",
		      s->perm_config->occtl_socket_file, strerror(e));
		return -1;
	}

	s->ctl_fd = sd;
	return sd;
}

static void method_status(method_ctx *ctx, int cfd, uint8_t * msg,
			  unsigned msg_size)
{
	StatusRep rep = STATUS_REP__INIT;
	int ret;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: status");

	rep.status = 1;
	rep.pid = getpid();
	rep.start_time = ctx->s->stats.start_time;
	rep.sec_mod_pid = ctx->s->sec_mod_pid;
	rep.active_clients = ctx->s->stats.active_clients;
	rep.secmod_client_entries = ctx->s->stats.secmod_client_entries;
	rep.stored_tls_sessions = ctx->s->stats.tlsdb_entries;
	rep.banned_ips = main_ban_db_elems(ctx->s);

	rep.session_timeouts = ctx->s->stats.session_timeouts;
	rep.session_idle_timeouts = ctx->s->stats.session_idle_timeouts;
	rep.session_errors = ctx->s->stats.session_errors;
	rep.sessions_closed = ctx->s->stats.sessions_closed;
	rep.kbytes_in = ctx->s->stats.kbytes_in;
	rep.kbytes_out = ctx->s->stats.kbytes_out;
	rep.min_mtu = ctx->s->stats.min_mtu;
	rep.max_mtu = ctx->s->stats.max_mtu;
	rep.last_reset = ctx->s->stats.last_reset;
	rep.avg_auth_time = ctx->s->stats.avg_auth_time;
	rep.avg_session_mins = ctx->s->stats.avg_session_mins;
	rep.max_auth_time = ctx->s->stats.max_auth_time;
	rep.max_session_mins = ctx->s->stats.max_session_mins;

	rep.auth_failures = ctx->s->stats.auth_failures;
	rep.total_auth_failures = ctx->s->stats.total_auth_failures;
	rep.total_sessions_closed = ctx->s->stats.total_sessions_closed;

	ret = send_msg(ctx->pool, cfd, CTL_CMD_STATUS_REP, &rep,
		       (pack_size_func) status_rep__get_packed_size,
		       (pack_func) status_rep__pack);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending ctl reply");
	}

	return;
}

static void method_reload(method_ctx *ctx, int cfd, uint8_t * msg,
			  unsigned msg_size)
{
	BoolMsg rep = BOOL_MSG__INIT;
	int ret;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: reload");

	ev_feed_signal_event (loop, SIGHUP);

	rep.status = 1;

	ret = send_msg(ctx->pool, cfd, CTL_CMD_RELOAD_REP, &rep,
		       (pack_size_func) bool_msg__get_packed_size,
		       (pack_func) bool_msg__pack);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending ctl reply");
	}

	return;
}

static void method_stop(method_ctx *ctx, int cfd, uint8_t * msg,
			unsigned msg_size)
{
	BoolMsg rep = BOOL_MSG__INIT;
	int ret;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: stop");

	ev_feed_signal_event (loop, SIGTERM);

	rep.status = 1;

	ret = send_msg(ctx->pool, cfd, CTL_CMD_STOP_REP, &rep,
		       (pack_size_func) bool_msg__get_packed_size,
		       (pack_func) bool_msg__pack);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending ctl reply");
	}

	return;
}

#define IPBUF_SIZE 64
static int append_user_info(method_ctx *ctx,
			    UserListRep * list,
			    struct proc_st *ctmp)
{
	uint32_t tmp;
	char *ipbuf;
	char *strtmp;
	UserInfoRep *rep;
	char *safe_id;

	list->user =
	    talloc_realloc(ctx->pool, list->user, UserInfoRep *, (1 + list->n_user));
	if (list->user == NULL)
		return -1;

	rep = talloc(ctx->pool, UserInfoRep);
	if (rep == NULL)
		return -1;

	safe_id = talloc_size(ctx->pool, SAFE_ID_SIZE);
	if (safe_id == NULL)
		return -1;

	list->user[list->n_user] = rep;
	list->n_user++;

	user_info_rep__init(rep);

	/* ID: pid */
	rep->id = ctmp->pid;
	rep->username = ctmp->username;
	rep->groupname = ctmp->groupname;

	ipbuf = talloc_size(ctx->pool, IPBUF_SIZE);
	if (ipbuf == NULL)
		return -1;

	strtmp =
	    human_addr2((struct sockaddr *)&ctmp->remote_addr,
			ctmp->remote_addr_len, ipbuf, IPBUF_SIZE, 0);
	if (strtmp == NULL)
		strtmp = "";
	rep->ip = strtmp;

	ipbuf = talloc_size(ctx->pool, IPBUF_SIZE);
	if (ipbuf == NULL)
		return -1;

	strtmp =
	    human_addr2((struct sockaddr *)&ctmp->our_addr,
			ctmp->our_addr_len, ipbuf, IPBUF_SIZE, 0);
	if (strtmp == NULL)
		strtmp = "";
	rep->local_dev_ip = strtmp;

	rep->tun = ctmp->tun_lease.name;

	ipbuf = talloc_size(ctx->pool, IPBUF_SIZE);
	if (ipbuf == NULL)
		return -1;

	strtmp = NULL;
	if (ctmp->ipv4 != NULL)
		strtmp =
		    human_addr2((struct sockaddr *)&ctmp->ipv4->rip,
				ctmp->ipv4->rip_len, ipbuf, IPBUF_SIZE, 0);
	if (strtmp == NULL)
		strtmp = "";
	rep->local_ip = strtmp;

	ipbuf = talloc_size(ctx->pool, IPBUF_SIZE);
	if (ipbuf == NULL)
		return -1;

	strtmp = NULL;
	if (ctmp->ipv4 != NULL)
		strtmp =
		    human_addr2((struct sockaddr *)&ctmp->ipv4->lip,
				ctmp->ipv4->lip_len, ipbuf, IPBUF_SIZE, 0);
	if (strtmp == NULL)
		strtmp = "";
	rep->remote_ip = strtmp;

	/* IPv6 */

	ipbuf = talloc_size(ctx->pool, IPBUF_SIZE);
	if (ipbuf == NULL)
		return -1;

	strtmp = NULL;
	if (ctmp->ipv6 != NULL)
		strtmp =
		    human_addr2((struct sockaddr *)&ctmp->ipv6->rip,
				ctmp->ipv6->rip_len, ipbuf, IPBUF_SIZE, 0);
	if (strtmp == NULL)
		strtmp = "";
	rep->local_ip6 = strtmp;

	ipbuf = talloc_size(ctx->pool, IPBUF_SIZE);
	if (ipbuf == NULL)
		return -1;

	strtmp = NULL;
	if (ctmp->ipv6 != NULL)
		strtmp =
		    human_addr2((struct sockaddr *)&ctmp->ipv6->lip,
				ctmp->ipv6->lip_len, ipbuf, IPBUF_SIZE, 0);
	if (strtmp == NULL)
		strtmp = "";
	rep->remote_ip6 = strtmp;

	rep->conn_time = ctmp->conn_time;
	rep->hostname = ctmp->hostname;
	rep->user_agent = ctmp->user_agent;

	rep->status = ctmp->status;

	rep->tls_ciphersuite = ctmp->tls_ciphersuite;
	rep->dtls_ciphersuite = ctmp->dtls_ciphersuite;

	calc_safe_id(ctmp->sid, sizeof(ctmp->sid), safe_id, SAFE_ID_SIZE);
	rep->safe_id.data = (unsigned char*)safe_id;
	rep->safe_id.len = SAFE_ID_SIZE;

	rep->cstp_compr = ctmp->cstp_compr;
	rep->dtls_compr = ctmp->dtls_compr;
	if (ctmp->mtu > 0) {
		rep->mtu = ctmp->mtu;
		rep->has_mtu = 1;
	}

	if (ctmp->config) {
		rep->restrict_to_routes = ctmp->config->restrict_user_to_routes;

		tmp = ctmp->config->rx_per_sec;
		tmp *= 1000;
		rep->rx_per_sec = tmp;

		tmp = ctmp->config->tx_per_sec;
		tmp *= 1000;
		rep->tx_per_sec = tmp;

		rep->dpd = ctmp->config->dpd;

		rep->keepalive = ctmp->config->keepalive;
		rep->domains = ctx->s->config->split_dns;
		rep->n_domains = ctx->s->config->split_dns_size;

		rep->dns = ctmp->config->dns;
		rep->n_dns = ctmp->config->n_dns;

		rep->nbns = ctmp->config->nbns;
		rep->n_nbns = ctmp->config->n_nbns;

		rep->n_routes = ctmp->config->n_routes;
		rep->routes = ctmp->config->routes;

		rep->n_no_routes = ctmp->config->n_no_routes;
		rep->no_routes = ctmp->config->no_routes;

		rep->iroutes = ctmp->config->iroutes;
		rep->n_iroutes = ctmp->config->n_iroutes;

		rep->n_fw_ports = ctmp->config->n_fw_ports;
		rep->fw_ports = ctmp->config->fw_ports;
	}

	return 0;
}

static void method_list_users(method_ctx *ctx, int cfd, uint8_t * msg,
			      unsigned msg_size)
{
	UserListRep rep = USER_LIST_REP__INIT;
	struct proc_st *ctmp = NULL;
	int ret;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: list-users");

	list_for_each(&ctx->s->proc_list.head, ctmp, list) {
		ret = append_user_info(ctx, &rep, ctmp);
		if (ret < 0) {
			mslog(ctx->s, NULL, LOG_ERR,
			      "error appending user info to reply");
			goto error;
		}
	}

	ret = send_msg(ctx->pool, cfd, CTL_CMD_LIST_REP, &rep,
		       (pack_size_func) user_list_rep__get_packed_size,
		       (pack_func) user_list_rep__pack);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending ctl reply");
	}

 error:
	return;
}

static void method_top(method_ctx *ctx, int cfd, uint8_t * msg,
			      unsigned msg_size)
{
	/* we send the initial user list, and the we send a TOP reply message
	 * once a user connects/disconnects. */

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: top");

	/* we can only have a single top listener */
	if (ctx->s->top_fd == -1)
		ctx->s->top_fd = cfd;

	method_list_users(ctx, cfd, msg, msg_size);
}

static int append_ban_info(method_ctx *ctx,
			    BanListRep *list,
			    struct ban_entry_st *e)
{
	BanInfoRep *rep;

	list->info =
	    talloc_realloc(ctx->pool, list->info, BanInfoRep *, (1 + list->n_info));
	if (list->info == NULL)
		return -1;

	rep = list->info[list->n_info] = talloc(ctx->pool, BanInfoRep);
	if (rep == NULL)
		return -1;
	list->n_info++;

	ban_info_rep__init(rep);

	rep->ip.data = e->ip.ip;
	rep->ip.len = e->ip.size;
	rep->score = e->score;

	if (ctx->s->config->max_ban_score > 0 && e->score >= ctx->s->config->max_ban_score) {
		rep->expires = e->expires;
		rep->has_expires = 1;
	}

	return 0;
}

static void method_list_banned(method_ctx *ctx, int cfd, uint8_t * msg,
			      unsigned msg_size)
{
	BanListRep rep = BAN_LIST_REP__INIT;
	struct ban_entry_st *e = NULL;
	struct htable *db = ctx->s->ban_db;
	int ret;
	struct htable_iter iter;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: list-banned-ips");

	e = htable_first(db, &iter);
	while (e != NULL) {
		ret = append_ban_info(ctx, &rep, e);
		if (ret < 0) {
			mslog(ctx->s, NULL, LOG_ERR,
			      "error appending ban info to reply");
			goto error;
		}
		e = htable_next(db, &iter);
	}

	ret = send_msg(ctx->pool, cfd, CTL_CMD_LIST_BANNED_REP, &rep,
		       (pack_size_func) ban_list_rep__get_packed_size,
		       (pack_func) ban_list_rep__pack);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending ban list reply");
	}

 error:
	return;
}

static void method_list_cookies(method_ctx *ctx, int cfd, uint8_t * msg,
			      unsigned msg_size)
{
	int ret;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: list-cookies");

	ret = send_msg(ctx->pool, ctx->s->sec_mod_fd_sync, CMD_SECM_LIST_COOKIES,
			 NULL, NULL, NULL);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending list cookies to sec-mod!");
	}

	ret = forward_msg(ctx->pool, ctx->s->sec_mod_fd_sync, CMD_SECM_LIST_COOKIES_REPLY,
			  cfd, CTL_CMD_LIST_COOKIES_REP, MAIN_SEC_MOD_TIMEOUT);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending list cookies reply");
	}

}

static void single_info_common(method_ctx *ctx, int cfd, uint8_t * msg,
			       unsigned msg_size, const char *user, unsigned id)
{
	UserListRep rep = USER_LIST_REP__INIT;
	int ret;
	unsigned found_user = 0;
	struct proc_st *ctmp = NULL;

	if (user != NULL)
		mslog(ctx->s, NULL, LOG_INFO, "providing info for user '%s'", user);
	else
		mslog(ctx->s, NULL, LOG_INFO, "providing info for ID '%u'", id);

	list_for_each(&ctx->s->proc_list.head, ctmp, list) {
		if (user == NULL) {	/* id */
			if (id == 0 || id == -1 || id != ctmp->pid) {
				continue;
			}
		} else {	/* username */
			if (strcmp(ctmp->username, user) != 0) {
				continue;
			}
		}

		ret = append_user_info(ctx, &rep, ctmp);
		if (ret < 0) {
			mslog(ctx->s, NULL, LOG_ERR,
			      "error appending user info to reply");
			goto error;
		}

		found_user = 1;

		if (id != 0)	/* id -> one a single element */
			break;
	}

	if (found_user == 0) {
		if (user != NULL)
			mslog(ctx->s, NULL, LOG_INFO, "could not find user '%s'",
			      user);
		else
			mslog(ctx->s, NULL, LOG_INFO, "could not find ID '%u'", id);
	}

	ret = send_msg(ctx->pool, cfd, CTL_CMD_LIST_REP, &rep,
		       (pack_size_func) user_list_rep__get_packed_size,
		       (pack_func) user_list_rep__pack);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending ctl reply");
	}

 error:
	return;
}

static void method_user_info(method_ctx *ctx, int cfd, uint8_t * msg,
			     unsigned msg_size)
{
	UsernameReq *req;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: user_info (name)");

	req = username_req__unpack(NULL, msg_size, msg);
	if (req == NULL) {
		mslog(ctx->s, NULL, LOG_ERR, "error parsing user_info request");
		return;
	}

	single_info_common(ctx, cfd, msg, msg_size, req->username, 0);
	username_req__free_unpacked(req, NULL);

	return;
}

static void method_id_info(method_ctx *ctx, int cfd, uint8_t * msg,
			   unsigned msg_size)
{
	IdReq *req;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: user_info (id)");

	req = id_req__unpack(NULL, msg_size, msg);
	if (req == NULL) {
		mslog(ctx->s, NULL, LOG_ERR, "error parsing id_info request");
		return;
	}

	single_info_common(ctx, cfd, msg, msg_size, NULL, req->id);
	id_req__free_unpacked(req, NULL);

	return;
}

static void method_unban_ip(method_ctx *ctx,
			    int cfd, uint8_t * msg,
			    unsigned msg_size)
{
	UnbanReq *req;
	BoolMsg rep = BOOL_MSG__INIT;
	int ret;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: unban IP");

	req = unban_req__unpack(NULL, msg_size, msg);
	if (req == NULL) {
		mslog(ctx->s, NULL, LOG_ERR,
		      "error parsing unban IP request");
		return;
	}

	if (remove_ip_from_ban_list(ctx->s, req->ip.data, req->ip.len) != 0) {
		rep.status = 1;
	}

	unban_req__free_unpacked(req, NULL);

	ret = send_msg(ctx->pool, cfd, CTL_CMD_UNBAN_IP_REP, &rep,
		       (pack_size_func) bool_msg__get_packed_size,
		       (pack_func) bool_msg__pack);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending unban IP ctl reply");
	}

	return;
}

static void method_disconnect_user_name(method_ctx *ctx,
					int cfd, uint8_t * msg,
					unsigned msg_size)
{
	UsernameReq *req;
	BoolMsg rep = BOOL_MSG__INIT;
	struct proc_st *cpos;
	struct proc_st *ctmp = NULL;
	int ret;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: disconnect_name");

	req = username_req__unpack(NULL, msg_size, msg);
	if (req == NULL) {
		mslog(ctx->s, NULL, LOG_ERR,
		      "error parsing disconnect_name request");
		return;
	}

	/* got the name. Try to disconnect */
	list_for_each_safe(&ctx->s->proc_list.head, ctmp, cpos, list) {
		if (strcmp(ctmp->username, req->username) == 0) {
			terminate_proc(ctx->s, ctmp);
			rep.status = 1;
		}
	}

	username_req__free_unpacked(req, NULL);

	ret = send_msg(ctx->pool, cfd, CTL_CMD_DISCONNECT_NAME_REP, &rep,
		       (pack_size_func) bool_msg__get_packed_size,
		       (pack_func) bool_msg__pack);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending ctl reply");
	}

	return;
}

static void method_disconnect_user_id(method_ctx *ctx, int cfd,
				      uint8_t * msg, unsigned msg_size)
{
	IdReq *req;
	BoolMsg rep = BOOL_MSG__INIT;
	struct proc_st *cpos;
	struct proc_st *ctmp = NULL;
	int ret;

	mslog(ctx->s, NULL, LOG_DEBUG, "ctl: disconnect_id");

	req = id_req__unpack(NULL, msg_size, msg);
	if (req == NULL) {
		mslog(ctx->s, NULL, LOG_ERR, "error parsing disconnect_id request");
		return;
	}

	/* got the ID. Try to disconnect */
	list_for_each_safe(&ctx->s->proc_list.head, ctmp, cpos, list) {
		if (ctmp->pid == req->id) {
			terminate_proc(ctx->s, ctmp);
			rep.status = 1;
			if (req->id != -1)
				break;
		}
	}

	/* reply */
	id_req__free_unpacked(req, NULL);

	ret = send_msg(ctx->pool, cfd, CTL_CMD_DISCONNECT_ID_REP, &rep,
		       (pack_size_func) bool_msg__get_packed_size,
		       (pack_func) bool_msg__pack);
	if (ret < 0) {
		mslog(ctx->s, NULL, LOG_ERR, "error sending ctl reply");
	}

	return;
}

struct ctl_watcher_st {
	int fd;
	struct ev_io ctl_cmd_io;
};

static void ctl_cmd_wacher_cb(EV_P_ ev_io *w, int revents)
{
	main_server_st *s = ev_userdata(loop);
	int ret;
	size_t length;
	uint8_t cmd;
	uint8_t buffer[256];
	method_ctx ctx;
	struct ctl_watcher_st *wst = container_of(w, struct ctl_watcher_st, ctl_cmd_io);
	unsigned i, indef = 0;

	ctx.s = s;
	ctx.pool = talloc_new(wst);

	if (ctx.pool == NULL)
		goto fail;

	/* read request */
	ret = recv_msg_data(wst->fd, &cmd, buffer, sizeof(buffer), NULL);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "error receiving ctl data");
		goto fail;
	}

	length = ret;

	for (i = 0;; i++) {
		if (methods[i].cmd == 0) {
			mslog(s, NULL, LOG_INFO,
			      "unknown unix ctl message: 0x%.1x",
			      (unsigned)cmd);
			break;
		} else if (methods[i].cmd == cmd) {
			indef = methods[i].indefinite;
			methods[i].func(&ctx, wst->fd, buffer, length);
			break;
		}
	}

	if (indef) {
		talloc_free(ctx.pool);
		return;
	}
 fail:
 	if (s->top_fd == wst->fd)
 		s->top_fd = -1;
 	close(wst->fd);
 	ev_io_stop(EV_A_ w);
 	talloc_free(wst);
 	return;
}

static void ctl_handle_commands(main_server_st * s)
{
	int cfd = -1, e, ret;
	struct sockaddr_un sa;
	socklen_t sa_len;
	struct ctl_watcher_st *wst;

	sa_len = sizeof(sa);
	cfd = accept(s->ctl_fd, (struct sockaddr *)&sa, &sa_len);
	if (cfd == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "error accepting control connection: %s", strerror(e));
		goto fail;
	}

	ret = check_upeer_id("ctl", s->perm_config->debug, cfd, 0, 0, NULL, NULL);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "ctl: unauthorized connection");
		goto fail;
	}

	set_cloexec_flag(cfd, 1);

	wst = talloc(s, struct ctl_watcher_st);
	if (wst == NULL)
		goto fail;

	wst->fd = cfd;

	ev_io_init(&wst->ctl_cmd_io, ctl_cmd_wacher_cb, wst->fd, EV_READ);
	ev_io_start(loop, &wst->ctl_cmd_io);

	return;
 fail:
	if (cfd != -1)
		close(cfd);
}

void ctl_handler_set_fds(main_server_st * s, ev_io *watcher)
{
	if (s->config->use_occtl == 0)
		return;

	ev_io_set(watcher, s->ctl_fd, EV_READ);
}

void ctl_handler_run_pending(main_server_st* s, ev_io *watcher)
{
	if (s->config->use_occtl == 0)
		return;

	ctl_handle_commands(s);
}

void ctl_handler_notify (main_server_st* s, struct proc_st *proc, unsigned connect)
{
	TopUpdateRep rep = TOP_UPDATE_REP__INIT;
	UserListRep list = USER_LIST_REP__INIT;
	int ret;
	method_ctx ctx;
	void *pool = talloc_new(proc);

	if (s->top_fd == -1)
		return;

	if (pool == NULL) {
		goto fail;
	}

	ctx.s = s;
	ctx.pool = pool;

	mslog(s, NULL, LOG_DEBUG, "ctl: top update");

	rep.connected = connect;
	if (connect == 0 && proc->discon_reason) {
		rep.has_discon_reason = 1;
		rep.discon_reason = proc->discon_reason;
		rep.discon_reason_txt = (char*)discon_reason_to_str(proc->discon_reason);
	}

	ret = append_user_info(&ctx, &list, proc);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR,
		      "error appending user info to reply");
		goto fail;
	}
	rep.user = &list;

	ret = send_msg(pool, s->top_fd, CTL_CMD_TOP_UPDATE_REP, &rep,
		       (pack_size_func) top_update_rep__get_packed_size,
		       (pack_func) top_update_rep__pack);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "error sending ctl reply");
		goto fail;
	}

	talloc_free(pool);
	return;
 fail:
	talloc_free(pool);
 	s->top_fd = -1;
}
