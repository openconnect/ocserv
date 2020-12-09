/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
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
#include <minmax.h>
#include "str.h"

#include <vpn.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>
#include <sec-mod-auth.h>
#include <auth/plain.h>
#include <common.h>
#include <auth/pam.h>
#include <sec-mod.h>
#include <vpn.h>
#include <base64-helper.h>
#include <sec-mod-sup-config.h>
#include <sec-mod-acct.h>
#include <c-strcase.h>
#include <hmac.h>

#ifdef HAVE_GSSAPI
# include <gssapi/gssapi.h>
# include <gssapi/gssapi_ext.h>
#endif

/* initializes vhost acct and auth modules if not already initialized
 */
void sec_auth_init(struct vhost_cfg_st *vhost)
{
	unsigned i;
	void *pool = vhost;

	for (i=0;i<vhost->perm_config.auth_methods;i++) {
		if (vhost->perm_config.auth[i].enabled && vhost->perm_config.auth[i].amod &&
		    vhost->perm_config.auth[i].amod->vhost_init && vhost->perm_config.auth[i].auth_ctx == NULL) {
			vhost->perm_config.auth[i].amod->vhost_init(&vhost->perm_config.auth[i].auth_ctx, pool, vhost->perm_config.auth[i].additional);
		}
	}

	if (vhost->perm_config.acct.amod && vhost->perm_config.acct.amod->vhost_init &&
	    vhost->perm_config.acct.acct_ctx == NULL)
		vhost->perm_config.acct.amod->vhost_init(&vhost->perm_config.acct.acct_ctx, pool, vhost->perm_config.acct.additional);
}

/* returns a negative number if we have reached the score for this client.
 */
static
void sec_mod_add_score_to_ip(sec_mod_st *sec, client_entry_st *e, const char *ip, unsigned points)
{
	void *lpool = talloc_new(e);
	int ret, err;
	BanIpMsg msg = BAN_IP_MSG__INIT;

	/* no reporting if banning is disabled */
	if (e->vhost->perm_config.config->max_ban_score == 0)
		return;

	msg.ip = (char*)ip;
	msg.score = points;
	msg.sid.data = e->sid;
	msg.sid.len = sizeof(e->sid);
	msg.has_sid = 1;

	if (lpool == NULL) {
		return;
	}

	ret = send_msg(lpool, sec->cmd_fd, CMD_SECM_BAN_IP, &msg,
				(pack_size_func) ban_ip_msg__get_packed_size,
				(pack_func) ban_ip_msg__pack);
	if (ret < 0) {
		err = errno;
		seclog(sec, LOG_WARNING, "error in sending BAN IP message: %s", strerror(err));
		goto fail;
	}

 fail:
	talloc_free(lpool);

	return;
}

static void update_auth_time_stats(sec_mod_st * sec, time_t secs)
{
	if (secs < 0)
		return;

	sec->total_authentications++;
	if (sec->total_authentications == 0) { /* reset stats */
		sec->avg_auth_time = 0;
		sec->max_auth_time = 0;
		return;
	}

	if (secs > sec->max_auth_time)
		sec->max_auth_time = secs;
	sec->avg_auth_time = ((uint64_t)sec->avg_auth_time*((uint64_t)(sec->total_authentications-1))+secs) / (uint64_t)sec->total_authentications;
}

static
int send_sec_auth_reply(int cfd, sec_mod_st * sec, client_entry_st * entry, AUTHREP r)
{
	SecAuthReplyMsg msg = SEC_AUTH_REPLY_MSG__INIT;
	int ret;

	if (r == AUTH__REP__OK) {
		/* fill message */
		msg.reply = AUTH__REP__OK;

		msg.user_name = entry->acct_info.username;

		if (entry->msg_str != NULL) {
			msg.msg = entry->msg_str;
		}

		/* calculate time in auth for this client */
		update_auth_time_stats(sec, time(0) - entry->created);

		msg.has_sid = 1;
		msg.sid.data = entry->sid;
		msg.sid.len = sizeof(entry->sid);

		msg.has_dtls_session_id = 1;
		msg.dtls_session_id.data = entry->dtls_session_id;
		msg.dtls_session_id.len = sizeof(entry->dtls_session_id);

		ret = send_msg(entry, cfd, CMD_SEC_AUTH_REPLY,
			       &msg,
			       (pack_size_func)
			       sec_auth_reply_msg__get_packed_size,
			       (pack_func) sec_auth_reply_msg__pack);
	} else {
		sec->auth_failures++;

		msg.reply = AUTH__REP__FAILED;

		ret = send_msg(entry, cfd, CMD_SEC_AUTH_REPLY,
			       &msg,
			       (pack_size_func)
			       sec_auth_reply_msg__get_packed_size,
			       (pack_func) sec_auth_reply_msg__pack);
	}

	if (ret < 0) {
		int e = errno;
		seclog(sec, LOG_ERR, "send_msg: %s", strerror(e));
		return ret;
	}

	talloc_free(entry->msg_str);
	entry->msg_str = NULL;

	return 0;
}

static
int send_sec_auth_reply_msg(int cfd, sec_mod_st * sec, client_entry_st * e)
{
	SecAuthReplyMsg msg = SEC_AUTH_REPLY_MSG__INIT;
	int ret;

	msg.msg = e->msg_str;
	msg.passwd_counter = e->passwd_counter;
	if (e->passwd_counter > 0)
		msg.has_passwd_counter = 1;

	msg.reply = AUTH__REP__MSG;

	msg.has_sid = 1;
	msg.sid.data = e->sid;
	msg.sid.len = sizeof(e->sid);

	ret = send_msg(e, cfd, CMD_SEC_AUTH_REPLY, &msg,
		       (pack_size_func) sec_auth_reply_msg__get_packed_size,
		       (pack_func) sec_auth_reply_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "send_auth_reply_msg error");
	}

	talloc_free(e->msg_str);
	e->msg_str = NULL;

	return ret;
}

static int check_cert_user_group_status(sec_mod_st * sec, client_entry_st * e)
{
	unsigned found, i;

	if (e->auth_type & AUTH_TYPE_CERTIFICATE) {
		if (e->tls_auth_ok == 0) {
			seclog(sec, LOG_INFO, "user %s "SESSION_STR" presented no certificate; rejecting",
			       e->acct_info.username, e->acct_info.safe_id);
			return -1;
		}

		if (e->acct_info.username[0] == 0 && e->vhost->perm_config.config->cert_user_oid != NULL) {
			if (e->cert_user_name[0] == 0) {
				seclog(sec, LOG_INFO, "no username in the certificate; rejecting");
				return -1;
			}

			strlcpy(e->acct_info.username, e->cert_user_name, sizeof(e->acct_info.username));
			if (e->cert_group_names_size > 0 && e->vhost->perm_config.config->cert_group_oid != NULL && e->acct_info.groupname[0] == 0)
				strlcpy(e->acct_info.groupname, e->cert_group_names[0], sizeof(e->acct_info.groupname));
		} else {
			if (e->vhost->perm_config.config->cert_user_oid != NULL && e->cert_user_name[0] && strcmp(e->acct_info.username, e->cert_user_name) != 0) {
				seclog(sec, LOG_INFO,
				       "user '%s' "SESSION_STR" presented a certificate which is for user '%s'; rejecting",
				       e->acct_info.username, e->acct_info.safe_id, e->cert_user_name);
				return -1;
			}

			if (e->vhost->perm_config.config->cert_group_oid != NULL) {
				found = 0;
				for (i=0;i<e->cert_group_names_size;i++) {
					if (strcmp(e->acct_info.groupname, e->cert_group_names[i]) == 0) {
						found++;
						break;
					}
				}
				if (found == 0) {
					seclog(sec, LOG_INFO,
						"user '%s' "SESSION_STR" presented a certificate from group '%s' but he isn't a member of it; rejecting",
						e->acct_info.username, e->acct_info.safe_id, e->acct_info.groupname);
						return -1;
				}
			}
		}
	}

	return 0;
}

static
int check_group(sec_mod_st * sec, client_entry_st * e)
{
	int ret;
	const char *req_group = NULL;

	if (e->req_group_name[0] != 0)
		req_group = e->req_group_name;

	if (e->module && e->module->auth_group) {
		ret =
		    e->module->auth_group(e->auth_ctx, req_group, e->acct_info.groupname,
				          sizeof(e->acct_info.groupname));
		if (ret != 0) {
			return -1;
		}
		e->acct_info.groupname[sizeof(e->acct_info.groupname) - 1] = 0;
	}

	/* set group name using the certificate info */
	if (e->auth_type & AUTH_TYPE_CERTIFICATE) {
		if (e->acct_info.groupname[0] == 0 && req_group != NULL && e->vhost->perm_config.config->cert_group_oid != NULL) {
			unsigned i, found = 0;

			for (i=0;i<e->cert_group_names_size;i++) {
				if (strcmp(req_group, e->cert_group_names[i]) == 0) {
					strlcpy(e->acct_info.groupname, e->cert_group_names[i], sizeof(e->acct_info.groupname));
					found = 1;
					break;
				}
			}

			if (found == 0) {
				seclog(sec, LOG_NOTICE, "user '%s' requested group '%s' but is not included on his certificate groups",
					e->acct_info.username, req_group);
				return -1;
			}
		}
	}

	ret =
	    check_cert_user_group_status(sec, e);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

/* Performs the required steps based on the result from the
 * authentication function (e.g. handle_auth_init).
 *
 * @cmd: the command received
 * @result: the auth result
 */
static
int handle_sec_auth_res(int cfd, sec_mod_st * sec, client_entry_st * e, int result)
{
	int ret;
	passwd_msg_st pst;
	int passwd_retries = 1;

	if ((result == ERR_AUTH_CONTINUE || result == 0) && e->module) {
		memset(&pst, 0, sizeof(pst));
		ret = e->module->auth_msg(e->auth_ctx, e, &pst);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_ERR, "error getting auth msg");
			return ret;
		}
		e->msg_str = pst.msg_str;

		/* password requested for the next stage in multifactor auth OR password is requested again at the same stage */
		passwd_retries = (e->passwd_counter < pst.counter) ? 0 : 1;
		e->passwd_counter = pst.counter;
	}

	if (result == ERR_AUTH_CONTINUE) {
		/* if the module allows multiple retries for the password and the password refers to the same stage */
		if (e->status != PS_AUTH_INIT && e->module && e->module->allows_retries && passwd_retries == 1) {
			sec_mod_add_score_to_ip(sec, e, e->acct_info.remote_ip, e->vhost->perm_config.config->ban_points_wrong_password);
		}

		ret = send_sec_auth_reply_msg(cfd, sec, e);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}
		return 0;	/* wait for another command */
	} else if (result == 0 && e->status != PS_AUTH_FAILED) {
		/* we checked status for PS_AUTH_FAILED, because status may
		 * change async if we receive a message from main that the
		 * user is banned */

		ret = check_group(sec, e);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_ERR, "could not accept group.");
			return ret;
		}

		e->status = PS_AUTH_COMPLETED;

		if (e->module) {
			e->module->auth_user(e->auth_ctx, e->acct_info.username,
					     sizeof(e->acct_info.username));
		}

		seclog(sec, LOG_DEBUG, "auth complete %sfor user '%s' "SESSION_STR" of group: '%s'",
		       (e->auth_type & AUTH_TYPE_CERTIFICATE)?"(with cert)":"",
		       e->acct_info.username, e->acct_info.safe_id, e->acct_info.groupname);

		ret = send_sec_auth_reply(cfd, sec, e, AUTH__REP__OK);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}

		ret = 0;
	} else {
		e->status = PS_AUTH_FAILED;

		sec_mod_add_score_to_ip(sec, e, e->acct_info.remote_ip, e->vhost->perm_config.config->ban_points_wrong_password);

		ret = send_sec_auth_reply(cfd, sec, e, AUTH__REP__FAILED);
		if (ret < 0) {
			seclog(sec, LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}

		if (result < 0) {
			ret = result;
		} else {
			seclog(sec, LOG_ERR, "unexpected auth result: %d\n", result);
			ret = ERR_BAD_COMMAND;
		}
	}

	return ret;
}

static void stats_add_to(stats_st *dst, stats_st *src1, stats_st *src2)
{
	dst->bytes_out = src1->bytes_out + src2->bytes_out;
	dst->bytes_in = src1->bytes_in + src2->bytes_in;
	dst->uptime = src1->uptime + src2->uptime;
}

static
int send_failed_session_open_reply(sec_mod_st *sec, int fd)
{
	SecmSessionReplyMsg rep = SECM_SESSION_REPLY_MSG__INIT;
	void *lpool;
	int ret;

	rep.reply = AUTH__REP__FAILED;

	lpool = talloc_new(sec);
	if (lpool == NULL) {
		return ERR_BAD_COMMAND;
	}

	ret = send_msg(lpool, fd, CMD_SECM_SESSION_REPLY, &rep,
			(pack_size_func) secm_session_reply_msg__get_packed_size,
			(pack_func) secm_session_reply_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_WARNING, "error in sending session reply");
		ret = ERR_BAD_COMMAND; /* we desynced */
	}
	talloc_free(lpool);

	return ret;
}

int handle_secm_session_open_cmd(sec_mod_st *sec, int fd, const SecmSessionOpenMsg *req)
{
	client_entry_st *e;
	void *lpool;
	int ret;
	SecmSessionReplyMsg rep = SECM_SESSION_REPLY_MSG__INIT;
	GroupCfgSt _cfg = GROUP_CFG_ST__INIT;

	rep.config = &_cfg;

	if (req->sid.len != SID_SIZE) {
		seclog(sec, LOG_ERR, "auth session open but with illegal sid size (%d)!",
		       (int)req->sid.len);
		return send_failed_session_open_reply(sec, fd);
	}

	e = find_client_entry(sec, req->sid.data);
	if (e == NULL) {
		seclog(sec, LOG_INFO, "session open but with non-existing SID!");
		return send_failed_session_open_reply(sec, fd);
	}

	if (e->status != PS_AUTH_COMPLETED) {
		seclog(sec, LOG_ERR, "session open received in unauthenticated client %s "SESSION_STR"!", e->acct_info.username, e->acct_info.safe_id);
		return send_failed_session_open_reply(sec, fd);
	}

	if IS_CLIENT_ENTRY_EXPIRED(sec, e, time(0)) {
		seclog(sec, LOG_ERR, "session expired; denied session for user '%s' "SESSION_STR, e->acct_info.username, e->acct_info.safe_id);
		e->status = PS_AUTH_FAILED;
		return send_failed_session_open_reply(sec, fd);
	}

	if (req->ipv4)
		strlcpy(e->acct_info.ipv4, req->ipv4, sizeof(e->acct_info.ipv4));
	if (req->ipv6)
		strlcpy(e->acct_info.ipv6, req->ipv6, sizeof(e->acct_info.ipv6));

	if (e->vhost->perm_config.acct.amod != NULL && e->vhost->perm_config.acct.amod->open_session != NULL && e->session_is_open == 0) {
		ret = e->vhost->perm_config.acct.amod->open_session(e->vhost_acct_ctx, e->auth_type, &e->acct_info, req->sid.data, req->sid.len);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_INFO, "denied session for user '%s' "SESSION_STR, e->acct_info.username, e->acct_info.safe_id);
			return send_failed_session_open_reply(sec, fd);
		}
	}
	e->session_is_open = 1;

	rep.username = e->acct_info.username;
	rep.groupname = e->acct_info.groupname;
	rep.user_agent = e->acct_info.user_agent;
	rep.device_platform = e->acct_info.device_platform;
	rep.device_type = e->acct_info.device_type;
	rep.ip = e->acct_info.remote_ip;
	rep.tls_auth_ok = e->tls_auth_ok;
	rep.vhost = e->vhost->name;

	/* Fixme: possibly we should allow for completely random seeds */
	if (e->vhost->perm_config.config->predictable_ips != 0) {
		rep.ipv4_seed = hash_any(e->acct_info.username, strlen(e->acct_info.username), 0);
	} else {
		ret = gnutls_rnd(GNUTLS_RND_NONCE, &rep.ipv4_seed, sizeof(rep.ipv4_seed));
		if (ret < 0)
			return -1;
	}

	rep.sid.data = e->sid;
	rep.sid.len = sizeof(e->sid);

	rep.reply = AUTH__REP__OK;

	lpool = talloc_new(e);
	if (lpool == NULL) {
		return ERR_BAD_COMMAND; /* we desync */
	}

	if (e->vhost->config_module && e->vhost->config_module->get_sup_config) {
		ret = e->vhost->config_module->get_sup_config(e->vhost->perm_config.config, e, &rep, lpool);
		if (ret < 0) {
			seclog(sec, LOG_ERR, "error reading additional configuration for '%s' "SESSION_STR, e->acct_info.username, e->acct_info.safe_id);
			talloc_free(lpool);
			return send_failed_session_open_reply(sec, fd);
		}
	}

	ret = send_msg(lpool, fd, CMD_SECM_SESSION_REPLY, &rep,
			(pack_size_func) secm_session_reply_msg__get_packed_size,
			(pack_func) secm_session_reply_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "error in sending session reply");
		return ERR_BAD_COMMAND; /* we desync */
	}
	talloc_free(lpool);

	seclog(sec, LOG_INFO, "%sinitiating session for user '%s' "SESSION_STR, PREFIX_VHOST(e->vhost), e->acct_info.username, e->acct_info.safe_id);
	/* refresh cookie validity */
	e->exptime = time(0) + e->vhost->perm_config.config->cookie_timeout + AUTH_SLACK_TIME;
	e->in_use++;

	return 0;
}

int handle_secm_session_close_cmd(sec_mod_st *sec, int fd, const SecmSessionCloseMsg *req)
{
	client_entry_st *e;
	int ret;
	CliStatsMsg rep = CLI_STATS_MSG__INIT;

	if (req->sid.len != SID_SIZE) {
		seclog(sec, LOG_ERR, "auth session close but with illegal sid size (%d)!",
		       (int)req->sid.len);
		return ERR_BAD_COMMAND;
	}

	e = find_client_entry(sec, req->sid.data);
	if (e == NULL) {
		seclog(sec, LOG_INFO, "session close but with non-existing SID");
		return send_msg(sec, fd, CMD_SECM_CLI_STATS, &rep,
		                (pack_size_func) cli_stats_msg__get_packed_size,
		                (pack_func) cli_stats_msg__pack);
	}

	if (e->status < PS_AUTH_COMPLETED) {
		seclog(sec, LOG_DEBUG, "session close received in unauthenticated client %s "SESSION_STR"!", e->acct_info.username, e->acct_info.safe_id);
		return send_msg(e, fd, CMD_SECM_CLI_STATS, &rep,
		                (pack_size_func) cli_stats_msg__get_packed_size,
		                (pack_func) cli_stats_msg__pack);
	}


	if (req->has_uptime && req->uptime > e->stats.uptime) {
			e->stats.uptime = req->uptime;
	}
	if (req->has_bytes_in && req->bytes_in > e->stats.bytes_in) {
			e->stats.bytes_in = req->bytes_in;
	}
	if (req->has_bytes_out && req->bytes_out > e->stats.bytes_out) {
			e->stats.bytes_out = req->bytes_out;
	}

	if (req->server_disconnected) {
		e->discon_reason = REASON_SERVER_DISCONNECT;
	}

	/* send reply */
	rep.bytes_in = e->stats.bytes_in;
	rep.bytes_out = e->stats.bytes_out;
	rep.has_discon_reason = 1;
	rep.discon_reason = e->discon_reason;

	ret = send_msg(e, fd, CMD_SECM_CLI_STATS, &rep,
			(pack_size_func) cli_stats_msg__get_packed_size,
			(pack_func) cli_stats_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "error in sending session stats");
		return ERR_BAD_COMMAND;
	}

	/* save total stats */
	stats_add_to(&e->saved_stats, &e->saved_stats, &e->stats);
	memset(&e->stats, 0, sizeof(e->stats));
	expire_client_entry(sec, e);

	return 0;
}

void handle_sec_auth_ban_ip_reply(sec_mod_st *sec, const BanIpReplyMsg *msg)
{
	client_entry_st *e;

	if (msg->sid.len != SID_SIZE) {
		seclog(sec, LOG_ERR, "ban IP reply but with illegal sid size (%d)!",
		       (int)msg->sid.len);
		return;
	}

	e = find_client_entry(sec, msg->sid.data);
	if (e == NULL) {
		return;
	}

	if (msg->reply != AUTH__REP__OK) {
		e->status = PS_AUTH_FAILED;
	}

	return;
}

int handle_sec_auth_stats_cmd(sec_mod_st * sec, const CliStatsMsg * req, pid_t pid)
{
	client_entry_st *e;
	stats_st totals;

	if (req->sid.len != SID_SIZE) {
		seclog(sec, LOG_ERR, "auth session stats but with illegal sid size (%d)!",
		       (int)req->sid.len);
		return -1;
	}

	e = find_client_entry(sec, req->sid.data);
	if (e == NULL) {
		seclog(sec, LOG_INFO, "session stats but with non-existing SID");
		return -1;
	}

	if (e->status != PS_AUTH_COMPLETED) {
		seclog(sec, LOG_ERR, "session stats received in unauthenticated client %s "SESSION_STR"!", e->acct_info.username, e->acct_info.safe_id);
		return -1;
	}

	/* stats only increase */
	if (req->bytes_in > e->stats.bytes_in)
		e->stats.bytes_in = req->bytes_in;
	if (req->bytes_out > e->stats.bytes_out)
		e->stats.bytes_out = req->bytes_out;
	if (req->uptime > e->stats.uptime)
		e->stats.uptime = req->uptime;

	if (req->has_discon_reason && req->discon_reason != 0) {
		e->discon_reason = req->discon_reason;
	}

	/* update PID */
	e->acct_info.id = pid;

	if (e->vhost->perm_config.acct.amod == NULL || e->vhost->perm_config.acct.amod->session_stats == NULL)
		return 0;

	stats_add_to(&totals, &e->stats, &e->saved_stats);
	if (req->remote_ip)
		strlcpy(e->acct_info.remote_ip, req->remote_ip, sizeof(e->acct_info.remote_ip));
	if (req->ipv4)
		strlcpy(e->acct_info.ipv4, req->ipv4, sizeof(e->acct_info.ipv4));
	if (req->ipv6)
		strlcpy(e->acct_info.ipv6, req->ipv6, sizeof(e->acct_info.ipv6));

	e->vhost->perm_config.acct.amod->session_stats(e->vhost_acct_ctx, e->auth_type, &e->acct_info, &totals);

	return 0;
}

int handle_sec_auth_cont(int cfd, sec_mod_st * sec, const SecAuthContMsg * req)
{
	client_entry_st *e;
	int ret;

	if (req->sid.len != SID_SIZE) {
		seclog(sec, LOG_ERR, "auth cont but with illegal sid size (%d)!",
		       (int)req->sid.len);
		return -1;
	}

	e = find_client_entry(sec, req->sid.data);
	if (e == NULL) {
		seclog(sec, LOG_ERR, "auth cont but with non-existing sid!");
		return -1;
	}

	if (e->status != PS_AUTH_INIT && e->status != PS_AUTH_CONT) {
		seclog(sec, LOG_ERR, "auth cont received for %s "SESSION_STR" but we are on state %s(%u)!",
		       e->acct_info.username, e->acct_info.safe_id, ps_status_to_str(e->status, 0), e->status);
		ret = -1;
		goto cleanup;
	}

	seclog(sec, LOG_DEBUG, "auth cont for user '%s' "SESSION_STR, e->acct_info.username, e->acct_info.safe_id);

	if (req->password == NULL) {
		seclog(sec, LOG_ERR, "no password given in auth cont for user '%s' "SESSION_STR,
			e->acct_info.username, e->acct_info.safe_id);
		ret = -1;
		goto cleanup;
	}

	if (e->module == NULL) {
		seclog(sec, LOG_ERR, "no module available!");
		ret = -1;
		goto cleanup;
	}

	e->status = PS_AUTH_CONT;

	ret =
	    e->module->auth_pass(e->auth_ctx, req->password,
			      strlen(req->password));
	if (ret < 0) {
		if (ret != ERR_AUTH_CONTINUE) {
			seclog(sec, LOG_DEBUG,
			       "error in password given in auth cont for user '%s' "SESSION_STR,
			       e->acct_info.username, e->acct_info.safe_id);
		}
		goto cleanup;
	}

 cleanup:
	return handle_sec_auth_res(cfd, sec, e, ret);
}

static
int set_module(sec_mod_st * sec, vhost_cfg_st *vhost, client_entry_st *e, unsigned auth_type)
{
	unsigned i;

	if (auth_type == 0)
		return -1;

	/* Find the first configured authentication method which contains
	 * the method asked by the worker, and use that. */
	for (i=0;i<vhost->perm_config.auth_methods;i++) {
		if (vhost->perm_config.auth[i].enabled && (vhost->perm_config.auth[i].type & auth_type) == auth_type) {
			e->module = vhost->perm_config.auth[i].amod;
			e->auth_type = vhost->perm_config.auth[i].type;
			e->vhost_auth_ctx = vhost->perm_config.auth[i].auth_ctx;
			e->vhost_acct_ctx = vhost->perm_config.acct.acct_ctx;

			seclog(sec, LOG_INFO, "%susing '%s' authentication to authenticate user "SESSION_STR, PREFIX_VHOST(vhost), vhost->perm_config.auth[i].name, e->acct_info.safe_id);
			return 0;
		}
	}

	return -1;
}

int handle_sec_auth_init(int cfd, sec_mod_st *sec, const SecAuthInitMsg *req, pid_t pid)
{
	int ret = -1;
	client_entry_st *e;
	unsigned i;
	unsigned need_continue = 0;
	vhost_cfg_st *vhost;
	hmac_component_st hmac_components[3];
	uint8_t computed_hmac[HMAC_DIGEST_SIZE];
	time_t now = time(0);
	time_t session_start_time;

	if (req->hmac.len != HMAC_DIGEST_SIZE || !req->hmac.data) {
		seclog(sec, LOG_NOTICE, "hmac is the wrong size");
		return -1;
	}

	/* Authenticate the client parameters */
	session_start_time = (time_t)req->session_start_time; // avoid time_t size problem

	hmac_components[0].data =  req->ip;
	// req->ip is required and protobuf doesn't permit null for required parameters
	hmac_components[0].length = strlen(req->ip);
	hmac_components[1].data = req->our_ip;
	hmac_components[1].length = req->our_ip ? strlen(req->our_ip) : 0;
	hmac_components[2].data = (void*)&session_start_time;
	hmac_components[2].length = sizeof(session_start_time);

	generate_hmac(sizeof(sec->hmac_key), sec->hmac_key, sizeof(hmac_components) / sizeof(hmac_components[0]), hmac_components, computed_hmac);

	if (memcmp(computed_hmac, req->hmac.data, req->hmac.len) != 0) {
		seclog(sec, LOG_NOTICE, "hmac presented by client doesn't match parameters provided - possible replay");
		return -1;
	}

	vhost = find_vhost(sec->vconfig, req->vhost);

	if ((now - session_start_time) > vhost->perm_config.config->auth_timeout) {
		seclog(sec, LOG_NOTICE, "hmac presented by client expired - possible replay");
		return -1;
	}

	e = new_client_entry(sec, vhost, req->ip, pid);
	if (e == NULL) {
		seclog(sec, LOG_ERR, "cannot initialize memory");
		return -1;
	}

	ret = set_module(sec, vhost, e, req->auth_type);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "no module found for auth type %u", (unsigned)req->auth_type);
		goto cleanup;
	}

	if (e->module) {
		common_auth_init_st st;

		st.username = req->user_name;
		st.ip = req->ip;
		st.our_ip = req->our_ip;
		st.user_agent = req->user_agent;
		st.id = pid;

		ret =
		    e->module->auth_init(&e->auth_ctx, e, e->vhost_auth_ctx, &st);
		if (ret == ERR_AUTH_CONTINUE) {
			need_continue = 1;
		} else if (ret < 0) {
			goto cleanup;
		}
	}

	e->tls_auth_ok = req->tls_auth_ok;

	if (req->device_platform != NULL) {
		strlcpy(e->acct_info.device_platform, req->device_platform, sizeof(e->acct_info.device_platform));
	}

	if (req->device_type != NULL) {
		strlcpy(e->acct_info.device_type, req->device_type, sizeof(e->acct_info.device_type));
	}

	if (req->user_agent != NULL)
		strlcpy(e->acct_info.user_agent, req->user_agent, sizeof(e->acct_info.user_agent));

	// Real user name is retrieved after auth.
	if (!(req->auth_type & CONFIDENTIAL_USER_NAME_AUTH_TYPES)) {
		if (req->user_name != NULL) {
			strlcpy(e->acct_info.username, req->user_name, sizeof(e->acct_info.username));
		}
	}

	if (req->our_ip != NULL) {
		strlcpy(e->acct_info.our_ip, req->our_ip, sizeof(e->acct_info.our_ip));
	}

	if (req->group_name != NULL) {
		strlcpy(e->req_group_name, req->group_name, sizeof(e->req_group_name));
	}

	if (req->cert_user_name != NULL) {
		strlcpy(e->cert_user_name, req->cert_user_name, sizeof(e->cert_user_name));
	}

	e->cert_group_names_size = MIN(MAX_GROUPS,req->n_cert_group_names);
	for (i=0;i<e->cert_group_names_size;i++) {
		e->cert_group_names[i] = talloc_strdup(e, req->cert_group_names[i]);
		if (e->cert_group_names[i] == NULL) {
			e->cert_group_names_size = 0;
			break;
		}
	}

	e->status = PS_AUTH_INIT;
	seclog(sec, LOG_DEBUG, "auth init %sfor user '%s' "SESSION_STR" of group: '%s' from '%s'",
	       req->tls_auth_ok?"(with cert) ":"",
	       e->acct_info.username, e->acct_info.safe_id, e->acct_info.groupname, req->ip);

	if (need_continue != 0) {
		ret = ERR_AUTH_CONTINUE;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	return handle_sec_auth_res(cfd, sec, e, ret);
}

void sec_auth_user_deinit(sec_mod_st *sec, client_entry_st *e)
{
	vhost_cfg_st *vhost;

	vhost = e->vhost;

	seclog(sec, LOG_DEBUG, "permamently closing session of user '%s' "SESSION_STR, e->acct_info.username, e->acct_info.safe_id);
	if (vhost->perm_config.acct.amod != NULL && vhost->perm_config.acct.amod->close_session != NULL && e->session_is_open != 0) {
		vhost->perm_config.acct.amod->close_session(e->vhost_acct_ctx, e->auth_type, &e->acct_info, &e->saved_stats, e->discon_reason);
	}

	if (e->auth_ctx != NULL) {
		if (e->module)
			e->module->auth_deinit(e->auth_ctx);
		e->auth_ctx = NULL;
	}
}
