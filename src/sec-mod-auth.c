/*
 * Copyright (C) 2013, 2014 Nikos Mavrogiannopoulos
 * Copyright (C) 2014 Red Hat
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
#include <sec-mod-auth.h>
#include <auth/plain.h>
#include <common.h>
#include <auth/pam.h>
#include <sec-mod.h>
#include <vpn.h>
#include <sec-mod-sup-config.h>
#include <sec-mod-acct.h>

#ifdef HAVE_GSSAPI
# include <gssapi/gssapi.h>
# include <gssapi/gssapi_ext.h>
#endif

void sec_auth_init(sec_mod_st * sec, struct cfg_st *config)
{
	unsigned i;

	for (i=0;i<config->auth_methods;i++) {
		if (config->auth[i].enabled && config->auth[i].amod && config->auth[i].amod->global_init)
			config->auth[i].amod->global_init(sec, config->server_name, config->auth[i].additional);
	}

	if (config->acct.amod && config->acct.amod->global_init)
		config->acct.amod->global_init(sec, config->server_name, config->acct.additional);
}

static int generate_cookie(sec_mod_st * sec, client_entry_st * entry)
{
	int ret;
	Cookie msg = COOKIE__INIT;

	msg.username = entry->auth_info.username;
	msg.groupname = entry->auth_info.groupname;
	msg.hostname = entry->hostname;
	msg.ip = entry->auth_info.remote_ip;
	msg.tls_auth_ok = entry->tls_auth_ok;

	/* Fixme: possibly we should allow for completely random seeds */
	if (sec->config->predictable_ips != 0) {
		msg.ipv4_seed = hash_any(entry->auth_info.username, strlen(entry->auth_info.username), 0);
	} else {
		ret = gnutls_rnd(GNUTLS_RND_NONCE, &msg.ipv4_seed, sizeof(msg.ipv4_seed));
		if (ret < 0)
			return -1;
	}

	msg.sid.data = entry->sid;
	msg.sid.len = sizeof(entry->sid);

	/* this is the time when this cookie must be activated (used to authenticate).
	 * if not activated by that time it expires */
	msg.expiration = time(0) + sec->config->cookie_timeout;

	ret =
	    encrypt_cookie(entry, &sec->dcookie_key, &msg, &entry->cookie,
			   &entry->cookie_size);
	if (ret < 0)
		return -1;

	return 0;
}

static
int send_sec_auth_reply(int cfd, sec_mod_st * sec, client_entry_st * entry, AUTHREP r)
{
	SecAuthReplyMsg msg = SEC_AUTH_REPLY_MSG__INIT;
	int ret;

	if (r == AUTH__REP__OK) {
		/* fill message */
		ret = generate_cookie(sec, entry);
		if (ret < 0) {
			seclog(sec, LOG_INFO, "cannot generate cookie");
			return ret;
		}

		msg.reply = AUTH__REP__OK;
		msg.has_cookie = 1;
		msg.cookie.data = entry->cookie;
		msg.cookie.len = entry->cookie_size;

		msg.user_name = entry->auth_info.username;

		if (entry->msg_str != NULL) {
			msg.msg = entry->msg_str;
		}

		msg.has_sid = 1;
		msg.sid.data = entry->sid;
		msg.sid.len = sizeof(entry->sid);

		msg.has_dtls_session_id = 1;
		msg.dtls_session_id.data = entry->dtls_session_id;
		msg.dtls_session_id.len = sizeof(entry->dtls_session_id);

		ret = send_msg(entry, cfd, SM_CMD_AUTH_REP,
			       &msg,
			       (pack_size_func)
			       sec_auth_reply_msg__get_packed_size,
			       (pack_func) sec_auth_reply_msg__pack);
	} else {
		msg.reply = AUTH__REP__FAILED;

		ret = send_msg(entry, cfd, SM_CMD_AUTH_REP,
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
	msg.reply = AUTH__REP__MSG;

	msg.has_sid = 1;
	msg.sid.data = e->sid;
	msg.sid.len = sizeof(e->sid);

	ret = send_msg(e, cfd, SM_CMD_AUTH_REP, &msg,
		       (pack_size_func) sec_auth_reply_msg__get_packed_size,
		       (pack_func) sec_auth_reply_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "send_auth_reply_msg error");
	}

	talloc_free(e->msg_str);
	e->msg_str = NULL;

	return ret;
}

static int check_user_group_status(sec_mod_st * sec, client_entry_st * e,
				   int tls_auth_ok, const char *cert_user,
				   char **cert_groups,
				   unsigned cert_groups_size)
{
	unsigned found, i;


	if (e->auth_type & AUTH_TYPE_CERTIFICATE) {
		if (tls_auth_ok == 0) {
			seclog(sec, LOG_INFO, "user %s (session: %s) presented no certificate",
			       e->auth_info.username, e->auth_info.psid);
			return -1;
		}

		e->tls_auth_ok = tls_auth_ok;
		if (tls_auth_ok != 0) {
			if (e->auth_info.username[0] == 0 && sec->config->cert_user_oid != NULL) {
				if (cert_user == NULL) {
					seclog(sec, LOG_INFO, "no username in the certificate!");
					return -1;
				}

				strlcpy(e->auth_info.username, cert_user, sizeof(e->auth_info.username));
				if (cert_groups_size > 0 && sec->config->cert_group_oid != NULL && e->auth_info.groupname[0] == 0)
					strlcpy(e->auth_info.groupname, cert_groups[0], sizeof(e->auth_info.groupname));
			} else {
				if (sec->config->cert_user_oid != NULL && cert_user && strcmp(e->auth_info.username, cert_user) != 0) {
					seclog(sec, LOG_INFO,
					       "user '%s' (session: %s) presented a certificate from user '%s'",
					       e->auth_info.username, e->auth_info.psid, cert_user);
					return -1;
				}

				if (sec->config->cert_group_oid != NULL) {
					found = 0;
					for (i=0;i<cert_groups_size;i++) {
						if (strcmp(e->auth_info.groupname, cert_groups[i]) == 0) {
							found++;
							break;
						}
					}
					if (found == 0) {
						seclog(sec, LOG_INFO,
							"user '%s' (session: %s) presented a certificate from group '%s' but he isn't a member of it",
							e->auth_info.username, e->auth_info.psid, e->auth_info.groupname);
							return -1;
					}
				}
			}
		}
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

	if ((result == ERR_AUTH_CONTINUE || result == 0) && e->module) {
		ret = e->module->auth_msg(e->auth_ctx, e, &e->msg_str);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_ERR, "error getting auth msg");
			return ret;
		}
	}

	if (result == ERR_AUTH_CONTINUE) {
		/* if the module allows multiple retries for the password */
		if (e->status != PS_AUTH_INIT && e->module && e->module->allows_retries) {
			add_ip_to_ban_list(sec, e->auth_info.remote_ip, 1, time(0) + sec->config->min_reauth_time);
		}

		ret = send_sec_auth_reply_msg(cfd, sec, e);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}
		return 0;	/* wait for another command */
	} else if (result == 0) {
		e->status = PS_AUTH_COMPLETED;

		if (e->module) {
			e->module->auth_user(e->auth_ctx, e->auth_info.username,
					     sizeof(e->auth_info.username));
		}

		ret = send_sec_auth_reply(cfd, sec, e, AUTH__REP__OK);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}
		remove_ip_from_ban_list(sec, e->auth_info.remote_ip);

		ret = 0;
	} else {
		e->status = PS_AUTH_FAILED;

		add_ip_to_ban_list(sec, e->auth_info.remote_ip, 1, time(0) + sec->config->min_reauth_time);

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

/* opens or closes a session.
 */
int handle_sec_auth_session_cmd(int cfd, sec_mod_st *sec, const SecAuthSessionMsg *req,
				unsigned cmd)
{
	client_entry_st *e;
	void *lpool;
	int ret;

	if (req->sid.len != SID_SIZE) {
		seclog(sec, LOG_ERR, "auth session open/close but with illegal sid size (%d)!",
		       (int)req->sid.len);
		return -1;
	}

	e = find_client_entry(sec, req->sid.data);
	if (e == NULL) {
		seclog(sec, LOG_INFO, "session open/close but with non-existing SID!");
		return -1;
	}

	if (e->status != PS_AUTH_COMPLETED) {
		seclog(sec, LOG_ERR, "session cmd received in unauthenticated client %s (session: %s)!", e->auth_info.username, e->auth_info.psid);
		return -1;
	}

	if (cmd == SM_CMD_AUTH_SESSION_OPEN) {
		SecAuthSessionReplyMsg rep = SEC_AUTH_SESSION_REPLY_MSG__INIT;

		if (e->time != -1 && time(0) > e->time + sec->config->cookie_timeout) {
			seclog(sec, LOG_ERR, "session is expired");
			return -1;
		}

		if (req->has_cookie == 0 || (req->cookie.len != e->cookie_size) ||
		    memcmp(req->cookie.data, e->cookie, e->cookie_size) != 0) {
			seclog(sec, LOG_ERR, "cookie doesn't match the one sent");
			return -1;
		}

		if (sec->config->acct.amod != NULL && sec->config->acct.amod->open_session != NULL && e->session_is_open == 0) {
			ret = sec->config->acct.amod->open_session(e->module->type, e->auth_ctx, &e->auth_info, req->sid.data, req->sid.len);
			if (ret < 0) {
				e->status = PS_AUTH_FAILED;
				seclog(sec, LOG_ERR, "could not open session.");
				rep.reply = AUTH__REP__FAILED;
			} else {
				rep.reply = AUTH__REP__OK;
				e->session_is_open = 1;
			}
		} else {
			rep.reply = AUTH__REP__OK;
		}

		lpool = talloc_new(e);
		if (lpool == NULL) {
			return ERR_MEM;
		}

		if (rep.reply == AUTH__REP__OK && sec->config_module && sec->config_module->get_sup_config) {
			ret = sec->config_module->get_sup_config(sec->config, e, &rep, lpool);
			if (ret < 0) {
				seclog(sec, LOG_ERR, "error reading additional configuration for '%s' (session: %s)", e->auth_info.username, e->auth_info.psid);
				talloc_free(lpool);
				return ERR_READ_CONFIG;
			}
		}

		ret = send_msg(lpool, cfd, SM_CMD_AUTH_SESSION_REPLY, &rep,
				(pack_size_func) sec_auth_session_reply_msg__get_packed_size,
				(pack_func) sec_auth_session_reply_msg__pack);
		if (ret < 0) {
			seclog(sec, LOG_WARNING, "error in sending session reply");
		}
		talloc_free(lpool);

		if (rep.reply != AUTH__REP__OK) {
			seclog(sec, LOG_INFO, "denied open session for user '%s' (session: %s)", e->auth_info.username, e->auth_info.psid);
			del_client_entry(sec, e);
		} else { /* set expiration time to unlimited (until someone closes the session) */
			seclog(sec, LOG_INFO, "initiating session for user '%s' (session: %s)", e->auth_info.username, e->auth_info.psid);
			e->time = -1;
			e->in_use++;
		}

	} else { /* CLOSE */
		seclog(sec, LOG_INFO, "temporarily closing session for %s (session: %s)", e->auth_info.username, e->auth_info.psid);

		if (req->has_uptime && req->uptime > e->stats.uptime) {
				e->stats.uptime = req->uptime;
		}
		if (req->has_bytes_in && req->bytes_in > e->stats.bytes_in) {
				e->stats.bytes_in = req->bytes_in;
		}
		if (req->has_bytes_out && req->bytes_out > e->stats.bytes_out) {
				e->stats.bytes_out = req->bytes_out;
		}

		stats_add_to(&e->saved_stats, &e->saved_stats, &e->stats);
		memset(&e->stats, 0, sizeof(e->stats));
		expire_client_entry(sec, e);
	}

	return 0;
}

int handle_sec_auth_stats_cmd(sec_mod_st * sec, const CliStatsMsg * req)
{
	client_entry_st *e;
	stats_st totals;

	if (req->sid.len != SID_SIZE) {
		seclog(sec, LOG_ERR, "auth session open/close but with illegal sid size (%d)!",
		       (int)req->sid.len);
		return -1;
	}

	e = find_client_entry(sec, req->sid.data);
	if (e == NULL) {
		seclog(sec, LOG_INFO, "session open/close but with non-existing sid!");
		return -1;
	}

	if (e->status != PS_AUTH_COMPLETED) {
		seclog(sec, LOG_ERR, "session stats received in unauthenticated client %s (session: %s)!", e->auth_info.username, e->auth_info.psid);
		return -1;
	}

	/* stats only increase */
	if (req->bytes_in > e->stats.bytes_in)
		e->stats.bytes_in = req->bytes_in;
	if (req->bytes_out > e->stats.bytes_out)
		e->stats.bytes_out = req->bytes_out;
	if (req->uptime > e->stats.uptime)
		e->stats.uptime = req->uptime;

	if (sec->config->acct.amod == NULL || sec->config->acct.amod->session_stats == NULL)
		return 0;

	stats_add_to(&totals, &e->stats, &e->saved_stats);
	if (req->remote_ip)
		strlcpy(e->auth_info.remote_ip, req->remote_ip, sizeof(e->auth_info.remote_ip));
	if (req->ipv4)
		strlcpy(e->auth_info.ipv4, req->ipv4, sizeof(e->auth_info.ipv4));
	if (req->ipv6)
		strlcpy(e->auth_info.ipv6, req->ipv6, sizeof(e->auth_info.ipv6));

	sec->config->acct.amod->session_stats(e->module->type, e->auth_ctx, &e->auth_info, &totals);
	return 0;
}

int handle_sec_auth_cont(int cfd, sec_mod_st * sec, const SecAuthContMsg * req)
{
	client_entry_st *e;
	int ret;

	if (check_if_banned(sec, req->ip) != 0) {
		seclog(sec, LOG_INFO,
		       "IP '%s' is banned", req->ip);
		return -1;
	}

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
		seclog(sec, LOG_ERR, "auth cont received for %s (session: %s) but we are on state %u!",
		       e->auth_info.username, e->auth_info.psid, e->status);
		ret = -1;
		goto cleanup;
	}

	seclog(sec, LOG_DEBUG, "auth cont for user '%s' (session: %s)", e->auth_info.username, e->auth_info.psid);

	if (req->password == NULL) {
		seclog(sec, LOG_ERR, "no password given in auth cont for user '%s' (session: %s)",
			e->auth_info.username, e->auth_info.psid);
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
		seclog(sec, LOG_DEBUG,
		       "error in password given in auth cont for user '%s' (session: %s)",
		       e->auth_info.username, e->auth_info.psid);
		goto cleanup;
	}

 cleanup:
	return handle_sec_auth_res(cfd, sec, e, ret);
}

static
int set_module(sec_mod_st * sec, client_entry_st *e, unsigned auth_type)
{
	unsigned i;

	if (auth_type == 0)
		return -1;

	/* Find the first configured authentication method which contains
	 * the method asked by the worker, and use that. */
	for (i=0;i<sec->config->auth_methods;i++) {
		if (sec->config->auth[i].enabled && (sec->config->auth[i].type & auth_type) == auth_type) {
			e->module = sec->config->auth[i].amod;
			e->auth_type = sec->config->auth[i].type;

			seclog(sec, LOG_INFO, "using '%s' authentication to authenticate user (session: %s)", sec->config->auth[i].name, e->auth_info.psid);
			return 0;
		}
	}

	return -1;
}

int handle_sec_auth_init(int cfd, sec_mod_st * sec, const SecAuthInitMsg * req)
{
	int ret = -1;
	client_entry_st *e;
	unsigned need_continue = 0;

	if (check_if_banned(sec, req->ip) != 0) {
		seclog(sec, LOG_INFO,
		       "IP '%s' is banned", req->ip);
		return -1;
	}

	e = new_client_entry(sec, req->ip);
	if (e == NULL) {
		seclog(sec, LOG_ERR, "cannot initialize memory");
		return -1;
	}

	ret = set_module(sec, e, req->auth_type);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "no module found for auth type %u", (unsigned)req->auth_type);
		goto cleanup;
	}

	if (req->hostname != NULL) {
		strlcpy(e->hostname, req->hostname, sizeof(e->hostname));
	}

	if (e->module) {
		ret =
		    e->module->auth_init(&e->auth_ctx, e, req->user_name, req->ip);
		if (ret == ERR_AUTH_CONTINUE) {
			need_continue = 1;
		} else if (ret < 0) {
			goto cleanup;
		}

		ret =
		    e->module->auth_group(e->auth_ctx, req->group_name, e->auth_info.groupname,
				       sizeof(e->auth_info.groupname));
		if (ret != 0) {
			ret = -1;
			goto cleanup;
		}
		e->auth_info.groupname[sizeof(e->auth_info.groupname) - 1] = 0;

		if (req->user_name != NULL) {
			strlcpy(e->auth_info.username, req->user_name, sizeof(e->auth_info.username));
		}
	}

	if (e->auth_type & AUTH_TYPE_CERTIFICATE) {
		if (e->auth_info.groupname[0] == 0 && req->group_name != NULL && sec->config->cert_group_oid != NULL) {
			unsigned i, found = 0;

			for (i=0;i<req->n_cert_group_names;i++) {
				if (strcmp(req->group_name, req->cert_group_names[i]) == 0) {
					strlcpy(e->auth_info.groupname, req->cert_group_names[i], sizeof(e->auth_info.groupname));
					found = 1;
					break;
				}
			}

			if (found == 0) {
				seclog(sec, LOG_AUTH, "user '%s' requested group '%s' but is not included on his certificate groups",
					req->user_name, req->group_name);
				ret = -1;
				goto cleanup;
			}
		}
	}

	ret =
	    check_user_group_status(sec, e, req->tls_auth_ok,
				    req->cert_user_name, req->cert_group_names,
				    req->n_cert_group_names);
	if (ret < 0) {
		goto cleanup;
	}

	e->status = PS_AUTH_INIT;
	seclog(sec, LOG_DEBUG, "auth init %sfor user '%s' (session: %s) of group: '%s' from '%s'", 
	       req->tls_auth_ok?"(with cert) ":"",
	       e->auth_info.username, e->auth_info.psid, e->auth_info.groupname, req->ip);

	if (need_continue != 0) {
		ret = ERR_AUTH_CONTINUE;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	return handle_sec_auth_res(cfd, sec, e, ret);
}

void sec_auth_user_deinit(sec_mod_st * sec, client_entry_st * e)
{
	if (e->module == NULL)
		return;

	seclog(sec, LOG_DEBUG, "permamently closing session of user '%s' (session: %s)", e->auth_info.username, e->auth_info.psid);
	if (e->auth_ctx != NULL) {
		if (sec->config->acct.amod != NULL && sec->config->acct.amod->close_session != NULL && e->session_is_open != 0) {
			sec->config->acct.amod->close_session(e->module->type, e->auth_ctx, &e->auth_info, &e->saved_stats);
		}
		e->module->auth_deinit(e->auth_ctx);
		e->auth_ctx = NULL;
	}
}
