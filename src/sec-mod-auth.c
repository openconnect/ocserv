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

static const struct auth_mod_st *module = NULL;

void sec_auth_init(sec_mod_st * sec, struct cfg_st *config)
{
	module = get_auth_mod();

	if (module && module->global_init) {
		module->global_init(sec, config->auth_additional);
	}
}

void sec_auth_reinit(sec_mod_st * sec, struct cfg_st *config)
{
	if (module) {
		if (module != get_auth_mod()) {
			seclog(sec, LOG_ERR, "Cannot change authentication method on reload");
			exit(1);
		}
	}
}

static int generate_cookie(sec_mod_st * sec, client_entry_st * entry)
{
	int ret;
	Cookie msg = COOKIE__INIT;

	msg.username = entry->username;
	msg.groupname = entry->groupname;
	msg.hostname = entry->hostname;
	msg.ip = entry->ip;
	msg.tls_auth_ok = entry->tls_auth_ok;

	/* Fixme: possibly we should allow for completely random seeds */
	if (sec->config->predictable_ips != 0) {
		msg.ipv4_seed = hash_any(entry->username, strlen(entry->username), 0);
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

		msg.user_name = entry->username;

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

	return 0;
}

static
int send_sec_auth_reply_msg(int cfd, sec_mod_st * sec, client_entry_st * e)
{
	SecAuthReplyMsg msg = SEC_AUTH_REPLY_MSG__INIT;
	char tmp[MAX_MSG_SIZE] = "";

	int ret;

	if (module == NULL || e->auth_ctx == NULL)
		return -1;

	ret = module->auth_msg(e->auth_ctx, tmp, sizeof(tmp));
	if (ret < 0)
		return ret;

	msg.msg = tmp;
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

	return ret;
}

static int check_user_group_status(sec_mod_st * sec, client_entry_st * e,
				   int tls_auth_ok, const char *cert_user,
				   char **cert_groups,
				   unsigned cert_groups_size)
{
	unsigned found, i;
	unsigned need_cert = 1;


	if (sec->config->auth_types & AUTH_TYPE_CERTIFICATE) {
		if ((sec->config->auth_types & AUTH_TYPE_CERTIFICATE_OPT) == AUTH_TYPE_CERTIFICATE_OPT) {
			need_cert = 0;
		}

		if (tls_auth_ok == 0 && need_cert != 0) {
			seclog(sec, LOG_INFO, "user '%s' presented no certificate",
			       e->username);
			return -1;
		}

		e->tls_auth_ok = tls_auth_ok;
		if (tls_auth_ok != 0) {
			if (e->username[0] == 0 && sec->config->cert_user_oid != NULL) {
				if (cert_user == NULL) {
					seclog(sec, LOG_INFO, "no username in the certificate!");
					return -1;
				}

				strlcpy(e->username, cert_user, sizeof(e->username));
				if (cert_groups_size > 0 && sec->config->cert_group_oid != NULL && e->groupname[0] == 0)
					strlcpy(e->groupname, cert_groups[0], sizeof(e->groupname));
			} else {
				if (sec->config->cert_user_oid != NULL && cert_user && strcmp(e->username, cert_user) != 0) {
					seclog(sec, LOG_INFO,
					       "user '%s' presented a certificate from user '%s'",
					       e->username, cert_user);
					return -1;
				}

				if (sec->config->cert_group_oid != NULL) {
					found = 0;
					for (i=0;i<cert_groups_size;i++) {
						if (strcmp(e->groupname, cert_groups[i]) == 0) {
							found++;
							break;
						}
					}
					if (found == 0) {
						seclog(sec, LOG_INFO,
							"user '%s' presented a certificate from group '%s' but he isn't a member of it",
							e->username, e->groupname);
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

	if (result == ERR_AUTH_CONTINUE) {
		ret = send_sec_auth_reply_msg(cfd, sec, e);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}
		return 0;	/* wait for another command */
	} else if (result == 0) {
		e->status = PS_AUTH_COMPLETED;

		ret = send_sec_auth_reply(cfd, sec, e, AUTH__REP__OK);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(sec, LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}

		ret = 0;
	} else {
		e->status = PS_AUTH_FAILED;
		add_ip_to_ban_list(sec, e->ip, time(0) + sec->config->min_reauth_time);

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

/* opens or closes a session.
 */
int handle_sec_auth_session_cmd(int cfd, sec_mod_st * sec, const SecAuthSessionMsg * req,
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
		seclog(sec, LOG_INFO, "session open/close but with non-existing sid!");
		return -1;
	}

	if (cmd == SM_CMD_AUTH_SESSION_OPEN) {
		SecAuthSessionReplyMsg rep = SEC_AUTH_SESSION_REPLY_MSG__INIT;

		if (module != NULL && module->open_session != NULL) {
			ret = module->open_session(e->auth_ctx, req->sid.data, req->sid.len);
			if (ret < 0) {
				e->status = PS_AUTH_FAILED;
				seclog(sec, LOG_ERR, "could not open session.");
				del_client_entry(sec, e);
				rep.reply = AUTH__REP__FAILED;
			} else {
				e->have_session = 1;
				rep.reply = AUTH__REP__OK;
			}
		} else {
			rep.reply = AUTH__REP__OK;
		}

		lpool = talloc_new(e);
		if (lpool == NULL) {
			return ERR_MEM;
		}

		if (sec->config_module && sec->config_module->get_sup_config) {
			ret = sec->config_module->get_sup_config(sec->config, e, &rep, lpool);
			if (ret < 0) {
				seclog(sec, LOG_ERR, "error reading additional configuration for '%s'", e->username);
				talloc_free(lpool);
				return ERR_READ_CONFIG;
			}
		}

		ret = send_msg(lpool, cfd, SM_CMD_AUTH_SESSION_REPLY, &rep,
				(pack_size_func) sec_auth_session_reply_msg__get_packed_size,
				(pack_func) sec_auth_session_reply_msg__pack);
		if (ret < 0) {
			seclog(sec, LOG_WARNING, "sec-mod error in sending session reply");
		}
		talloc_free(lpool);
	} else {
		if (req->has_uptime && req->uptime > e->stats.uptime) {
				e->stats.uptime = req->uptime;
		}
		if (req->has_bytes_in && req->bytes_in > e->stats.bytes_in) {
				e->stats.bytes_in = req->bytes_in;
		}
		if (req->has_bytes_out && req->bytes_out > e->stats.bytes_out) {
				e->stats.bytes_out = req->bytes_out;
		}
		del_client_entry(sec, e);
	}

	return 0;
}

int handle_sec_auth_stats_cmd(sec_mod_st * sec, const CliStatsMsg * req)
{
	client_entry_st *e;

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
		seclog(sec, LOG_ERR, "session stats received in unauthenticated client!");
		return -1;
	}

	/* stats only increase */
	if (req->bytes_in > e->stats.bytes_in)
		e->stats.bytes_in = req->bytes_in;
	if (req->bytes_out > e->stats.bytes_out)
		e->stats.bytes_out = req->bytes_out;
	if (req->uptime > e->stats.uptime)
		e->stats.uptime = req->uptime;

	if (module == NULL || module->session_stats == NULL)
		return 0;

	module->session_stats(e->auth_ctx, &e->stats);
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

	if (e->status != PS_AUTH_INIT) {
		seclog(sec, LOG_ERR, "auth cont received but we are on state %u!", e->status);
		return -1;
	}

	seclog(sec, LOG_DEBUG, "auth cont for user '%s'", e->username);

	if (req->password == NULL) {
		seclog(sec, LOG_ERR, "no password given in auth cont for user '%s'",
		       e->username);
		return -1;
	}

	ret =
	    module->auth_pass(e->auth_ctx, req->password,
			      strlen(req->password));
	if (ret < 0) {
		seclog(sec, LOG_DEBUG,
		       "error in password given in auth cont for user '%s'",
		       e->username);
	}

	return handle_sec_auth_res(cfd, sec, e, ret);
}

int handle_sec_auth_init(int cfd, sec_mod_st * sec, const SecAuthInitMsg * req)
{
	int ret = -1;
	client_entry_st *e;

	if (check_if_banned(sec, req->ip) != 0) {
		seclog(sec, LOG_INFO,
		       "IP '%s' is banned", req->ip);
		return -1;
	}

	if ((req->user_name == NULL || req->user_name[0] == 0)
	    && (sec->config->auth_types & AUTH_TYPE_USERNAME_PASS)) {
		seclog(sec, LOG_DEBUG,
		       "auth init from '%s' with no username present", req->ip);
		return -1;
	}

	e = new_client_entry(sec, req->ip);
	if (e == NULL) {
		seclog(sec, LOG_ERR, "cannot initialize memory");
		return -1;
	}

	if (req->hostname != NULL) {
		strlcpy(e->hostname, req->hostname, sizeof(e->hostname));
	}

	if (sec->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
		/* req->username is non-null at this point */
		ret =
		    module->auth_init(&e->auth_ctx, e, req->user_name, req->ip,
				      sec->config->auth_additional);
		if (ret < 0) {
			return ret;
		}

		ret =
		    module->auth_group(e->auth_ctx, req->group_name, e->groupname,
				       sizeof(e->groupname));
		if (ret != 0)
			return -1;
		e->groupname[sizeof(e->groupname) - 1] = 0;

		/* a module is allowed to change the name of the user */
		ret =
		    module->auth_user(e->auth_ctx, e->username,
				      sizeof(e->username));
		if (ret != 0 && req->user_name != NULL) {
			strlcpy(e->username, req->user_name, sizeof(e->username));
		}
	}

	if (sec->config->auth_types & AUTH_TYPE_CERTIFICATE) {
		if (e->groupname[0] == 0 && req->group_name != NULL && sec->config->cert_group_oid != NULL) {
			unsigned i, found = 0;

			for (i=0;i<req->n_cert_group_names;i++) {
				if (strcmp(req->group_name, req->cert_group_names[i]) == 0) {
					strlcpy(e->groupname, req->cert_group_names[i], sizeof(e->groupname));
					found = 1;
					break;
				}
			}

			if (found == 0) {
				seclog(sec, LOG_AUTH, "user '%s' requested group '%s' but is not included on his certificate groups",
					req->user_name, req->group_name);
				return -1;
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
	seclog(sec, LOG_DEBUG, "auth init %sfor user '%s' (group: '%s') from '%s'", 
	       req->tls_auth_ok?"(with cert) ":"",
	       e->username, e->groupname, req->ip);

	if (sec->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
		ret = ERR_AUTH_CONTINUE;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	return handle_sec_auth_res(cfd, sec, e, ret);
}

void sec_auth_user_deinit(sec_mod_st * sec, client_entry_st * e)
{
	if (module == NULL)
		return;

	seclog(sec, LOG_DEBUG, "auth deinit for user '%s'", e->username);
	if (e->auth_ctx != NULL) {
		if (e->have_session) {
			module->close_session(e->auth_ctx, &e->stats);
		}
		module->auth_deinit(e->auth_ctx);
		e->auth_ctx = NULL;
	}
}
