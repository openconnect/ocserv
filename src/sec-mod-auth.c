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

static const struct auth_mod_st *module = NULL;

void sec_auth_init(struct cfg_st *config)
{
#ifdef HAVE_PAM
	if ((config->auth_types & pam_auth_funcs.type) == pam_auth_funcs.type)
		module = &pam_auth_funcs;
	else
#endif
	if ((config->auth_types & plain_auth_funcs.type) ==
		    plain_auth_funcs.type) {
		module = &plain_auth_funcs;
	}
}

static int generate_cookie(sec_mod_st * sec, client_entry_st * entry)
{
	int ret;
	struct stored_cookie_st sc;
	uint32_t t;

	ret =
	    gnutls_rnd(GNUTLS_RND_NONCE, sc.session_id, sizeof(sc.session_id));
	if (ret < 0)
		return -1;

	/* Fixme: possibly we should allow for completely random seeds */
	if (sec->config->predictable_ips != 0) {
		t = hash_any(entry->username, strlen(entry->username), 0);
		memcpy(sc.ipv4_seed, &t, 4);
	} else {
		ret = gnutls_rnd(GNUTLS_RND_NONCE, sc.ipv4_seed, sizeof(sc.ipv4_seed));
		if (ret < 0)
			return -1;
	}

	memcpy(sc.username, entry->username, sizeof(entry->username));
	memcpy(sc.groupname, entry->groupname, sizeof(entry->groupname));
	memcpy(sc.hostname, entry->hostname, sizeof(entry->hostname));

	sc.expiration = time(0) + sec->config->cookie_validity;

	ret =
	    encrypt_cookie(&sec->cookie_key, &sc, entry->cookie,
			   sizeof(entry->cookie));
	if (ret < 0)
		return -1;

	return 0;
}

static
int send_sec_auth_reply(sec_mod_st * sec, client_entry_st * entry, AUTHREP r)
{
	SecAuthReplyMsg msg = SEC_AUTH_REPLY_MSG__INIT;
	int ret;

	if (r == AUTH__REP__OK) {
		/* fill message */
		ret = generate_cookie(sec, entry);
		if (ret < 0) {
			seclog(LOG_INFO, "cannot generate cookie");
			return ret;
		}

		msg.reply = AUTH__REP__OK;
		msg.has_cookie = 1;
		msg.cookie.data = entry->cookie;
		msg.cookie.len = COOKIE_SIZE;

		msg.user_name = entry->username;

		msg.has_sid = 1;
		msg.sid.data = entry->sid;
		msg.sid.len = sizeof(entry->sid);

		msg.has_dtls_session_id = 1;
		msg.dtls_session_id.data = entry->dtls_session_id;
		msg.dtls_session_id.len = sizeof(entry->dtls_session_id);

		ret = send_msg(entry, sec->fd, SM_CMD_AUTH_REP,
			       &msg,
			       (pack_size_func)
			       sec_auth_reply_msg__get_packed_size,
			       (pack_func) sec_auth_reply_msg__pack);
	} else {
		msg.reply = AUTH__REP__FAILED;

		ret = send_msg(entry, sec->fd, SM_CMD_AUTH_REP,
			       &msg,
			       (pack_size_func)
			       sec_auth_reply_msg__get_packed_size,
			       (pack_func) sec_auth_reply_msg__pack);
	}

	if (ret < 0) {
		int e = errno;
		seclog(LOG_ERR, "send_msg: %s", strerror(e));
		return ret;
	}

	return 0;
}

static
int send_sec_auth_reply_msg(sec_mod_st * sec, client_entry_st * e)
{
	SecAuthReplyMsg msg = SEC_AUTH_REPLY_MSG__INIT;
	char tmp[MAX_MSG_SIZE] = "";

	int ret;

	if (e->auth_ctx == NULL)
		return -1;

	ret = module->auth_msg(e->auth_ctx, tmp, sizeof(tmp));
	if (ret < 0)
		return ret;

	msg.msg = tmp;
	msg.reply = AUTH__REP__MSG;

	msg.has_sid = 1;
	msg.sid.data = e->sid;
	msg.sid.len = sizeof(e->sid);

	ret = send_msg(e, sec->fd, SM_CMD_AUTH_REP, &msg,
		       (pack_size_func) sec_auth_reply_msg__get_packed_size,
		       (pack_func) sec_auth_reply_msg__pack);
	if (ret < 0) {
		seclog(LOG_ERR, "send_auth_reply_msg error");
	}

	return ret;
}

static int check_user_group_status(sec_mod_st * sec, client_entry_st * e,
				   int tls_auth_ok, const char *cert_user,
				   const char *cert_group)
{
	if (sec->config->auth_types & AUTH_TYPE_CERTIFICATE) {
		if (tls_auth_ok == 0 && sec->config->cisco_client_compat == 0) {
			seclog(LOG_INFO, "user '%s' presented no certificate",
			       e->username);
			return -1;
		}

		if (tls_auth_ok != 0) {
			if (e->username[0] == 0) {
				snprintf(e->username, sizeof(e->username), "%s",
					 cert_user);
				snprintf(e->groupname, sizeof(e->groupname),
					 "%s", cert_group);
			} else {
				if (strcmp(e->username, cert_user) != 0) {
					seclog(LOG_INFO,
					       "user '%s' presented a certificate from user '%s'",
					       e->username, cert_user);
					return -1;
				}

				if (sec->config->cert_group_oid != NULL
				    && strcmp(e->groupname, cert_group) != 0) {
					seclog(LOG_INFO,
					       "user '%s' presented a certificate from group '%s' but he is member of '%s'",
					       e->username, cert_group,
					       e->groupname);
					return -1;
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
int handle_sec_auth_res(sec_mod_st * sec, client_entry_st * e, int result)
{
	int ret;

	if (result == ERR_AUTH_CONTINUE) {
		ret = send_sec_auth_reply_msg(sec, e);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}
		return 0;	/* wait for another command */
	} else if (result == 0) {
		e->status = PS_AUTH_COMPLETED;

		ret = send_sec_auth_reply(sec, e, AUTH__REP__OK);
		if (ret < 0) {
			e->status = PS_AUTH_FAILED;
			seclog(LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}

		del_client_entry(sec->client_db, e);
	} else {
		e->status = PS_AUTH_FAILED;
		add_ip_to_ban_list(sec->ban_db, e->ip, time(0) + sec->config->min_reauth_time);

		ret = send_sec_auth_reply(sec, e, AUTH__REP__FAILED);
		if (ret < 0) {
			seclog(LOG_ERR, "could not send reply auth cmd.");
			return ret;
		}

		if (result < 0) {
			ret = result;
		} else {
			seclog(LOG_ERR, "unexpected auth result: %d\n", result);
			ret = ERR_BAD_COMMAND;
		}
	}

	return ret;
}

int handle_sec_auth_cont(sec_mod_st * sec, const SecAuthContMsg * req)
{
	client_entry_st *e;
	int ret;

	if (check_if_banned(sec->ban_db, req->ip) != 0) {
		seclog(LOG_INFO,
		       "IP '%s' is banned", req->ip);
		return -1;
	}

	if (req->sid.len != SID_SIZE) {
		seclog(LOG_ERR, "auth cont but with illegal sid size (%d)!",
		       (int)req->sid.len);
		return -1;
	}

	e = find_client_entry(sec->client_db, req->sid.data);
	if (e == NULL) {
		seclog(LOG_ERR, "auth cont but with non-existing sid!");
		return -1;
	}

	if (e->status != PS_AUTH_INIT) {
		seclog(LOG_ERR, "auth cont received but we are on state %u!", e->status);
		return -1;
	}

	seclog(LOG_DEBUG, "auth cont for user '%s'", e->username);

	if (req->password == NULL) {
		seclog(LOG_ERR, "no password given in auth cont for user '%s'",
		       e->username);
		return -1;
	}

	ret =
	    module->auth_pass(e->auth_ctx, req->password,
			      strlen(req->password));
	if (ret < 0) {
		seclog(LOG_DEBUG,
		       "error in password given in auth cont for user '%s'",
		       e->username);
	}

	return handle_sec_auth_res(sec, e, ret);
}

int handle_sec_auth_init(sec_mod_st * sec, const SecAuthInitMsg * req)
{
	int ret = -1;
	client_entry_st *e;

	if (check_if_banned(sec->ban_db, req->ip) != 0) {
		seclog(LOG_INFO,
		       "IP '%s' is banned", req->ip);
		return -1;
	}

	if ((req->user_name == NULL || req->user_name[0] == 0)
	    && (sec->config->auth_types & AUTH_TYPE_USERNAME_PASS)) {
		seclog(LOG_DEBUG,
		       "auth init from '%s' with no username present", req->ip);
		return -1;
	}

	e = new_client_entry(sec->client_db, req->ip);
	if (e == NULL) {
		seclog(LOG_ERR, "cannot initialize memory");
		return -1;
	}

	if (req->hostname != NULL) {
		snprintf(e->hostname, sizeof(e->hostname), "%s", req->hostname);
	}


	if (sec->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
		/* req->username is non-null at this point */
		ret =
		    module->auth_init(&e->auth_ctx, e, req->user_name, req->ip,
				      sec->config->plain_passwd);
		if (ret < 0) {
			return ret;
		}

		ret =
		    module->auth_group(e->auth_ctx, e->groupname,
				       sizeof(e->groupname));
		if (ret != 0)
			return -1;
		e->groupname[sizeof(e->groupname) - 1] = 0;

		/* a module is allowed to change the name of the user */
		ret =
		    module->auth_user(e->auth_ctx, e->username,
				      sizeof(e->username));
		if (ret != 0 && req->user_name != NULL) {
			snprintf(e->username, MAX_USERNAME_SIZE, "%s",
				 req->user_name);
		}
	}


	ret =
	    check_user_group_status(sec, e, req->tls_auth_ok,
				    req->cert_user_name, req->cert_group_name);
	if (ret < 0) {
		goto cleanup;
	}

	e->status = PS_AUTH_INIT;
	seclog(LOG_DEBUG, "auth init for user '%s' from '%s'", e->username, req->ip);

	if (sec->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
		ret = ERR_AUTH_CONTINUE;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	return handle_sec_auth_res(sec, e, ret);
}

void sec_auth_user_deinit(client_entry_st * e)
{
	seclog(LOG_DEBUG, "auth deinit for user '%s'", e->username);
	if (e->auth_ctx != NULL) {
		module->auth_deinit(e->auth_ctx);
		e->auth_ctx = NULL;
	}
}
