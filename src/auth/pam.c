/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <vpn.h>
#include "pam.h"
#include "cfg.h"
#include <sec-mod-auth.h>

#ifdef HAVE_PAM

/* A simple PAM authenticator based on coroutines (to achieve
 * asynchronous operation). It does not use pam_open_session()
 * as it is unclear to me whether this can have any benefit in our
 * use cases (and it does not seem to apply to the forking model
 * we use).
 *
 * As it is now it only provides authentication via PAM, but
 * no session management.
 */

#include <security/pam_appl.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include "auth/pam.h"

#define PAM_STACK_SIZE (96*1024)

#define MAX_REPLIES 2

enum {
	PAM_S_INIT,
	PAM_S_WAIT_FOR_PASS,
	PAM_S_COMPLETE,
};

static int ocserv_conv(int msg_size, const struct pam_message **msg, 
		struct pam_response **resp, void *uptr)
{
struct pam_ctx_st * pctx = uptr;
unsigned i;

	if (msg_size == 0)
		return PAM_SUCCESS;

	pctx->replies = calloc(1, msg_size*sizeof(*pctx->replies));
	if (pctx->replies == NULL)
		return PAM_BUF_ERR;

	for (i=0;i<msg_size;i++) {
		switch (msg[i]->msg_style) {
			case PAM_ERROR_MSG:
			case PAM_TEXT_INFO:
				syslog(LOG_DEBUG, "PAM-auth conv info: %s", msg[i]->msg);

				str_append_str(&pctx->msg, msg[i]->msg);
				str_append_data(&pctx->msg, " ", 1);
				pctx->sent_msg = 1;
				break;
			case PAM_PROMPT_ECHO_OFF:
			case PAM_PROMPT_ECHO_ON:
				syslog(LOG_DEBUG, "PAM-auth conv: echo-%s, sent: %d", (msg[i]->msg_style==PAM_PROMPT_ECHO_ON)?"on":"off", pctx->sent_msg);

				if (pctx->sent_msg == 0) {
					/* no message, just asking for password */
					str_reset(&pctx->msg);
					pctx->sent_msg = 1;
				}
				pctx->state = PAM_S_WAIT_FOR_PASS;
				pctx->cr_ret = PAM_SUCCESS;
				co_resume();
				pctx->state = PAM_S_INIT;

				pctx->replies[i].resp = strdup(pctx->password);
				pctx->sent_msg = 0;
				break;
                }
	}

	*resp = pctx->replies;
	pctx->replies = NULL;
	return PAM_SUCCESS;  
}

static void co_auth_user(void* data)
{
struct pam_ctx_st * pctx = data;
int pret;

	pctx->state = PAM_S_INIT;

	pret = pam_authenticate(pctx->ph, 0);
	if (pret != PAM_SUCCESS) {
		syslog(LOG_INFO, "PAM authenticate error: %s", pam_strerror(pctx->ph, pret));
		pctx->cr_ret = pret;
		goto wait;
	}
	
	pret = pam_acct_mgmt(pctx->ph, 0);
	if (pret == PAM_NEW_AUTHTOK_REQD) {
		/* change password */
		syslog(LOG_INFO, "Password for user '%s' is expired. Attempting to update...", pctx->username);

		pctx->changing = 1;
		pret = pam_chauthtok(pctx->ph, PAM_CHANGE_EXPIRED_AUTHTOK);
	}
	
	if (pret != PAM_SUCCESS) {
		syslog(LOG_INFO, "PAM acct-mgmt error: %s", pam_strerror(pctx->ph, pret));
		pctx->cr_ret = pret;
		goto wait;
	}
	
	pctx->state = PAM_S_COMPLETE;
	pctx->cr_ret = PAM_SUCCESS;

wait:
	while(1) {
		co_resume();
	}
}

static int pam_auth_init(void** ctx, void *pool, const char* user, const char* ip)
{
int pret;
struct pam_ctx_st * pctx;

	if (user == NULL || user[0] == 0) {
		syslog(LOG_AUTH,
		       "pam-auth: no username present");
		return ERR_AUTH_FAIL;
	}

	pctx = talloc_zero(pool, struct pam_ctx_st);
	if (pctx == NULL)
		return -1;

	str_init(&pctx->msg, pctx);

	pctx->dc.conv = ocserv_conv;
	pctx->dc.appdata_ptr = pctx;
	pret = pam_start(PACKAGE, user, &pctx->dc, &pctx->ph);
	if (pret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "PAM-auth init: %s", pam_strerror(pctx->ph, pret));
		goto fail1;
	}

	pctx->cr = co_create(co_auth_user, pctx, NULL, PAM_STACK_SIZE);
	if (pctx->cr == NULL)
		goto fail2;

	strlcpy(pctx->username, user, sizeof(pctx->username));

	if (ip != NULL)
		pam_set_item(pctx->ph, PAM_RHOST, ip);

	*ctx = pctx;
	
	return ERR_AUTH_CONTINUE;

fail2:
	pam_end(pctx->ph, pret);
fail1:
	talloc_free(pctx);
	return -1;
}

static int pam_auth_msg(void* ctx, void *pool, char** msg)
{
struct pam_ctx_st * pctx = ctx;

	if (pctx->state != PAM_S_INIT && pctx->state != PAM_S_WAIT_FOR_PASS) {
		*msg = NULL;
		return 0;
	}

	if (pctx->state == PAM_S_INIT) {
		/* get the prompt */
		pctx->cr_ret = PAM_CONV_ERR;
		co_call(pctx->cr);

		if (pctx->cr_ret != PAM_SUCCESS) {
			syslog(LOG_AUTH, "PAM-auth pam_auth_msg: %s", pam_strerror(pctx->ph, pctx->cr_ret));
			return ERR_AUTH_FAIL;
		}
	}

	if (msg != NULL) {
		if (pctx->msg.length == 0)
                        if (pctx->changing)
				*msg = talloc_strdup(pool, "Please enter the new password.");
                        else
				*msg = talloc_strdup(pool, "Please enter your password.");
		else {
			if (str_append_data(&pctx->msg, "\0", 1) < 0)
				return -1;

			*msg = talloc_strdup(pool, (char*)pctx->msg.data);
		}
	}

	return 0;
}

/* Returns 0 if the user is successfully authenticated
 */
static int pam_auth_pass(void* ctx, const char* pass, unsigned pass_len)
{
struct pam_ctx_st * pctx = ctx;

	if (pass == NULL || pass_len+1 > sizeof(pctx->password))
		return -1;

	if (pctx->state != PAM_S_WAIT_FOR_PASS) {
		syslog(LOG_AUTH, "PAM auth: conversation in wrong state (%d/expecting %d)", pctx->state, PAM_S_WAIT_FOR_PASS);
		return ERR_AUTH_FAIL;
	}

	memcpy(pctx->password, pass, pass_len);
	pctx->password[pass_len] = 0;

	pctx->cr_ret = PAM_CONV_ERR;
	co_call(pctx->cr);

	if (pctx->cr_ret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "PAM-auth pam_auth_pass: %s", pam_strerror(pctx->ph, pctx->cr_ret));
		return ERR_AUTH_FAIL;
	}
	
	if (pctx->state != PAM_S_COMPLETE)
		return ERR_AUTH_CONTINUE;

	return 0;
}

/* Returns 0 if the user is successfully authenticated
 */
static int pam_auth_group(void* ctx, const char *suggested, char *groupname, int groupname_size)
{
struct passwd * pwd;
struct pam_ctx_st * pctx = ctx;
struct group *grp;
int ret;
unsigned found;

	groupname[0] = 0;

	pwd = getpwnam(pctx->username);
	if (pwd != NULL) {
		if (suggested != NULL) {
			gid_t groups[MAX_GROUPS];
			int ngroups = sizeof(groups)/sizeof(groups[0]);
			unsigned i;

			ret = getgrouplist(pctx->username, pwd->pw_gid, groups, &ngroups);
			if (ret <= 0) {
				return 0;
			}

			found = 0;
			for (i=0;i<ngroups;i++) {
				grp = getgrgid(groups[i]);
				if (grp != NULL && strcmp(suggested, grp->gr_name) == 0) {
					strlcpy(groupname, grp->gr_name, groupname_size);
					found = 1;
					break;
				}
			}

			if (found == 0) {
				syslog(LOG_AUTH,
				       "user '%s' requested group '%s' but is not a member",
				       pctx->username, suggested);
				return -1;
			}
		} else {
			struct group* grp = getgrgid(pwd->pw_gid);
			if (grp != NULL)
				strlcpy(groupname, grp->gr_name, groupname_size);
		}
	}

	return 0;
}

static int pam_auth_user(void* ctx, char *username, int username_size)
{
const char* user = NULL;
struct pam_ctx_st * pctx = ctx;
int pret;

	username[0] = 0;

	pret = pam_get_item(pctx->ph, PAM_USER, (const void **)&user);
	if (pret != PAM_SUCCESS) {
		/*syslog(LOG_AUTH, "PAM-auth: pam_get_item(PAM_USER): %s", pam_strerror(pctx->ph, pret));*/
		return -1;
	}
	
	if (user != NULL) {
		strlcpy(username, user, username_size);

		return 0;
	}
	
	return -1;
}

static void pam_auth_deinit(void* ctx)
{
struct pam_ctx_st * pctx = ctx;

	pam_end(pctx->ph, pctx->cr_ret);
	free(pctx->replies);
	str_clear(&pctx->msg);
	if (pctx->cr != NULL)
		co_delete(pctx->cr);
	talloc_free(pctx);
}

static void pam_group_list(void *pool, void *_additional, char ***groupname, unsigned *groupname_size)
{
	struct group *grp;
	struct pam_cfg_st *config = _additional;
	gid_t min = 0;

	if (config)
		min = config->gid_min;

	setgrent();

	*groupname_size = 0;
	*groupname = talloc_size(pool, sizeof(char*)*MAX_GROUPS);
	if (*groupname == NULL) {
		goto exit;
	}

	while((grp = getgrent()) != NULL && (*groupname_size) < MAX_GROUPS) {
		if (grp->gr_gid >= min) {
			(*groupname)[(*groupname_size)] = talloc_strdup(*groupname, grp->gr_name);
			if ((*groupname)[(*groupname_size)] == NULL)
				break;
			(*groupname_size)++;
		}
	}

 exit:
	endgrent();
	return;
}

const struct auth_mod_st pam_auth_funcs = {
  .type = AUTH_TYPE_PAM | AUTH_TYPE_USERNAME_PASS,
  .auth_init = pam_auth_init,
  .auth_deinit = pam_auth_deinit,
  .auth_msg = pam_auth_msg,
  .auth_pass = pam_auth_pass,
  .auth_group = pam_auth_group,
  .auth_user = pam_auth_user,
  .group_list = pam_group_list
};

#endif
