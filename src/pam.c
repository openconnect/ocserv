/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <vpn.h>
#include <main-auth.h>

#ifdef HAVE_PAM

#include <security/pam_appl.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <pcl.h>

#define APP_NAME PACKAGE

#define MAX_REPLIES 2

enum {
	PAM_S_INIT,
	PAM_S_WAIT_FOR_PASS,
	PAM_S_COMPLETE,
};

struct pam_ctx_st {
	char password[MAX_PASSWORD_SIZE];
	char username[MAX_USERNAME_SIZE];
	pam_handle_t * ph;
	struct pam_conv dc;
	coroutine_t cr;
	int cr_ret;
	const char* cr_msg;
	unsigned sent_msg;
	struct pam_response *replies; /* for safety */
	unsigned state; /* PAM_S_ */
};

static int dummy_conv(int msg_size, const struct pam_message **msg, 
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
			        if (pctx->sent_msg == 0) {
					pctx->state = PAM_S_WAIT_FOR_PASS;
					pctx->cr_msg = msg[i]->msg;
					pctx->cr_ret = PAM_SUCCESS;

					pctx->sent_msg = 1;
					co_resume();
					pctx->state = PAM_S_INIT;
				}
				break;
		}
		

		switch (msg[i]->msg_style) {
			case PAM_PROMPT_ECHO_OFF:
			case PAM_PROMPT_ECHO_ON:
				if (pctx->sent_msg == 0) {
					/* no message, just asking for password */
					pctx->state = PAM_S_WAIT_FOR_PASS;
					pctx->cr_msg = NULL;
					pctx->cr_ret = PAM_SUCCESS;
					pctx->sent_msg = 1;
					co_resume();
					pctx->state = PAM_S_INIT;
				}

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

	pret = pam_authenticate(pctx->ph, PAM_SILENT);
	if (pret != PAM_SUCCESS) {
		pctx->cr_ret = pret;
		return;
	}
	
	pret = pam_acct_mgmt(pctx->ph, PAM_SILENT);
	if (pret != PAM_SUCCESS) {
		pctx->cr_ret = pret;
		return;
	}
	
	pctx->state = PAM_S_COMPLETE;

	pctx->cr_ret = PAM_SUCCESS;
	
	co_resume();
}

static int pam_auth_init(void** ctx, const char* user, const char* ip, void* additional)
{
int pret;
struct pam_ctx_st * pctx;

	if (user == NULL)
		return -1;

	pctx = calloc(1, sizeof(*pctx));
	if (pctx == NULL)
		return -1;

	pctx->cr = co_create(co_auth_user, pctx, NULL, 128*1024);
	if (pctx->cr == NULL)
		goto fail;

	pctx->dc.conv = dummy_conv;
	pctx->dc.appdata_ptr = pctx;
	snprintf(pctx->username, sizeof(pctx->username), "%s", user);

	pret = pam_start(APP_NAME, user, &pctx->dc, &pctx->ph);
	if (pret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "Error in PAM authentication initialization: %s", pam_strerror(pctx->ph, pret));
		goto fail;
	}
	
	if (ip != NULL)
		pam_set_item(pctx->ph, PAM_RHOST, ip);

	*ctx = pctx;
	
	return 0;

fail:
	free(pctx);
	return -1;
}

static int pam_auth_msg(void* ctx, char* msg, size_t msg_size)
{
struct pam_ctx_st * pctx = ctx;

	if (pctx->state != PAM_S_INIT && pctx->state != PAM_S_WAIT_FOR_PASS) {
		syslog(LOG_AUTH, "PAM conversation in wrong state (%d)", pctx->state);
		return ERR_AUTH_FAIL;
	}

	if (pctx->state == PAM_S_INIT) {
		/* get the prompt */
		pctx->cr_ret = PAM_CONV_ERR;
		co_call(pctx->cr);
  	}

	if (pctx->cr_ret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "Error in PAM authentication: %s", pam_strerror(pctx->ph, pctx->cr_ret));
		return ERR_AUTH_FAIL;
	}

	if (msg != NULL) {
		if (pctx->cr_msg == NULL)
			snprintf(msg, msg_size, "Please enter your password");
		else
			snprintf(msg, msg_size, "%s", pctx->cr_msg);
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
		syslog(LOG_AUTH, "PAM conversation in wrong state (%d/expecting %d)", pctx->state, PAM_S_WAIT_FOR_PASS);
		return ERR_AUTH_FAIL;
	}

	memcpy(pctx->password, pass, pass_len);
	pctx->password[pass_len] = 0;

	pctx->cr_ret = PAM_CONV_ERR;
	co_call(pctx->cr);

	if (pctx->cr_ret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "Error in PAM authentication: %s", pam_strerror(pctx->ph, pctx->cr_ret));
		return ERR_AUTH_FAIL;
	}
	
	if (pctx->state != PAM_S_COMPLETE)
		return ERR_AUTH_CONTINUE;

	return 0;
}

/* Returns 0 if the user is successfully authenticated
 */
static int pam_auth_group(void* ctx, char *groupname, int groupname_size)
{
struct passwd * pwd;
struct pam_ctx_st * pctx = ctx;

	groupname[0] = 0;
	pwd = getpwnam(pctx->username);
	if (pwd != NULL) {
		struct group* grp = getgrgid(pwd->pw_gid);
		if (grp != NULL)
			snprintf(groupname, groupname_size, "%s", grp->gr_name);
	}

	return 0;
}

static void pam_auth_deinit(void* ctx)
{
struct pam_ctx_st * pctx = ctx;

	pam_end(pctx->ph, pctx->cr_ret);
	free(pctx->replies);
	co_delete(pctx->cr);
	free(pctx);
}

const struct auth_mod_st pam_auth_funcs = {
  .type = AUTH_TYPE_PAM | AUTH_TYPE_USERNAME_PASS,
  .auth_init = pam_auth_init,
  .auth_deinit = pam_auth_deinit,
  .auth_msg = pam_auth_msg,
  .auth_pass = pam_auth_pass,
  .auth_group = pam_auth_group
};

#endif
