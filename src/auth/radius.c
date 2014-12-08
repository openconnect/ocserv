/*
 * Copyright (C) 2014 Red Hat, Inc.
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
#include <unistd.h>
#include <vpn.h>
#include <c-ctype.h>
#include <arpa/inet.h> /* inet_ntop */
#include "radius.h"
#include "auth/common.h"

#ifdef HAVE_RADIUS

#include <freeradius-client.h>

#define RAD_GROUP_NAME 1030

int rc_aaa(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
    char *msg, int add_nas_port, int request_type);

static rc_handle *rh = NULL;

struct radius_ctx_st {
	char username[MAX_USERNAME_SIZE*2];
	char groupname[MAX_GROUPNAME_SIZE];
	char msg[4096];

	char ipv4[MAX_IP_STR];
	char ipv6[MAX_IP_STR];

	const char *config;	/* radius config file */
	const char *pass_msg;
	unsigned retries;
};

static void radius_global_init(void *pool, void *additional)
{
	rh = rc_read_config(additional);
	if (rh == NULL) {
		fprintf(stderr, "radius initialization error\n");
		exit(1);
	}

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
		fprintf(stderr, "error reading the radius dictionary\n");
		exit(1);
	}

	return;
}

static void radius_global_deinit()
{
	if (rh != NULL)
		rc_destroy(rh);
}

static int radius_auth_init(void **ctx, void *pool, const char *username, const char *ip,
			   void *additional)
{
	struct radius_ctx_st *pctx;
	char *default_realm;

	pctx = talloc_zero(pool, struct radius_ctx_st);
	if (pctx == NULL)
		return ERR_AUTH_FAIL;

	snprintf(pctx->username, sizeof(pctx->username), "%s", username);
	pctx->config = additional;
	pctx->pass_msg = pass_msg_first;

	default_realm = rc_conf_str(rh, "default_realm");
	
	if ((strchr(username, '@') == NULL) && default_realm &&
	    default_realm[0] != 0) {
		snprintf(pctx->username, sizeof(pctx->username), "%s@%s", username, default_realm);
	} else {
		strcpy(pctx->username, username);
	}


	*ctx = pctx;

	return 0;
}

static int radius_auth_group(void *ctx, const char *suggested, char *groupname, int groupname_size)
{
	struct radius_ctx_st *pctx = ctx;

	groupname[0] = 0;

	if (suggested != NULL) {
		if (strcmp(suggested, pctx->groupname) == 0) {
			snprintf(groupname, groupname_size, "%s", pctx->groupname);
			return 0;
		}

		syslog(LOG_AUTH,
		       "user '%s' requested group '%s' but is not a member",
		       pctx->username, suggested);
		return -1;
	}

	if (pctx->groupname[0] != 0 && groupname[0] == 0) {
		snprintf(groupname, groupname_size, "%s", pctx->groupname);
	}
	return 0;
}

static int radius_auth_user(void *ctx, char *username, int username_size)
{
	/* do not update username */
	return -1;
}

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int radius_auth_pass(void *ctx, const char *pass, unsigned pass_len)
{
	struct radius_ctx_st *pctx = ctx;
	VALUE_PAIR *send = NULL, *recvd = NULL;
	uint32_t service;
	int ret;

	syslog(LOG_DEBUG, "communicating username (%s) and password to radius", pctx->username);
	if (rc_avpair_add(rh, &send, PW_USER_NAME, pctx->username, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: user '%s' auth error", __func__, __LINE__,
		       pctx->username);
		return ERR_AUTH_FAIL;
	}

	if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, (char*)pass, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: user '%s' auth error", __func__, __LINE__,
		       pctx->username);
		return ERR_AUTH_FAIL;
	}

	service = PW_AUTHENTICATE_ONLY;
	if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: user '%s' auth error", __func__, __LINE__,
		       pctx->username);
		return ERR_AUTH_FAIL;
	}

	ret = rc_aaa(rh, 0, send, &recvd, pctx->msg, 1, PW_ACCESS_REQUEST);

	if (ret == OK_RC) {
		VALUE_PAIR *vp = recvd;
		while(vp != NULL) {
			if (vp->attribute == PW_SERVICE_TYPE && vp->lvalue != PW_FRAMED) {
				syslog(LOG_ERR,
				       "%s:%u: unknown radius service type '%d'", __func__, __LINE__,
				       (int)vp->lvalue);
				goto fail;
			} else if (vp->attribute == RAD_GROUP_NAME && vp->type == PW_TYPE_STRING) {
				snprintf(pctx->groupname, sizeof(pctx->groupname), "%s", vp->strvalue);
			} else if (vp->attribute == PW_FRAMED_IP_ADDRESS && vp->type == PW_TYPE_IPADDR) {
				inet_ntop(AF_INET, &vp->lvalue, pctx->ipv4, sizeof(pctx->ipv4));
			} else {
				syslog(LOG_DEBUG, "radius: ignoring server's value %u of type %u", (int)vp->attribute, (int)vp->type);
			}
			vp = vp->next;
		}

		if (recvd != NULL)
			rc_avpair_free(recvd);
		return 0;
	} else {
 fail:
		if (recvd != NULL)
			rc_avpair_free(recvd);

		if (ret == PW_ACCESS_CHALLENGE) {
			pctx->pass_msg = pass_msg_second;
			return ERR_AUTH_CONTINUE;
		} else if ( pctx->retries++ < MAX_TRIES) {
			pctx->pass_msg = pass_msg_failed;
			return ERR_AUTH_CONTINUE;
		} else {
			syslog(LOG_AUTH,
			       "radius-auth: error authenticating user '%s'",
			       pctx->username);
			return ERR_AUTH_FAIL;
		}
	}
}

static int radius_auth_msg(void *ctx, char *msg, size_t msg_size)
{
	struct radius_ctx_st *pctx = ctx;

	snprintf(msg, msg_size, "%s", pctx->pass_msg);
	return 0;
}

static void radius_auth_deinit(void *ctx)
{
	struct radius_ctx_st *pctx = ctx;
	talloc_free(pctx);
}


static int radius_auth_open_session(void* ctx)
{
struct radius_ctx_st * pctx = ctx;
int ret;
uint32_t status_type;
VALUE_PAIR *send = NULL, *recvd = NULL;

	status_type = PW_STATUS_START;

	syslog(LOG_DEBUG, "opening session with radius");
	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL)
		return -1;

	ret = rc_aaa(rh, 0, send, &recvd, pctx->msg, 1, PW_ACCOUNTING_REQUEST);
	if (recvd != NULL)
		rc_avpair_free(recvd);

	if (ret != OK_RC) {
		syslog(LOG_AUTH, "radius-auth: radius_open_session: %d", ret);
		return -1;
	}

	return 0;
}

static void radius_auth_close_session(void* ctx)
{
struct radius_ctx_st * pctx = ctx;
int ret;
uint32_t status_type;
VALUE_PAIR *send = NULL, *recvd = NULL;

	status_type = PW_STATUS_STOP;

	syslog(LOG_DEBUG, "closing session with radius");
	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL)
		return;

	ret = rc_aaa(rh, 0, send, &recvd, pctx->msg, 1, PW_ACCOUNTING_REQUEST);
	if (recvd != NULL)
		rc_avpair_free(recvd);

	if (ret != OK_RC) {
		syslog(LOG_INFO, "radius-auth: radius_close_session: %d", ret);
		return;
	}

	return;
}

const struct auth_mod_st radius_auth_funcs = {
	.type = AUTH_TYPE_RADIUS | AUTH_TYPE_USERNAME_PASS,
	.global_init = radius_global_init,
	.global_deinit = radius_global_deinit,
	.auth_init = radius_auth_init,
	.auth_deinit = radius_auth_deinit,
	.auth_msg = radius_auth_msg,
	.auth_pass = radius_auth_pass,
	.auth_user = radius_auth_user,
	.auth_group = radius_auth_group,
	.open_session = radius_auth_open_session,
	.close_session = radius_auth_close_session,
	.group_list = NULL
};

#endif
