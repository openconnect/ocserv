/*
 * Copyright (C) 2015 Red Hat, Inc.
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
#include "gssapi.h"
#include "auth/common.h"
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <gl/base64.h>

#define MAX_MSG_SIZE 256

#ifdef HAVE_GSSAPI

static gss_cred_id_t glob_creds;
gss_OID_set glob_oids;

struct gssapi_ctx_st {
	char username[MAX_USERNAME_SIZE];
	gss_ctx_id_t gssctx;

	gss_cred_id_t delegated_creds;
	gss_buffer_desc msg;
};

static void gssapi_global_init(void *pool, void *additional)
{
	int ret;
	OM_uint32 time, minor;
	gss_name_t name = GSS_C_NO_NAME;

	if (additional && strncmp(additional, "keytab:", 7) == 0) {
		gss_key_value_element_desc element;
		gss_key_value_set_desc cred_store;

		element.key = "keytab";
		element.value = additional+7;
		cred_store.count = 1;
		cred_store.elements = &element;

		ret = gss_acquire_cred_from(&minor, name, 0, GSS_C_NO_OID_SET, 2,
			&cred_store, &glob_creds, &glob_oids, &time);
	} else {
		ret = gss_acquire_cred(&minor, name, 0, GSS_C_NO_OID_SET, 2,
			&glob_creds, &glob_oids, &time);
	}

	if (ret != GSS_S_COMPLETE) {
		ret = -1;
		syslog(LOG_ERR, "gssapi: error in gss_acquire_cred[%s]: %d", (name==GSS_C_NO_NAME)?"default":(char*)additional, ret);
		exit(1);
	}

	if (name != GSS_C_NO_NAME)
		gss_release_name(&minor, &name);

	return;
}

static void gssapi_global_deinit()
{
	OM_uint32 minor;

	if (glob_creds != NULL)
		gss_release_cred(&minor, &glob_creds);
}

static void get_name(struct gssapi_ctx_st *pctx, gss_name_t client, gss_OID mech_type)
{
	int ret;
	OM_uint32 minor;
	gss_buffer_desc name;

	pctx->username[0] = 0;

	ret = gss_display_name(&minor, client, &name, NULL);
	if (GSS_ERROR(ret)) {
		syslog(LOG_ERR, "gssapi: error in gss_display_name: %d", ret);
		return;
	}

	syslog(LOG_DEBUG, "gssapi: full username %.*s", (unsigned)name.length, (char*)name.value);
	gss_release_buffer(&minor, &name);

	ret = gss_localname(&minor, client, mech_type, &name);
	if (GSS_ERROR(ret) || name.length >= MAX_USERNAME_SIZE) {
		syslog(LOG_ERR, "gssapi: error in gss_display_name: %d", ret);
		return;
	}

	syslog(LOG_DEBUG, "gssapi: username %.*s", (unsigned)name.length, (char*)name.value);

	memcpy(pctx->username, name.value, name.length);
	pctx->username[name.length] = 0;
	gss_release_buffer(&minor, &name);

	return;
}

static int gssapi_auth_init(void **ctx, void *pool, const char *spnego, const char *ip,
			   void *additional)
{
	struct gssapi_ctx_st *pctx;
	OM_uint32 minor, flags, time;
	gss_buffer_desc buf;
	gss_name_t client = GSS_C_NO_NAME;
	gss_OID mech_type = GSS_C_NO_OID;
	int ret;
	size_t raw_len;
	char *raw;

	if (spnego == NULL || spnego[0] == 0) {
		syslog(LOG_ERR, "gssapi: error in spnego data %s", __func__);
		return ERR_AUTH_FAIL;
	}

	pctx = talloc_zero(pool, struct gssapi_ctx_st);
	if (pctx == NULL)
		return ERR_AUTH_FAIL;

	ret = base64_decode_alloc(spnego, strlen(spnego), &raw, &raw_len);
	if (ret == 0) {
		syslog(LOG_ERR, "gssapi: error in base64 decoding %s", __func__);
		return ERR_AUTH_FAIL;
	}

	buf.value = raw;
	buf.length = raw_len;
	ret = gss_accept_sec_context(&minor, &pctx->gssctx, glob_creds, &buf,
		GSS_C_NO_CHANNEL_BINDINGS, &client, &mech_type, &pctx->msg,
		&flags, &time, &pctx->delegated_creds);
	free(raw);

	if (ret == GSS_S_CONTINUE_NEEDED) {
		gss_release_name(&minor, &client);
		ret = ERR_AUTH_CONTINUE;
	} else if (ret == GSS_S_COMPLETE) {
		get_name(pctx, client, mech_type);
		gss_release_name(&minor, &client);
		ret = 0;
	} else {
		syslog(LOG_ERR, "gssapi: error in gss_accept_sec_context: %d", ret);
		return ERR_AUTH_FAIL;
	}

	*ctx = pctx;

	return ret;
}

static int gssapi_auth_group(void *ctx, const char *suggested, char *groupname, int groupname_size)
{
	groupname[0] = 0;
	return 0;
}

static int gssapi_auth_user(void *ctx, char *username, int username_size)
{
	struct gssapi_ctx_st *pctx = ctx;

	strlcpy(username, pctx->username, username_size);
	return -1;
}

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int gssapi_auth_pass(void *ctx, const char *spnego, unsigned spnego_len)
{
	struct gssapi_ctx_st *pctx = ctx;
	OM_uint32 minor, flags, time;
	gss_buffer_desc buf;
	gss_name_t client = GSS_C_NO_NAME;
	gss_OID mech_type = GSS_C_NO_OID;
	size_t raw_len;
	char *raw;
	int ret;

	/* nothing to be done */
	ret = base64_decode_alloc(spnego, spnego_len, &raw, &raw_len);
	if (ret == 0) {
		syslog(LOG_ERR, "gssapi: error in base64 decoding %s", __func__);
		return ERR_AUTH_FAIL;
	}

	buf.value = raw;
	buf.length = raw_len;
	ret = gss_accept_sec_context(&minor, &pctx->gssctx, glob_creds, &buf,
		GSS_C_NO_CHANNEL_BINDINGS, &client, &mech_type, &pctx->msg,
		&flags, &time, &pctx->delegated_creds);
	free(raw);

	if (ret == GSS_S_CONTINUE_NEEDED) {
		gss_release_name(&minor, &client);
		return ERR_AUTH_CONTINUE;
	} else if (ret == GSS_S_COMPLETE) {
		get_name(pctx, client, mech_type);
		gss_release_name(&minor, &client);
		return 0;
	} else {
		syslog(LOG_ERR, "gssapi: error in gss_accept_sec_context: %d", ret);
		return ERR_AUTH_FAIL;
	}
}

static int gssapi_auth_msg(void *ctx, char *msg, size_t msg_size)
{
	struct gssapi_ctx_st *pctx = ctx;
	OM_uint32 min;

	/* our msg is our SPNEGO reply */
	if (pctx->msg.value != NULL) {
		base64_encode((char *)pctx->msg.value, pctx->msg.length, (char *)msg, msg_size);
		gss_release_buffer(&min, &pctx->msg);
		pctx->msg.value = NULL;
	} else {
		msg[0] = 0;
	}
	return 0;
}

static void gssapi_auth_deinit(void *ctx)
{
	struct gssapi_ctx_st *pctx = ctx;
	OM_uint32 min;

	gss_delete_sec_context(&min, &pctx->gssctx, GSS_C_NO_BUFFER);
	gss_release_cred(&min, &pctx->delegated_creds);
	gss_release_buffer(&min, &pctx->msg);
	talloc_free(ctx);
}

const struct auth_mod_st gssapi_auth_funcs = {
	.type = AUTH_TYPE_GSSAPI,
	.auth_init = gssapi_auth_init,
	.auth_deinit = gssapi_auth_deinit,
	.auth_msg = gssapi_auth_msg,
	.auth_pass = gssapi_auth_pass,
	.auth_user = gssapi_auth_user,
	.auth_group = gssapi_auth_group,
	.global_init = gssapi_global_init,
	.global_deinit = gssapi_global_deinit,
};

#endif
