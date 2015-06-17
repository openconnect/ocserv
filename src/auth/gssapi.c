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

#ifdef HAVE_GSSAPI

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <vpn.h>
#include <c-ctype.h>
#include "gssapi.h"
#include "auth/common.h"
#include "auth-unix.h"
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <gl/base64.h>
#include "common-config.h"

static gss_cred_id_t glob_creds;
static gss_OID_set glob_oids;
static unsigned no_local_map = 0;
static time_t ticket_freshness_secs = 0;

struct gssapi_ctx_st {
	char username[MAX_USERNAME_SIZE];
	gss_ctx_id_t gssctx;

	gss_cred_id_t delegated_creds;
	gss_buffer_desc msg;
};

/* Taken from openconnect's gssapi */
static void print_gss_err(const char *where,
			  gss_OID mech, OM_uint32 err_maj,
			  OM_uint32 err_min)
{
	OM_uint32 major, minor, msg_ctx = 0;
	gss_buffer_desc status = GSS_C_EMPTY_BUFFER;

	do {
		major = gss_display_status(&minor, err_maj, GSS_C_GSS_CODE,
					   mech, &msg_ctx, &status);
		if (GSS_ERROR(major))
			break;
		syslog(LOG_ERR, "gssapi: %s[maj]: %s\n", where, (char *)status.value);
		gss_release_buffer(&minor, &status);
	} while (msg_ctx);

	msg_ctx = 0;
	do {
		major = gss_display_status(&minor, err_min, GSS_C_MECH_CODE,
					   mech, &msg_ctx, &status);
		if (GSS_ERROR(major))
			break;
		syslog(LOG_ERR, "gssapi: %s[min]: %s\n", where, (char *)status.value);
		gss_release_buffer(&minor, &status);
	} while (msg_ctx);
}

const gss_OID_desc spnego_mech = {6, (void *)"\x2b\x06\x01\x05\x05\x02"};
const gss_OID_set_desc desired_mechs = { 
	.count = 1,
	.elements = (gss_OID)&spnego_mech
};

static void gssapi_global_init(void *pool, void *additional)
{
	int ret;
	OM_uint32 time, minor;
	gss_name_t name = GSS_C_NO_NAME;
	gssapi_cfg_st *config = additional;

	if (config) {
		no_local_map = config->no_local_map;
		ticket_freshness_secs = config->ticket_freshness_secs;
	}

	if (config && config->keytab) {
		gss_key_value_element_desc element;
		gss_key_value_set_desc cred_store;

		element.key = "keytab";
		element.value = config->keytab;
		cred_store.count = 1;
		cred_store.elements = &element;

		ret = gss_acquire_cred_from(&minor, name, 0, (gss_OID_set)&desired_mechs, 2,
			&cred_store, &glob_creds, &glob_oids, &time);

		if (ret != GSS_S_COMPLETE) {
			ret = -1;
			print_gss_err("gss_acquire_cred(keytab)", GSS_C_NO_OID, ret, minor);
			exit(1);
		}
	} else {
		ret = gss_acquire_cred(&minor, name, 0, (gss_OID_set)&desired_mechs, 2,
			&glob_creds, &glob_oids, &time);

		if (ret != GSS_S_COMPLETE) {
			ret = -1;
			print_gss_err("gss_acquire_cred", GSS_C_NO_OID, ret, minor);
			exit(1);
		}
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

static int get_name(struct gssapi_ctx_st *pctx, gss_name_t client, gss_OID mech_type)
{
	int ret;
	OM_uint32 minor;
	gss_buffer_desc name = GSS_C_EMPTY_BUFFER;

	pctx->username[0] = 0;

	ret = gss_display_name(&minor, client, &name, NULL);
	if (GSS_ERROR(ret)) {
		print_gss_err("gss_display_name", mech_type, ret, minor);
		return -1;
	}

	if (name.length < sizeof(pctx->username)) {
		memcpy(pctx->username, name.value, name.length);
		pctx->username[name.length] = 0;
	}

	syslog(LOG_DEBUG, "gssapi: authenticated GSSAPI user: %.*s", (unsigned)name.length, (char*)name.value);
	gss_release_buffer(&minor, &name);

	if (no_local_map == 0) {
		ret = gss_localname(&minor, client, mech_type, &name);
		if (GSS_ERROR(ret) || name.length >= MAX_USERNAME_SIZE) {
			print_gss_err("gss_localname", mech_type, ret, minor);
			syslog(LOG_INFO, "gssapi: authenticated user doesn't map to a local user");
			return -1;
		}

		memcpy(pctx->username, name.value, name.length);
		pctx->username[name.length] = 0;
		syslog(LOG_INFO, "gssapi: authenticated local user: %s", pctx->username);

		gss_release_buffer(&minor, &name);
	}

	if (pctx->username[0] == 0)
		return -1;
	else
		return 0;
}

static int verify_krb5_constraints(struct gssapi_ctx_st *pctx, gss_OID mech_type)
{
	int ret;
	OM_uint32 minor;
	krb5_timestamp authtime;

	if (mech_type == NULL ||
	   ((mech_type->length != gss_mech_krb5->length || memcmp(mech_type->elements, gss_mech_krb5->elements, mech_type->length) != 0) &&
	    (mech_type->length != gss_mech_krb5_old->length || memcmp(mech_type->elements, gss_mech_krb5_old->elements, mech_type->length) != 0)) ||
	    ticket_freshness_secs == 0) {
		return 0;
	}

	ret = gsskrb5_extract_authtime_from_sec_context (&minor, pctx->gssctx, &authtime);
	if (GSS_ERROR(ret)) {
		print_gss_err("gsskrb5_extract_authtime_from_sec_context", mech_type, ret, minor);
		return -1;
	}

	if (time(0) > authtime + ticket_freshness_secs) {
		syslog(LOG_INFO, "gssapi: the presented kerberos ticket for %s is too old", pctx->username);
		return -1;
	}

	return 0;
}

static int gssapi_auth_init(void **ctx, void *pool, const char *spnego, const char *ip, const char *our_ip, unsigned pid)
{
	struct gssapi_ctx_st *pctx;
	OM_uint32 minor, flags, time;
	gss_buffer_desc buf= GSS_C_EMPTY_BUFFER;
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
		ret = get_name(pctx, client, mech_type);
		gss_release_name(&minor, &client);
		if (ret < 0)
			return ret;

		ret = verify_krb5_constraints(pctx, mech_type);
	} else {
		print_gss_err("gss_accept_sec_context", mech_type, ret, minor);
		return ERR_AUTH_FAIL;
	}

	*ctx = pctx;

	return ret;
}

static int gssapi_auth_group(void *ctx, const char *suggested, char *groupname, int groupname_size)
{
	struct gssapi_ctx_st *pctx = ctx;

	return get_user_auth_group(pctx->username, suggested, groupname, groupname_size);
}

static int gssapi_auth_user(void *ctx, char *username, int username_size)
{
	struct gssapi_ctx_st *pctx = ctx;

	strlcpy(username, pctx->username, username_size);
	return 0;
}

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int gssapi_auth_pass(void *ctx, const char *spnego, unsigned spnego_len)
{
	struct gssapi_ctx_st *pctx = ctx;
	OM_uint32 minor, flags, time;
	gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
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
		ret = get_name(pctx, client, mech_type);
		gss_release_name(&minor, &client);
		if (ret < 0)
			return ret;

		ret = verify_krb5_constraints(pctx, mech_type);
		return ret;
	} else {
		print_gss_err("gss_accept_sec_context", mech_type, ret, minor);
		return ERR_AUTH_FAIL;
	}
}

static int gssapi_auth_msg(void *ctx, void *pool, passwd_msg_st *pst)
{
	struct gssapi_ctx_st *pctx = ctx;
	OM_uint32 min;
	unsigned length;

	/* our msg is our SPNEGO reply */
	if (pctx->msg.value != NULL) {
		length = BASE64_LENGTH(pctx->msg.length)+1;
		pst->msg_str = talloc_size(pool, length);

		base64_encode((char *)pctx->msg.value, pctx->msg.length, pst->msg_str, length);
		gss_release_buffer(&min, &pctx->msg);
		pctx->msg.value = NULL;
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

static void gssapi_group_list(void *pool, void *_additional, char ***groupname, unsigned *groupname_size)
{
	gssapi_cfg_st *config = _additional;
	gid_t min = 0;

	if (config)
		min = config->gid_min;

	unix_group_list(pool, min, groupname, groupname_size);
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
	.group_list = gssapi_group_list
};

#endif
