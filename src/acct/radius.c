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
#include <sec-mod-acct.h>
#include "auth/radius.h"
#include "acct/radius.h"
#include "cfg.h"

static rc_handle *rh = NULL;
static char nas_identifier[64];

static void acct_radius_global_init(void *pool, void *additional)
{
	radius_cfg_st *config = additional;

	if (config == NULL)
		goto fail;

	rh = rc_read_config(config->config);
	if (rh == NULL)
		goto fail;

	if (config->nas_identifier) {
		strlcpy(nas_identifier, config->nas_identifier, sizeof(nas_identifier));
	} else {
		nas_identifier[0] = 0;
	}

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
		fprintf(stderr, "error reading the radius dictionary\n");
		exit(1);
	}

	return;
 fail:
 	fprintf(stderr, "radius acct initialization error\n");
	exit(1);

}

static void acct_radius_global_deinit(void)
{
	if (rh != NULL)
		rc_destroy(rh);
}

static void append_stats(rc_handle *rh, VALUE_PAIR **send, stats_st *stats)
{
uint32_t uin, uout;

	if (stats->uptime) {
		uin = stats->uptime;
		if (rc_avpair_add(rh, send, PW_ACCT_SESSION_TIME, &uin, -1, 0) == NULL) {
			return;
		}
	}

	uin = stats->bytes_in;
	uout = stats->bytes_out;

	if (rc_avpair_add(rh, send, PW_ACCT_INPUT_OCTETS, &uin, -1, 0) == NULL) {
		return;
	}

	if (rc_avpair_add(rh, send, PW_ACCT_OUTPUT_OCTETS, &uout, -1, 0) == NULL) {
		return;
	}

	uin = stats->bytes_in / 4294967296;
	if (rc_avpair_add(rh, send, PW_ACCT_INPUT_GIGAWORDS, &uin, -1, 0) == NULL) {
		return;
	}

	uout = stats->bytes_in / 4294967296;
	if (rc_avpair_add(rh, send, PW_ACCT_OUTPUT_GIGAWORDS, &uout, -1, 0) == NULL) {
		return;
	}

	return;
}

static void append_acct_standard(rc_handle *rh, const common_auth_info_st *ai, VALUE_PAIR **send)
{
	int i;

	if (nas_identifier[0] != 0) {
		if (rc_avpair_add(rh, send, PW_NAS_IDENTIFIER, nas_identifier, -1, 0) == NULL) {
			return;
		}
	}

	if (rc_avpair_add(rh, send, PW_USER_NAME, ai->username, -1, 0) == NULL) {
		return;
	}

	i = PW_FRAMED;
	if (rc_avpair_add(rh, send, PW_SERVICE_TYPE, &i, -1, 0) == NULL) {
		return;
	}

	i = PW_PPP;
	if (rc_avpair_add(rh, send, PW_FRAMED_PROTOCOL, &i, -1, 0) == NULL) {
		return;
	}

	if (ai->ipv4[0] != 0) {
		struct in_addr in;
		inet_pton(AF_INET, ai->ipv4, &in);
		in.s_addr = ntohl(in.s_addr);
		if (rc_avpair_add(rh, send, PW_FRAMED_IP_ADDRESS, &in, sizeof(in), 0) == NULL) {
			return;
		}
	}

#if 0 /* bug in freeradius-client */
	if (ai->ipv6[0] != 0) {
		struct in6_addr in;
		inet_pton(AF_INET6, ai->ipv6, &in);
		if (rc_avpair_add(rh, send, PW_FRAMED_IPV6_ADDRESS, &in, sizeof(in), 0) == NULL) {
			return;
		}
	}
#endif

	if (rc_avpair_add(rh, send, PW_CALLING_STATION_ID, ai->remote_ip, -1, 0) == NULL) {
		return;
	}

	if (rc_avpair_add(rh, send, PW_ACCT_SESSION_ID, ai->psid, -1, 0) == NULL) {
		return;
	}

	i = PW_RADIUS;
	if (rc_avpair_add(rh, send, PW_ACCT_AUTHENTIC, &i, -1, 0) == NULL) {
		return;
	}

	i = PW_ASYNC;
	if (rc_avpair_add(rh, send, PW_NAS_PORT_TYPE, &i, -1, 0) == NULL) {
		return;
	}

	return;
}

static void radius_acct_session_stats(unsigned auth_method, void *ctx, const common_auth_info_st *ai, stats_st *stats)
{
int ret;
uint32_t status_type;
VALUE_PAIR *send = NULL, *recvd = NULL;

	status_type = PW_STATUS_ALIVE;

	syslog(LOG_DEBUG, "radius-auth: sending session interim update");

	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL) {
		ret = -1;
		goto cleanup;
	}

	append_acct_standard(rh, ai, &send);
	append_stats(rh, &send, stats);

	ret = rc_aaa(rh, 0, send, &recvd, NULL, 1, PW_ACCOUNTING_REQUEST);

	if (recvd != NULL)
		rc_avpair_free(recvd);

	if (ret != OK_RC) {
		syslog(LOG_AUTH, "radius-auth: radius_open_session: %d", ret);
		goto cleanup;
	}

 cleanup:
	rc_avpair_free(send);
	return;
}

static int radius_acct_open_session(unsigned auth_method, void *ctx, const common_auth_info_st *ai, const void *sid, unsigned sid_size)
{
int ret;
uint32_t status_type;
VALUE_PAIR *send = NULL, *recvd = NULL;

	status_type = PW_STATUS_START;

	if (sid_size != SID_SIZE) {
		syslog(LOG_DEBUG, "radius-auth: incorrect sid size");
		return -1;
	}

	syslog(LOG_DEBUG, "radius-auth: opening session %s", ai->psid);

	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL) {
		ret = -1;
		goto cleanup;
	}

	append_acct_standard(rh, ai, &send);

	ret = rc_aaa(rh, 0, send, &recvd, NULL, 1, PW_ACCOUNTING_REQUEST);

	if (recvd != NULL)
		rc_avpair_free(recvd);

	if (ret != OK_RC) {
		syslog(LOG_AUTH, "radius-auth: radius_open_session: %d", ret);
		ret = -1;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	rc_avpair_free(send);
	return ret;
}

static void radius_acct_close_session(unsigned auth_method, void *ctx, const common_auth_info_st *ai, stats_st *stats)
{
int ret;
uint32_t status_type;
VALUE_PAIR *send = NULL, *recvd = NULL;

	status_type = PW_STATUS_STOP;

	syslog(LOG_DEBUG, "radius-auth: closing session");
	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL)
		return;

	ret = PW_USER_REQUEST;
	if (rc_avpair_add(rh, &send, PW_ACCT_TERMINATE_CAUSE, &ret, -1, 0) == NULL) {
		goto cleanup;
	}

	append_acct_standard(rh, ai, &send);
	append_stats(rh, &send, stats);

	ret = rc_aaa(rh, 0, send, &recvd, NULL, 1, PW_ACCOUNTING_REQUEST);
	if (recvd != NULL)
		rc_avpair_free(recvd);

	if (ret != OK_RC) {
		syslog(LOG_INFO, "radius-auth: radius_close_session: %d", ret);
		goto cleanup;
	}

 cleanup:
 	rc_avpair_free(send);
	return;
}

const struct acct_mod_st radius_acct_funcs = {
	.type = ACCT_TYPE_RADIUS,
	.auth_types = ALL_AUTH_TYPES,
	.global_init = acct_radius_global_init,
	.global_deinit = acct_radius_global_deinit,
	.open_session = radius_acct_open_session,
	.close_session = radius_acct_close_session,
	.session_stats = radius_acct_session_stats
};

#endif
