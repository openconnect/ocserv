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
#define RAD_IPV4_DNS1 ((311<<16)|(28))
#define RAD_IPV4_DNS2 ((311<<16)|(29))

static rc_handle *rh = NULL;

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

	strlcpy(pctx->username, username, sizeof(pctx->username));
	strlcpy(pctx->remote_ip, ip, sizeof(pctx->remote_ip));
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
			strlcpy(groupname, pctx->groupname, groupname_size);
			return 0;
		}

		syslog(LOG_AUTH,
		       "user '%s' requested group '%s' but is not a member",
		       pctx->username, suggested);
		return -1;
	}

	if (pctx->groupname[0] != 0 && groupname[0] == 0) {
		strlcpy(groupname, pctx->groupname, groupname_size);
	}
	return 0;
}

static int radius_auth_user(void *ctx, char *username, int username_size)
{
	/* do not update username */
	return -1;
}

static void append_route(struct radius_ctx_st *pctx, const char *route, unsigned len)
{
	unsigned i;
	char *p;

	/* accept route/mask */
	if ((p=strchr(route, '/')) == 0)
		return;

	p = strchr(p, ' ');
	if (p != NULL) {
		len = p - route;
	}

	if (pctx->routes_size == 0) {
		pctx->routes = talloc_size(pctx, sizeof(char*));
	} else {
		pctx->routes = talloc_realloc_size(pctx, pctx->routes,
						   (pctx->routes_size+1)*sizeof(char*));
	}

	if (pctx->routes != NULL) {
		i = pctx->routes_size;
		pctx->routes[i] = talloc_strndup(pctx, route, len);
		if (pctx->routes[i] != NULL)
			pctx->routes_size++;
	}
}

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int radius_auth_pass(void *ctx, const char *pass, unsigned pass_len)
{
	struct radius_ctx_st *pctx = ctx;
	VALUE_PAIR *send = NULL, *recvd = NULL;
	uint32_t service;
	uint8_t ip[16];
	char route[64];
	char txt[64];
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
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	if (rc_avpair_add(rh, &send, PW_CALLING_STATION_ID, pctx->remote_ip, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: user '%s' auth error", __func__, __LINE__,
		       pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	service = PW_AUTHENTICATE_ONLY;
	if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: user '%s' auth error", __func__, __LINE__,
		       pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	ret = rc_aaa(rh, 0, send, &recvd, NULL, 1, PW_ACCESS_REQUEST);

	if (ret == OK_RC) {
		VALUE_PAIR *vp = recvd;
		uint32_t ipv4;
		uint8_t ipv6[16];
		while(vp != NULL) {
			if (vp->attribute == PW_SERVICE_TYPE && vp->lvalue != PW_FRAMED) {
				syslog(LOG_ERR,
				       "%s:%u: unknown radius service type '%d'", __func__, __LINE__,
				       (int)vp->lvalue);
				goto fail;
			} else if (vp->attribute == RAD_GROUP_NAME && vp->type == PW_TYPE_STRING) {
				/* Group-Name */
				strlcpy(pctx->groupname, vp->strvalue, sizeof(pctx->groupname));
			} else if (vp->attribute == PW_FRAMED_IPV6_ADDRESS && vp->type == PW_TYPE_IPV6ADDR) {
				/* Framed-IPv6-Address */
				if (inet_ntop(AF_INET6, vp->strvalue, pctx->ipv6, sizeof(pctx->ipv6)) != NULL) {
					pctx->ipv6_prefix = 64;
					strlcpy(pctx->ipv6_net, pctx->ipv6, sizeof(pctx->ipv6_net));
				}
			} else if (vp->attribute == PW_FRAMED_IPV6_PREFIX && vp->type == PW_TYPE_IPV6PREFIX) {
				if (vp->lvalue > 2 && vp->lvalue <= 18) {
					/* Framed-IPv6-Prefix */
					memset(ipv6, 0, sizeof(ipv6)); 
					memcpy(ipv6, vp->strvalue+2, vp->lvalue-2); 
					if (inet_ntop(AF_INET6, ip, txt, sizeof(txt)) != NULL) {
						snprintf(route, sizeof(route), "%s/%u", txt, (unsigned)(unsigned char)vp->strvalue[1]);
						append_route(pctx, vp->strvalue, vp->lvalue);
					}
				}
			} else if (vp->attribute == PW_DNS_SERVER_IPV6_ADDRESS && vp->type == PW_TYPE_IPV6ADDR) {
				/* DNS-Server-IPv6-Address */
				if (pctx->ipv6_dns1[0] == 0)
					inet_ntop(AF_INET6, vp->strvalue, pctx->ipv6_dns1, sizeof(pctx->ipv6_dns1));
				else
					inet_ntop(AF_INET6, vp->strvalue, pctx->ipv6_dns2, sizeof(pctx->ipv6_dns2));
			} else if (vp->attribute == PW_FRAMED_IP_ADDRESS && vp->type == PW_TYPE_IPADDR) {
				/* Framed-IP-Address */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4, sizeof(pctx->ipv4));
			} else if (vp->attribute == PW_FRAMED_IP_NETMASK && vp->type == PW_TYPE_IPADDR) {
				/* Framed-IP-Netmask */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4_mask, sizeof(pctx->ipv4_mask));
			} else if (vp->attribute == RAD_IPV4_DNS1 && vp->type == PW_TYPE_IPADDR) {
				/* MS-Primary-DNS-Server */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4_dns1, sizeof(pctx->ipv4_dns1));
			} else if (vp->attribute == RAD_IPV4_DNS2 && vp->type == PW_TYPE_IPADDR) {
				/* MS-Secondary-DNS-Server */
				ipv4 = htonl(vp->lvalue);
				inet_ntop(AF_INET, &ipv4, pctx->ipv4_dns2, sizeof(pctx->ipv4_dns2));
			} else if (vp->attribute == PW_FRAMED_ROUTE && vp->type == PW_TYPE_STRING) {
				/* Framed-Route */
				append_route(pctx, vp->strvalue, vp->lvalue);
			} else if (vp->attribute == PW_FRAMED_IPV6_ROUTE && vp->type == PW_TYPE_STRING) {
				/* Framed-IPv6-Route */
				append_route(pctx, vp->strvalue, vp->lvalue);
			} else {
				syslog(LOG_DEBUG, "radius: ignoring server's value %u of type %u", (int)vp->attribute, (int)vp->type);
			}
			vp = vp->next;
		}

		ret = 0;
 cleanup:
		rc_avpair_free(send);
		if (recvd != NULL)
			rc_avpair_free(recvd);
		return ret;
	} else {
 fail:
		if (send != NULL)
			rc_avpair_free(send);

		if (recvd != NULL)
			rc_avpair_free(recvd);

		if (ret == PW_ACCESS_CHALLENGE) {
			pctx->pass_msg = pass_msg_second;
			return ERR_AUTH_CONTINUE;
		} else if (pctx->retries++ < MAX_TRIES-1) {
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

	strlcpy(msg, pctx->pass_msg, msg_size);
	return 0;
}

static void radius_auth_deinit(void *ctx)
{
	struct radius_ctx_st *pctx = ctx;
	talloc_free(pctx);
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

static void append_acct_standard(struct radius_ctx_st * pctx, rc_handle *rh,
			    VALUE_PAIR **send)
{
	int i;

	if (rc_avpair_add(rh, send, PW_USER_NAME, pctx->username, -1, 0) == NULL) {
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

	if (pctx->ipv4[0] != 0) {
		struct in_addr in;
		inet_pton(AF_INET, pctx->ipv4, &in);
		in.s_addr = ntohl(in.s_addr);
		if (rc_avpair_add(rh, send, PW_FRAMED_IP_ADDRESS, &in, sizeof(in), 0) == NULL) {
			return;
		}
	}

	if (pctx->ipv6[0] != 0) {
		struct in6_addr in;
		inet_pton(AF_INET6, pctx->ipv6, &in);
		if (rc_avpair_add(rh, send, PW_FRAMED_IPV6_ADDRESS, &in, sizeof(in), 0) == NULL) {
			return;
		}
	}

	if (rc_avpair_add(rh, send, PW_ACCT_SESSION_ID, pctx->sid, -1, 0) == NULL) {
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

static void radius_auth_session_stats(void* ctx, stats_st *stats)
{
struct radius_ctx_st * pctx = ctx;
int ret;
uint32_t status_type;
VALUE_PAIR *send = NULL, *recvd = NULL;

	status_type = PW_STATUS_ALIVE;

	syslog(LOG_DEBUG, "sending radius session interim update");

	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL) {
		ret = -1;
		goto cleanup;
	}

	append_acct_standard(pctx, rh, &send);
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

static int radius_auth_open_session(void* ctx, const void *sid, unsigned sid_size)
{
struct radius_ctx_st * pctx = ctx;
int ret;
uint32_t status_type;
VALUE_PAIR *send = NULL, *recvd = NULL;

	status_type = PW_STATUS_START;

	if (sid_size != SID_SIZE) {
		syslog(LOG_DEBUG, "incorrect sid size");
		return -1;
	}

	base64_encode((char *)sid, sid_size, (char *)pctx->sid, sizeof(pctx->sid));

	syslog(LOG_DEBUG, "opening session %s with radius", pctx->sid);

	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL) {
		ret = -1;
		goto cleanup;
	}

	append_acct_standard(pctx, rh, &send);

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

static void radius_auth_close_session(void* ctx, stats_st *stats)
{
struct radius_ctx_st * pctx = ctx;
int ret;
uint32_t status_type;
VALUE_PAIR *send = NULL, *recvd = NULL;

	status_type = PW_STATUS_STOP;

	syslog(LOG_DEBUG, "closing session with radius");
	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL)
		return;

	ret = PW_USER_REQUEST;
	if (rc_avpair_add(rh, &send, PW_ACCT_TERMINATE_CAUSE, &ret, -1, 0) == NULL) {
		goto cleanup;
	}

	append_acct_standard(pctx, rh, &send);
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
	.session_stats = radius_auth_session_stats,
	.group_list = NULL
};

#endif
