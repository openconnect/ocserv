/*
 * Copyright (C) 2014-2016 Red Hat, Inc.
 * Copyright (C) 2016 Nikos Mavrogiannopoulos
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
#include "str.h"

#ifdef HAVE_RADIUS

#include "common-config.h"

#ifdef LEGACY_RADIUS
# include <freeradius-client.h>
#else
# include <radcli/radcli.h>
#endif

#define RAD_GROUP_NAME PW_CLASS
#define RAD_IPV4_DNS1 ((311<<16)|(28))
#define RAD_IPV4_DNS2 ((311<<16)|(29))

#if defined(LEGACY_RADIUS)
# ifndef PW_DELEGATED_IPV6_PREFIX
#  define PW_DELEGATED_IPV6_PREFIX 123
# endif
# ifndef PW_ACCT_INTERIM_INTERVAL
#  define PW_ACCT_INTERIM_INTERVAL 85
# endif
#endif

#if RADCLI_VERSION_NUMBER < 0x010207
# define CHALLENGE_RC 3
#endif

static rc_handle *rh = NULL;
static char nas_identifier[64];

static void radius_global_init(void *pool, void *additional)
{
	radius_cfg_st *config = additional;

	if (config == NULL)
		goto fail;

	rh = rc_read_config(config->config);
	if (rh == NULL) {
		goto fail;
	}

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
	fprintf(stderr, "radius initialization error\n");
	exit(1);
}

static void radius_global_deinit()
{
	if (rh != NULL)
		rc_destroy(rh);
}

static int radius_auth_init(void **ctx, void *pool, const common_auth_init_st *info)
{
	struct radius_ctx_st *pctx;
	char *default_realm;

	if (info->username == NULL || info->username[0] == 0) {
		syslog(LOG_AUTH,
		       "radius-auth: no username present");
		return ERR_AUTH_FAIL;
	}

	pctx = talloc_zero(pool, struct radius_ctx_st);
	if (pctx == NULL)
		return ERR_AUTH_FAIL;

	if (info->ip)
		strlcpy(pctx->remote_ip, info->ip, sizeof(pctx->remote_ip));
	if (info->our_ip)
		strlcpy(pctx->our_ip, info->our_ip, sizeof(pctx->our_ip));

	pctx->pass_msg[0] = 0;

	default_realm = rc_conf_str(rh, "default_realm");

	if ((strchr(info->username, '@') == NULL) && default_realm &&
	    default_realm[0] != 0) {
		snprintf(pctx->username, sizeof(pctx->username), "%s@%s", info->username, default_realm);
	} else {
		strlcpy(pctx->username, info->username, sizeof(pctx->username));
	}
	pctx->id = info->id;

	if (info->user_agent)
		strlcpy(pctx->user_agent, info->user_agent, sizeof(pctx->user_agent));

	*ctx = pctx;

	return ERR_AUTH_CONTINUE;
}

static int radius_auth_group(void *ctx, const char *suggested, char *groupname, int groupname_size)
{
	struct radius_ctx_st *pctx = ctx;
	unsigned i;

	groupname[0] = 0;

	if (suggested != NULL) {
		for (i=0;i<pctx->groupnames_size;i++) {
			if (strcmp(suggested, pctx->groupnames[i]) == 0) {
				strlcpy(groupname, pctx->groupnames[i], groupname_size);
				return 0;
			}
		}

		syslog(LOG_AUTH,
		       "radius-auth: user '%s' requested group '%s' but is not a member",
		       pctx->username, suggested);
		return -1;
	}

	if (pctx->groupnames_size > 0 && groupname[0] == 0) {
		strlcpy(groupname, pctx->groupnames[0], groupname_size);
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

/* Parses group of format "OU=group1;group2;group3" */
static void parse_groupnames(struct radius_ctx_st *pctx, const char *full)
{
	char *p, *p2;
	unsigned i;

	pctx->groupnames_size = 0;

	if (strncmp(full, "OU=", 3) == 0) {
		full += 3;

		p = talloc_strdup(pctx, full);
		if (p == NULL)
			return;

		i = 0;
		p2 = strsep(&p, ";");
		while(p2 != NULL) {
			pctx->groupnames[i++] = p2;
			pctx->groupnames_size = i;

			trim_trailing_whitespace(p2);

			p2 = strsep(&p, ";"); 
		}
	} else {
		pctx->groupnames[0] = talloc_strdup(pctx, full);
		if (pctx->groupnames[0] == NULL)
			return;
		pctx->groupnames_size = 1;
	}
}

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int radius_auth_pass(void *ctx, const char *pass, unsigned pass_len)
{
	struct radius_ctx_st *pctx = ctx;
	VALUE_PAIR *send = NULL, *recvd = NULL;
	uint32_t service;
	char route[64];
	char txt[64];
	VALUE_PAIR *vp;
	int ret;

	/* send Access-Request */
	syslog(LOG_DEBUG, "radius-auth: communicating username (%s) and password", pctx->username);
	if (rc_avpair_add(rh, &send, PW_USER_NAME, pctx->username, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: error in constructing radius message for user '%s'", __func__, __LINE__,
		       pctx->username);
		return ERR_AUTH_FAIL;
	}

	if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, (char*)pass, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: error in constructing radius message for user '%s'", __func__, __LINE__,
		       pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	if (pctx->our_ip[0] != 0) {
		struct in_addr in;
		struct in6_addr in6;

		if (inet_pton(AF_INET, pctx->our_ip, &in) != 0) {
			in.s_addr = ntohl(in.s_addr);
			rc_avpair_add(rh, &send, PW_NAS_IP_ADDRESS, (char*)&in, sizeof(struct in_addr), 0);
		} else if (inet_pton(AF_INET6, pctx->our_ip, &in6) != 0) {
			rc_avpair_add(rh, &send, PW_NAS_IPV6_ADDRESS, (char*)&in6, sizeof(struct in6_addr), 0);
		}
	}

	if (nas_identifier[0] != 0) {
		if (rc_avpair_add(rh, &send, PW_NAS_IDENTIFIER, nas_identifier, -1, 0) == NULL) {
			syslog(LOG_ERR,
			       "%s:%u: error in constructing radius message for user '%s'", __func__, __LINE__,
			       pctx->username);
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
	}

	if (rc_avpair_add(rh, &send, PW_CALLING_STATION_ID, pctx->remote_ip, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: error in constructing radius message for user '%s'", __func__, __LINE__,
		       pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	if (pctx->user_agent[0] != 0) {
		if (rc_avpair_add(rh, &send, PW_CONNECT_INFO, pctx->user_agent, -1, 0) == NULL) {
			syslog(LOG_ERR,
			       "%s:%u: error in constructing radius message for user '%s'", __func__, __LINE__,
			       pctx->username);
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
	}

	service = PW_AUTHENTICATE_ONLY;
	if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: error in constructing radius message for user '%s'", __func__, __LINE__,
		       pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	service = PW_ASYNC;
	if (rc_avpair_add(rh, &send, PW_NAS_PORT_TYPE, &service, -1, 0) == NULL) {
		syslog(LOG_ERR,
		       "%s:%u: error in constructing radius message for user '%s'", __func__, __LINE__,
		       pctx->username);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	pctx->pass_msg[0] = 0;
	ret = rc_aaa(rh, pctx->id, send, &recvd, pctx->pass_msg, 1, PW_ACCESS_REQUEST);

	if (ret == OK_RC) {
		uint32_t ipv4;
		uint8_t ipv6[16];

		vp = recvd;

		while(vp != NULL) {
			if (vp->attribute == PW_SERVICE_TYPE && vp->lvalue != PW_FRAMED) {
				syslog(LOG_ERR,
				       "%s:%u: unknown radius service type '%d'", __func__, __LINE__,
				       (int)vp->lvalue);
				goto fail;
			} else if (vp->attribute == RAD_GROUP_NAME && vp->type == PW_TYPE_STRING) {
				/* Group-Name */
				parse_groupnames(pctx, vp->strvalue);
			} else if (vp->attribute == PW_FRAMED_IPV6_ADDRESS && vp->type == PW_TYPE_IPV6ADDR) {
				/* Framed-IPv6-Address */
				if (inet_ntop(AF_INET6, vp->strvalue, pctx->ipv6, sizeof(pctx->ipv6)) != NULL) {
					pctx->ipv6_subnet_prefix = 64;
					strlcpy(pctx->ipv6_net, pctx->ipv6, sizeof(pctx->ipv6_net));
				}
			} else if (vp->attribute == PW_DELEGATED_IPV6_PREFIX && vp->type == PW_TYPE_IPV6PREFIX) {
				/* Delegated-IPv6-Prefix */
				if (inet_ntop(AF_INET6, vp->strvalue, pctx->ipv6, sizeof(pctx->ipv6)) != NULL) {
					memset(ipv6, 0, sizeof(ipv6)); 
					memcpy(ipv6, vp->strvalue+2, vp->lvalue-2); 
					if (inet_ntop(AF_INET6, ipv6, pctx->ipv6, sizeof(pctx->ipv6)) != NULL) {
						pctx->ipv6_subnet_prefix = (unsigned)(unsigned char)vp->strvalue[1];
					}
				}
			} else if (vp->attribute == PW_FRAMED_IPV6_PREFIX && vp->type == PW_TYPE_IPV6PREFIX) {
				if (vp->lvalue > 2 && vp->lvalue <= 18) {
					/* Framed-IPv6-Prefix */
					memset(ipv6, 0, sizeof(ipv6)); 
					memcpy(ipv6, vp->strvalue+2, vp->lvalue-2); 
					if (inet_ntop(AF_INET6, ipv6, txt, sizeof(txt)) != NULL) {
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
				if (vp->lvalue != 0xffffffff && vp->lvalue != 0xfffffffe) {
					/* According to RFC2865 the values above (fe) instruct the
					 * server to assign an address from the pool of the server,
					 * and (ff) to assign address as negotiated with the client.
					 * We don't negotiate with clients.
					 */
					ipv4 = htonl(vp->lvalue);
					inet_ntop(AF_INET, &ipv4, pctx->ipv4, sizeof(pctx->ipv4));
				}
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
			} else if (vp->attribute == PW_ACCT_INTERIM_INTERVAL && vp->type == PW_TYPE_INTEGER) {
				pctx->interim_interval_secs = vp->lvalue;
			} else if (vp->attribute == PW_SESSION_TIMEOUT && vp->type == PW_TYPE_INTEGER) {
				pctx->session_timeout_secs = vp->lvalue;
			} else {
				syslog(LOG_DEBUG, "radius-auth: ignoring server's value %u of type %u", (int)vp->attribute, (int)vp->type);
			}
			vp = vp->next;
		}

		ret = 0;
		goto cleanup;
	} else {
 fail:
		if (pctx->pass_msg[0] == 0)
			strlcpy(pctx->pass_msg, pass_msg_failed, sizeof(pctx->pass_msg));

		if (pctx->retries++ < MAX_PASSWORD_TRIES-1) {
			ret = ERR_AUTH_CONTINUE;
			goto cleanup;
		}

		syslog(LOG_AUTH,
		       "radius-auth: error authenticating user '%s' (code %d)",
		       pctx->username, ret);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

 cleanup:
	if (send != NULL)
		rc_avpair_free(send);
	if (recvd != NULL)
		rc_avpair_free(recvd);
	return ret;
}

static int radius_auth_msg(void *ctx, void *pool, passwd_msg_st *pst)
{
	struct radius_ctx_st *pctx = ctx;

	if (pctx->pass_msg[0] != 0)
		pst->msg_str = talloc_strdup(pool, pctx->pass_msg);

	/* use default prompt */
	return 0;
}

static void radius_auth_deinit(void *ctx)
{
	struct radius_ctx_st *pctx = ctx;
	talloc_free(pctx);
}

const struct auth_mod_st radius_auth_funcs = {
	.type = AUTH_TYPE_RADIUS | AUTH_TYPE_USERNAME_PASS,
	.allows_retries = 1,
	.global_init = radius_global_init,
	.global_deinit = radius_global_deinit,
	.auth_init = radius_auth_init,
	.auth_deinit = radius_auth_deinit,
	.auth_msg = radius_auth_msg,
	.auth_pass = radius_auth_pass,
	.auth_user = radius_auth_user,
	.auth_group = radius_auth_group,
	.group_list = NULL
};

#endif
