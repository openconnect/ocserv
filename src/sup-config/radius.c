/*
 * Copyright (C) 2014 Red Hat, Inc.
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
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <ocserv-args.h>
#include <autoopts/options.h>
#include <limits.h>
#include <common.h>
#include <c-strcase.h>

#ifdef HAVE_RADIUS

#include <vpn.h>
#include <main.h>
#include <sec-mod-sup-config.h>
#include <auth/radius.h>

static int get_sup_config(struct cfg_st *cfg, client_entry_st *entry,
			  SecAuthSessionReplyMsg *msg, void *pool)
{
	struct radius_ctx_st *pctx = entry->auth_ctx;
	unsigned dns = 0, i;

	if (pctx == NULL)
		return 0;

	if (pctx->ipv4[0] != 0) {
		msg->explicit_ipv4 = talloc_strdup(pool, pctx->ipv4);
	}

	if (pctx->ipv4_mask[0] != 0) {
		msg->ipv4_netmask = talloc_strdup(pool, pctx->ipv4_mask);
	}

	if (pctx->routes_size > 0) {
		msg->routes = talloc_size(pool, pctx->routes_size*sizeof(char*));
		if (msg->routes != NULL) {
			for (i=0;i<pctx->routes_size;i++) {
				msg->routes[i] = talloc_strdup(pool, pctx->routes[i]);
			}
			msg->n_routes = pctx->routes_size;
		}
	}

	if (pctx->ipv4_dns1[0] != 0)
		dns++;
	if (pctx->ipv4_dns2[0] != 0)
		dns++;
	if (pctx->ipv6_dns1[0] != 0)
		dns++;
	if (pctx->ipv6_dns2[0] != 0)
		dns++;

	if (dns > 0) {
		msg->dns = talloc_size(pool, dns*sizeof(char*));
		if (msg->dns != NULL) {
			unsigned pos = 0;
			if (pctx->ipv4_dns1[0] != 0)
				msg->dns[pos++] = talloc_strdup(pool, pctx->ipv4_dns1);
			if (pctx->ipv4_dns2[0] != 0)
				msg->dns[pos++] = talloc_strdup(pool, pctx->ipv4_dns2);
			if (pctx->ipv6_dns1[0] != 0)
				msg->dns[pos++] = talloc_strdup(pool, pctx->ipv6_dns1);
			if (pctx->ipv6_dns2[0] != 0)
				msg->dns[pos++] = talloc_strdup(pool, pctx->ipv6_dns2);

			msg->n_dns = dns;
		}
	}

	if (pctx->ipv6[0] != 0) {
		msg->explicit_ipv6 = talloc_strdup(pool, pctx->ipv6);
	}

	if (pctx->ipv6_net[0] != 0) {
		msg->ipv6_net = talloc_strdup(pool, pctx->ipv6_net);
	}

	if (pctx->ipv6_prefix != 0) {
		msg->ipv6_prefix = pctx->ipv6_prefix;
		msg->has_ipv6_prefix = 1;
	}

	return 0;
}

struct config_mod_st radius_sup_config = {
	.get_sup_config = get_sup_config,
};

#endif
