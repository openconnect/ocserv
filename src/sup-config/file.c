/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 * Copyright (C) 2014, 2015 Red Hat, Inc.
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
#include <limits.h>
#include <common.h>
#include <ip-util.h>
#include <c-strcase.h>
#include <c-ctype.h>

#include "inih/ini.h"

#include <vpn.h>
#include <main.h>
#include <common-config.h>
#include <sec-mod-sup-config.h>

#define READ_RAW_MULTI_LINE(varname, num) \
	_add_multi_line_val(pool, &varname, &num, value)

#define READ_RAW_STRING(varname) { \
	if (varname != NULL) \
		talloc_free(varname); \
	varname = talloc_strdup(pool, value); \
	}

#define READ_RAW_NUMERIC(varname, var_set) { \
	varname = strtol(value, NULL, 10); \
	var_set = 1; \
	}

#define READ_RAW_PRIO_TOS(varname, var_set) { \
	if (strncmp(value, "0x", 2) == 0) { \
		varname = strtol(value, NULL, 16); \
		varname = TOS_PACK(varname); \
		var_set = 1; \
	} else { \
		varname = strtol(value, NULL, 10); \
		varname++; \
		var_set = 1; \
	} \
	}

#define READ_TF(varname, is_set) { \
	char* tmp_tf = NULL; \
	READ_RAW_STRING(tmp_tf); \
	if (c_strcasecmp(tmp_tf, "true") == 0 || c_strcasecmp(tmp_tf, "yes") == 0) \
		varname = 1; \
	else \
		varname = 0; \
	is_set = 1; \
	talloc_free(tmp_tf); \
	}

struct ini_ctx_st {
	SecmSessionReplyMsg *msg;
	const char *file;
	void *pool;
};

static int group_cfg_ini_handler(void *_ctx, const char *section, const char *name, const char* _value)
{
	struct ini_ctx_st *ctx = _ctx;
	SecmSessionReplyMsg *msg = ctx->msg;
	const char *file = ctx->file;
	void *pool = ctx->pool;
	unsigned prefix = 0, prefix4 = 0;
	int ret;
	char *value;

	if (section != NULL && section[0] != 0) {
		syslog(LOG_INFO, "skipping unknown section '%s' in %s", section, file);
		return 0;
	}

	value = sanitize_config_value(ctx->pool, _value);
	if (value == NULL)
		return 0;

	if (strcmp(name, "no-udp") == 0) {
		READ_TF(msg->config->no_udp, msg->config->has_no_udp);
	} else if (strcmp(name, "restrict-user-to-routes")==0) {
		READ_TF(msg->config->restrict_user_to_routes, msg->config->has_restrict_user_to_routes);
	} else if (strcmp(name, "tunnel_all_dns") == 0) {
		READ_TF(msg->config->tunnel_all_dns, msg->config->has_tunnel_all_dns);
	} else if (strcmp(name, "deny-roaming") == 0) {
		READ_TF(msg->config->deny_roaming, msg->config->has_deny_roaming);
	} else if (strcmp(name, "route") == 0) {
		READ_RAW_MULTI_LINE(msg->config->routes, msg->config->n_routes);
	} else if (strcmp(name, "split-dns") == 0) {
		READ_RAW_MULTI_LINE(msg->config->split_dns, msg->config->n_split_dns);
	} else if (strcmp(name, "no-route") == 0) {
		READ_RAW_MULTI_LINE(msg->config->no_routes, msg->config->n_no_routes);
	} else if (strcmp(name, "iroute") == 0) {
		READ_RAW_MULTI_LINE(msg->config->iroutes, msg->config->n_iroutes);
	} else if (strcmp(name, "dns") == 0) {
		READ_RAW_MULTI_LINE(msg->config->dns, msg->config->n_dns);
	} else if (strcmp(name, "ipv6-dns") == 0) {
		READ_RAW_MULTI_LINE(msg->config->dns, msg->config->n_dns);
	} else if (strcmp(name, "ipv4-dns") == 0) {
		READ_RAW_MULTI_LINE(msg->config->dns, msg->config->n_dns);
	} else if (strcmp(name, "nbns") == 0) {
		READ_RAW_MULTI_LINE(msg->config->nbns, msg->config->n_nbns);
	} else if (strcmp(name, "ipv4-nbns") == 0) {
		READ_RAW_MULTI_LINE(msg->config->nbns, msg->config->n_nbns);
	} else if (strcmp(name, "ipv6-nbns") == 0) {
		READ_RAW_MULTI_LINE(msg->config->nbns, msg->config->n_nbns);
	} else if (strcmp(name, "cgroup") == 0) {
		READ_RAW_STRING(msg->config->cgroup);
	} else if (strcmp(name, "ipv4-network") == 0) {
		READ_RAW_STRING(msg->config->ipv4_net);
		prefix4 = extract_prefix(msg->config->ipv4_net);
		if (prefix4 != 0)
			msg->config->ipv4_netmask = ipv4_prefix_to_strmask(pool, prefix4);
	} else if (strcmp(name, "ipv4-netmask") == 0) {
		READ_RAW_STRING(msg->config->ipv4_netmask);
	} else if (strcmp(name, "explicit-ipv4") == 0) {
		READ_RAW_STRING(msg->config->explicit_ipv4);
	} else if (strcmp(name, "ipv6-network") == 0) {
		READ_RAW_STRING(msg->config->ipv6_net);

		prefix = extract_prefix(msg->config->ipv6_net);
		if (prefix != 0) {
			if (valid_ipv6_prefix(prefix) == 0) {
				syslog(LOG_ERR, "unknown ipv6-prefix '%u' in %s", msg->config->ipv6_prefix, file);
			}
			msg->config->ipv6_prefix = prefix;
			msg->config->has_ipv6_prefix = 1;
		}
	} else if (strcmp(name, "explicit-ipv6") == 0) {
		READ_RAW_STRING(msg->config->explicit_ipv6);
	} else if (strcmp(name, "ipv6-subnet-prefix") == 0) {
		READ_RAW_NUMERIC(msg->config->ipv6_subnet_prefix, msg->config->has_ipv6_subnet_prefix);
	} else if (strcmp(name, "hostname") == 0) {
		READ_RAW_STRING(msg->config->hostname);
	} else if (strcmp(name, "rx-data-per-sec") == 0) {
		READ_RAW_NUMERIC(msg->config->rx_per_sec, msg->config->has_rx_per_sec);
		msg->config->rx_per_sec /= 1000; /* in kb */
	} else if (strcmp(name, "tx-data-per-sec") == 0) {
		READ_RAW_NUMERIC(msg->config->tx_per_sec, msg->config->has_tx_per_sec);
		msg->config->tx_per_sec /= 1000; /* in kb */
	} else if (strcmp(name, "stats-report-time") == 0) {
		READ_RAW_NUMERIC(msg->config->interim_update_secs, msg->config->has_interim_update_secs);
	} else if (strcmp(name, "session-timeout") == 0) {
		READ_RAW_NUMERIC(msg->config->session_timeout_secs, msg->config->has_session_timeout_secs);
	} else if (strcmp(name, "mtu") == 0) {
		READ_RAW_NUMERIC(msg->config->mtu, msg->config->has_mtu);
	} else if (strcmp(name, "dpd") == 0) {
		READ_RAW_NUMERIC(msg->config->dpd, msg->config->has_dpd);
	} else if (strcmp(name, "mobile-dpd") == 0) {
		READ_RAW_NUMERIC(msg->config->mobile_dpd, msg->config->has_mobile_dpd);
	} else if (strcmp(name, "idle-timeout") == 0) {
		READ_RAW_NUMERIC(msg->config->idle_timeout, msg->config->has_idle_timeout);
	} else if (strcmp(name, "mobile-idle-timeout") == 0) {
		READ_RAW_NUMERIC(msg->config->mobile_idle_timeout, msg->config->has_mobile_idle_timeout);
	} else if (strcmp(name, "keepalive") == 0) {
		READ_RAW_NUMERIC(msg->config->keepalive, msg->config->has_keepalive);
	} else if (strcmp(name, "max-same-clients") == 0) {
		READ_RAW_NUMERIC(msg->config->max_same_clients, msg->config->has_max_same_clients);
	} else if (strcmp(name, "net-priority") == 0) {
		/* net-priority will contain the actual priority + 1,
		 * to allow having zero as uninitialized. */
		 READ_RAW_PRIO_TOS(msg->config->net_priority, msg->config->has_net_priority);
#ifdef ANYCONNECT_CLIENT_COMPAT
	} else if (strcmp(name, "user-profile") == 0) {
		READ_RAW_STRING(msg->config->xml_config_file);
#endif		
	} else if (strcmp(name, "restrict-user-to-ports") == 0) {
		ret = cfg_parse_ports(pool, &msg->config->fw_ports, &msg->config->n_fw_ports, value);
		if (ret < 0) {
			talloc_free(value);
			return -1;
		}
	} else {
		syslog(LOG_INFO, "skipping unknown option '%s' in %s", name, file);
	}

	talloc_free(value);
	return 0;
}

/* This will parse the configuration file and append/replace data into
 * config. The provided config must either be memset to zero, or be
 * already allocated using this function.
 */
static
int parse_group_cfg_file(struct cfg_st *global_config,
			 SecmSessionReplyMsg *msg, void *pool,
			 const char* file)
{
	int ret;
	unsigned j;
	struct ini_ctx_st ctx;

	ctx.pool = pool;
	ctx.msg = msg;
	ctx.file = file;

	ret = ini_parse(file, group_cfg_ini_handler, &ctx);
	if (ret < 0) {
		syslog(LOG_ERR, "cannot load config file %s", file);
		return 0;
	}

	for (j=0;j<msg->config->n_routes;j++) {
		if (ip_route_sanity_check(msg->config->routes, &msg->config->routes[j]) != 0) {
			ret = ERR_READ_CONFIG;
			goto fail;
		}
	}

	for (j=0;j<msg->config->n_iroutes;j++) {
		if (ip_route_sanity_check(msg->config->iroutes, &msg->config->iroutes[j]) != 0) {
			ret = ERR_READ_CONFIG;
			goto fail;
		}
	}

	for (j=0;j<msg->config->n_no_routes;j++) {
		if (ip_route_sanity_check(msg->config->no_routes, &msg->config->no_routes[j]) != 0) {
			ret = ERR_READ_CONFIG;
			goto fail;
		}
	}

	ret = 0;
 fail:
	
	return ret;
}

static int read_sup_config_file(struct cfg_st *global_config,
				SecmSessionReplyMsg *msg, void *pool,
				const char *file, const char *fallback, const char *type)
{
	int ret;

	if (access(file, R_OK) == 0) {
		syslog(LOG_DEBUG, "Loading %s configuration '%s'", type,
		      file);

		ret = parse_group_cfg_file(global_config, msg, pool, file);
		if (ret < 0)
			return ERR_READ_CONFIG;
	} else {
		if (fallback != NULL) {
			syslog(LOG_DEBUG, "Loading default %s configuration '%s'", type, fallback);

			ret = parse_group_cfg_file(global_config, msg, pool, fallback);
			if (ret < 0)
				return ERR_READ_CONFIG;
		}
	}

	return 0;
}

static int get_sup_config(struct cfg_st *cfg, client_entry_st *entry,
			  SecmSessionReplyMsg *msg, void *pool)
{
	char file[_POSIX_PATH_MAX];
	int ret;

	if (cfg->per_group_dir != NULL && entry->acct_info.groupname[0] != 0) {
		snprintf(file, sizeof(file), "%s/%s", cfg->per_group_dir,
			 entry->acct_info.groupname);

		ret = read_sup_config_file(cfg, msg, pool, file, cfg->default_group_conf, "group");
		if (ret < 0)
			return ret;
	}

	if (cfg->per_user_dir != NULL) {
		snprintf(file, sizeof(file), "%s/%s", cfg->per_user_dir,
			 entry->acct_info.username);
		ret = read_sup_config_file(cfg, msg, pool, file, cfg->default_user_conf, "user");
		if (ret < 0)
			return ret;
	}

	return 0;
}

struct config_mod_st file_sup_config = {
	.get_sup_config = get_sup_config,
};
