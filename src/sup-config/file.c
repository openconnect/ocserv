/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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

#include <vpn.h>
#include <main.h>
#include <sec-mod-sup-config.h>

struct cfg_options {
	const char* name;
	unsigned type;
};

static struct cfg_options available_options[] = {
	{ .name = "no-udp", .type = OPTION_BOOLEAN },
	{ .name = "deny-roaming", .type = OPTION_BOOLEAN },
	{ .name = "require-cert", .type = OPTION_BOOLEAN },
	{ .name = "route", .type = OPTION_MULTI_LINE },
	{ .name = "no-route", .type = OPTION_MULTI_LINE },
	{ .name = "iroute", .type = OPTION_MULTI_LINE },
	{ .name = "dns", .type = OPTION_MULTI_LINE },
	{ .name = "ipv4-dns", .type = OPTION_MULTI_LINE }, /* alias of dns */
	{ .name = "ipv6-dns", .type = OPTION_MULTI_LINE }, /* alias of dns */
	{ .name = "nbns", .type = OPTION_MULTI_LINE },
	{ .name = "ipv4-nbns", .type = OPTION_MULTI_LINE }, /* alias of nbns */
	{ .name = "ipv6-nbns", .type = OPTION_MULTI_LINE }, /* alias of nbns */
	{ .name = "ipv4-network", .type = OPTION_STRING },
	{ .name = "ipv6-network", .type = OPTION_STRING },
	{ .name = "ipv4-netmask", .type = OPTION_STRING },
	{ .name = "ipv6-prefix", .type = OPTION_NUMERIC },
	{ .name = "explicit-ipv4", .type = OPTION_STRING },
	{ .name = "explicit-ipv6", .type = OPTION_STRING },
	{ .name = "rx-data-per-sec", .type = OPTION_NUMERIC },
	{ .name = "tx-data-per-sec", .type = OPTION_NUMERIC },
	{ .name = "net-priority", .type = OPTION_STRING },
	{ .name = "cgroup", .type = OPTION_STRING },
	{ .name = "user-profile", .type = OPTION_STRING },
};

#define READ_RAW_MULTI_LINE(name, s_name, num) { \
	val = optionGetValue(pov, name); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) { \
		if (s_name == NULL) { \
			num = 0; \
			s_name = talloc_size(pool, sizeof(char*)*MAX_CONFIG_ENTRIES); \
		} \
		do { \
		        if (num >= MAX_CONFIG_ENTRIES) \
			        break; \
		        if (val && !strcmp(val->pzName, name)==0) \
				continue; \
		        s_name[num] = talloc_strdup(pool, val->v.strVal); \
		        num++; \
	      } while((val = optionNextValue(pov, val)) != NULL); \
	      s_name[num] = NULL; \
	}}

#define READ_RAW_STRING(name, s_name) { \
	val = optionGetValue(pov, name); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) { \
		if (s_name != NULL) \
			talloc_free(s_name); \
		s_name = talloc_strdup(pool, val->v.strVal); \
	}}

#define READ_RAW_NUMERIC(name, s_name, def) { \
	val = optionGetValue(pov, name); \
	if (val != NULL) { \
		if (val->valType == OPARG_TYPE_NUMERIC) {\
			s_name = val->v.longVal; \
			def = 1; \
		} else if (val->valType == OPARG_TYPE_STRING) {\
			s_name = atoi(val->v.strVal); \
			def = 1; \
		} \
	}}

#define READ_RAW_PRIO_TOS(name, s_name, def) { \
	val = optionGetValue(pov, name); \
	if (val != NULL) { \
		if (val->valType == OPARG_TYPE_STRING) { \
			if (strncmp(val->v.strVal, "0x", 2) == 0) { \
				s_name = strtol(val->v.strVal, NULL, 16); \
				s_name = TOS_PACK(s_name); \
				def = 1; \
			} else { \
				s_name = atoi(val->v.strVal); \
				s_name++; \
				def = 1; \
			} \
		} \
	}}

#define READ_TF(name, s_name, def) { \
	{ char* tmp_tf = NULL; \
		READ_RAW_STRING(name, tmp_tf); \
		if (tmp_tf == NULL) { def = 0; \
		} else { \
			if (c_strcasecmp(tmp_tf, "true") == 0 || c_strcasecmp(tmp_tf, "yes") == 0) \
				s_name = 1; \
			else \
				s_name = 0; \
			def = 1; \
		} \
		talloc_free(tmp_tf); \
	}}

static int handle_option(const tOptionValue* val)
{
unsigned j;

	for (j=0;j<sizeof(available_options)/sizeof(available_options[0]);j++) {
		if (strcasecmp(val->pzName, available_options[j].name) == 0) {
			return 1;
		}
	}
	
	return 0;
}

/* This will parse the configuration file and append/replace data into
 * config. The provided config must either be memset to zero, or be
 * already allocated using this function.
 */
static
int parse_group_cfg_file(struct cfg_st *global_config,
			 SecAuthSessionReplyMsg *msg, void *pool,
			 const char* file)
{
tOptionValue const * pov;
const tOptionValue* val, *prev;
unsigned prefix = 0;

	pov = configFileLoad(file);
	if (pov == NULL) {
		syslog(LOG_ERR, "cannot load config file %s", file);
		return 0;
	}

	val = optionGetValue(pov, NULL);
	if (val == NULL) {
		syslog(LOG_ERR, "no configuration directives found in %s", file);
		optionUnloadNested(pov);
		return ERR_READ_CONFIG;
	}

	do {
		if (handle_option(val) == 0) {
			syslog(LOG_ERR, "skipping unknown option '%s' in %s", val->pzName, file);
		}
		prev = val;
	} while((val = optionNextValue(pov, prev)) != NULL);

	READ_TF("no-udp", msg->no_udp, msg->has_no_udp);
	READ_TF("deny-roaming", msg->deny_roaming, msg->has_deny_roaming);
	READ_TF("require-cert", msg->require_cert, msg->has_require_cert);

	READ_RAW_MULTI_LINE("route", msg->routes, msg->n_routes);
	READ_RAW_MULTI_LINE("no-route", msg->no_routes, msg->n_no_routes);
	READ_RAW_MULTI_LINE("iroute", msg->iroutes, msg->n_iroutes);

	READ_RAW_MULTI_LINE("dns", msg->dns, msg->n_dns);
	if (msg->n_dns == 0) {
		/* try aliases */
		READ_RAW_MULTI_LINE("ipv6-dns", msg->dns, msg->n_dns);
		READ_RAW_MULTI_LINE("ipv4-dns", msg->dns, msg->n_dns);
	}

	READ_RAW_MULTI_LINE("nbns", msg->nbns, msg->n_nbns);
	if (msg->n_nbns == 0) {
		/* try aliases */
		READ_RAW_MULTI_LINE("ipv6-nbns", msg->nbns, msg->n_nbns);
		READ_RAW_MULTI_LINE("ipv4-nbns", msg->nbns, msg->n_nbns);
	}

	READ_RAW_STRING("cgroup", msg->cgroup);
	READ_RAW_STRING("ipv4-network", msg->ipv4_net);
	READ_RAW_STRING("ipv6-network", msg->ipv6_net);
	READ_RAW_STRING("ipv4-netmask", msg->ipv4_netmask);
	READ_RAW_STRING("explicit-ipv4", msg->explicit_ipv4);
	READ_RAW_STRING("explicit-ipv6", msg->explicit_ipv6);

	msg->ipv6_prefix = extract_prefix(msg->ipv6_net);
	if (msg->ipv6_prefix == 0) {
		READ_RAW_NUMERIC("ipv6-prefix", msg->ipv6_prefix, msg->has_ipv6_prefix);
	} else {
		msg->has_ipv6_prefix = 1;
	}

	if (msg->has_ipv6_prefix != 0) {
		if (valid_ipv6_prefix(msg->ipv6_prefix) == 0) {
			syslog(LOG_ERR, "unknown ipv6-prefix '%u' in %s", prefix, file);
		}
	}

	READ_RAW_NUMERIC("rx-data-per-sec", msg->rx_per_sec, msg->has_rx_per_sec);
	READ_RAW_NUMERIC("tx-data-per-sec", msg->tx_per_sec, msg->has_tx_per_sec);
	msg->rx_per_sec /= 1000; /* in kb */
	msg->tx_per_sec /= 1000; /* in kb */
	
	/* net-priority will contain the actual priority + 1,
	 * to allow having zero as uninitialized. */
	READ_RAW_PRIO_TOS("net-priority", msg->net_priority, msg->has_net_priority);

	READ_RAW_STRING("user-profile", msg->xml_config_file);

	optionUnloadNested(pov);
	
	return 0;
}

static int read_sup_config_file(struct cfg_st *global_config,
				SecAuthSessionReplyMsg *msg, void *pool,
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
			  SecAuthSessionReplyMsg *msg, void *pool)
{
	char file[_POSIX_PATH_MAX];
	int ret;

	if (cfg->per_group_dir != NULL && entry->groupname[0] != 0) {
		snprintf(file, sizeof(file), "%s/%s", cfg->per_group_dir,
			 entry->groupname);

		ret = read_sup_config_file(cfg, msg, pool, file, cfg->default_group_conf, "group");
		if (ret < 0)
			return ret;
	}

	if (cfg->per_user_dir != NULL) {
		snprintf(file, sizeof(file), "%s/%s", cfg->per_user_dir,
			 entry->username);
		ret = read_sup_config_file(cfg, msg, pool, file, cfg->default_user_conf, "user");
		if (ret < 0)
			return ret;
	}

	return 0;
}

struct config_mod_st file_sup_config = {
	.get_sup_config = get_sup_config,
};
