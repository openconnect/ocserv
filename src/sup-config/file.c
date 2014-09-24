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
#include <main-sup-config.h>

struct cfg_options {
	const char* name;
	unsigned type;
};

static struct cfg_options available_options[] = {
	{ .name = "no-udp", .type = OPTION_BOOLEAN },
	{ .name = "deny-roaming", .type = OPTION_BOOLEAN },
	{ .name = "require-cert", .type = OPTION_BOOLEAN },
	{ .name = "route", .type = OPTION_MULTI_LINE },
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
			s_name = talloc_size(proc, sizeof(char*)*MAX_CONFIG_ENTRIES); \
		} \
		do { \
		        if (num >= MAX_CONFIG_ENTRIES) \
			        break; \
		        if (val && !strcmp(val->pzName, name)==0) \
				continue; \
		        s_name[num] = talloc_strdup(proc, val->v.strVal); \
		        num++; \
	      } while((val = optionNextValue(pov, val)) != NULL); \
	      s_name[num] = NULL; \
	}}

#define READ_RAW_STRING(name, s_name) { \
	val = optionGetValue(pov, name); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) { \
		if (s_name != NULL) \
			talloc_free(s_name); \
		s_name = talloc_strdup(proc, val->v.strVal); \
	}}

#define READ_RAW_NUMERIC(name, s_name) { \
	val = optionGetValue(pov, name); \
	if (val != NULL) { \
		if (val->valType == OPARG_TYPE_NUMERIC) \
			s_name = val->v.longVal; \
		else if (val->valType == OPARG_TYPE_STRING) \
			s_name = atoi(val->v.strVal); \
	}}

#define READ_RAW_PRIO_TOS(name, s_name) { \
	val = optionGetValue(pov, name); \
	if (val != NULL) { \
		if (val->valType == OPARG_TYPE_STRING) { \
			if (strncmp(val->v.strVal, "0x", 2) == 0) { \
				s_name = strtol(val->v.strVal, NULL, 16); \
				s_name = TOS_PACK(s_name); \
			} else { \
				s_name = atoi(val->v.strVal); \
				s_name++; \
			} \
		} \
	}}

#define READ_TF(name, s_name, def) { \
	{ char* tmp_tf = NULL; \
		READ_RAW_STRING(name, tmp_tf); \
		if (tmp_tf == NULL) s_name = def; \
		else { \
			if (c_strcasecmp(tmp_tf, "true") == 0 || c_strcasecmp(tmp_tf, "yes") == 0) \
				s_name = 1; \
			else \
				s_name = 0; \
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
int parse_group_cfg_file(struct cfg_st *global_config, struct proc_st *proc,
			 const char* file)
{
tOptionValue const * pov;
const tOptionValue* val, *prev;
unsigned prefix = 0;
struct group_cfg_st *sconfig = &proc->config;

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

	READ_TF("no-udp", sconfig->no_udp, (global_config->udp_port!=0)?0:1);
	READ_TF("deny-roaming", sconfig->deny_roaming, global_config->deny_roaming);
	READ_TF("require-cert", sconfig->require_cert, 0);

	READ_RAW_MULTI_LINE("route", sconfig->routes, sconfig->routes_size);
	READ_RAW_MULTI_LINE("iroute", sconfig->iroutes, sconfig->iroutes_size);

	READ_RAW_MULTI_LINE("dns", sconfig->dns, sconfig->dns_size);
	if (sconfig->dns_size == 0) {
		/* try aliases */
		READ_RAW_MULTI_LINE("ipv6-dns", sconfig->dns, sconfig->dns_size);
		READ_RAW_MULTI_LINE("ipv4-dns", sconfig->dns, sconfig->dns_size);
	}

	READ_RAW_MULTI_LINE("nbns", sconfig->nbns, sconfig->nbns_size);
	if (sconfig->nbns_size == 0) {
		/* try aliases */
		READ_RAW_MULTI_LINE("ipv6-nbns", sconfig->nbns, sconfig->nbns_size);
		READ_RAW_MULTI_LINE("ipv4-nbns", sconfig->nbns, sconfig->nbns_size);
	}

	READ_RAW_STRING("cgroup", sconfig->cgroup);
	READ_RAW_STRING("ipv4-network", sconfig->ipv4_network);
	READ_RAW_STRING("ipv6-network", sconfig->ipv6_network);
	READ_RAW_STRING("ipv4-netmask", sconfig->ipv4_netmask);

	READ_RAW_NUMERIC("ipv6-prefix", prefix);
	if (prefix > 0) {
		sconfig->ipv6_netmask = ipv6_prefix_to_mask(proc, prefix);
		sconfig->ipv6_prefix = prefix;

		if (sconfig->ipv6_netmask == NULL) {
			syslog(LOG_ERR, "unknown ipv6-prefix '%u' in %s", prefix, file);
		}
	}

	READ_RAW_NUMERIC("rx-data-per-sec", sconfig->rx_per_sec);
	READ_RAW_NUMERIC("tx-data-per-sec", sconfig->tx_per_sec);
	sconfig->rx_per_sec /= 1000; /* in kb */
	sconfig->tx_per_sec /= 1000; /* in kb */
	
	/* net-priority will contain the actual priority + 1,
	 * to allow having zero as uninitialized. */
	READ_RAW_PRIO_TOS("net-priority", sconfig->net_priority);

	READ_RAW_STRING("user-profile", sconfig->xml_config_file);

	optionUnloadNested(pov);
	
	return 0;
}

static int read_sup_config_file(struct cfg_st *global_config, struct proc_st *proc,
				       const char *file, const char *fallback, const char *type)
{
	int ret;

	if (access(file, R_OK) == 0) {
		syslog(LOG_DEBUG, "Loading %s configuration '%s'", type,
		      file);

		ret = parse_group_cfg_file(global_config, proc, file);
		if (ret < 0)
			return ERR_READ_CONFIG;
	} else {
		if (fallback != NULL) {
			syslog(LOG_DEBUG, "Loading default %s configuration '%s'", type, fallback);

			ret = parse_group_cfg_file(global_config, proc, fallback);
			if (ret < 0)
				return ERR_READ_CONFIG;
		} else {
			syslog(LOG_DEBUG, "No %s configuration for '%s'", type,
			      proc->username);
		}
	}

	return 0;
}

static int get_sup_config(struct cfg_st *global_config, struct proc_st *proc)
{
	char file[_POSIX_PATH_MAX];
	int ret;

	if (global_config->per_group_dir != NULL && proc->groupname[0] != 0) {
		snprintf(file, sizeof(file), "%s/%s", global_config->per_group_dir,
			 proc->groupname);

		ret = read_sup_config_file(global_config, proc, file, global_config->default_group_conf, "group");
		if (ret < 0)
			return ret;
	}

	if (global_config->per_user_dir != NULL) {
		snprintf(file, sizeof(file), "%s/%s", global_config->per_user_dir,
			 proc->username);

		ret = read_sup_config_file(global_config, proc, file, global_config->default_user_conf, "user");
		if (ret < 0)
			return ret;
	}

	return 0;
}


static
void clear_sup_config(struct group_cfg_st* config)
{
unsigned i;

	for(i=0;i<config->routes_size;i++) {
		talloc_free(config->routes[i]);
	}
	talloc_free(config->routes);

	for(i=0;i<config->iroutes_size;i++) {
		talloc_free(config->iroutes[i]);
	}
	talloc_free(config->iroutes);

	for(i=0;i<config->dns_size;i++) {
		talloc_free(config->dns[i]);
	}
	talloc_free(config->dns);

	for(i=0;i<config->nbns_size;i++) {
		talloc_free(config->nbns[i]);
	}
	talloc_free(config->nbns);

	talloc_free(config->cgroup);
	talloc_free(config->ipv4_network);
	talloc_free(config->ipv6_network);
	talloc_free(config->ipv4_netmask);
	talloc_free(config->ipv6_netmask);
	safe_memset(config, 0, sizeof(*config));
}

struct config_mod_st file_sup_config = {
	.get_sup_config = get_sup_config,
	.clear_sup_config = clear_sup_config,
};
