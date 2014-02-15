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

struct cfg_options {
	const char* name;
	unsigned type;
};

static struct cfg_options available_options[] = {
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
	{ .name = "rx-data-per-sec", .type = OPTION_NUMERIC, },
	{ .name = "tx-data-per-sec", .type = OPTION_NUMERIC, },
	{ .name = "net-priority", .type = OPTION_STRING, },
	{ .name = "cgroup", .type = OPTION_STRING, },
};

#define READ_RAW_MULTI_LINE(name, s_name, num) \
	val = optionGetValue(pov, name); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) { \
		if (s_name == NULL) { \
			num = 0; \
			s_name = malloc(sizeof(char*)*MAX_CONFIG_ENTRIES); \
		} \
		do { \
		        if (val && !strcmp(val->pzName, name)==0) \
				continue; \
		        s_name[num] = strdup(val->v.strVal); \
		        num++; \
		        if (num>=MAX_CONFIG_ENTRIES) \
		        break; \
	      } while((val = optionNextValue(pov, val)) != NULL); \
	      s_name[num] = NULL; \
	}

#define READ_RAW_STRING(name, s_name) \
	val = optionGetValue(pov, name); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) { \
		s_name = strdup(val->v.strVal); \
	}

#define READ_RAW_NUMERIC(name, s_name) \
	val = optionGetValue(pov, name); \
	if (val != NULL) { \
		if (val->valType == OPARG_TYPE_NUMERIC) \
			s_name = val->v.longVal; \
		else if (val->valType == OPARG_TYPE_STRING) \
			s_name = atoi(val->v.strVal); \
	}

#define READ_RAW_PRIO_TOS(name, s_name) \
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
	}


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

int parse_group_cfg_file(main_server_st* s, const char* file, struct group_cfg_st *config)
{
tOptionValue const * pov;
const tOptionValue* val, *prev;
unsigned prefix = 0;

	memset(config, 0, sizeof(*config));

	pov = configFileLoad(file);
	if (pov == NULL) {
		mslog(s, NULL, LOG_ERR, "Cannot load config file %s", file);
		return 0;
	}

	val = optionGetValue(pov, NULL);
	if (val == NULL) {
		mslog(s, NULL, LOG_ERR, "No configuration directives found in %s", file);
		return ERR_READ_CONFIG;
	}

	do {
		if (handle_option(val) == 0) {
			mslog(s, NULL, LOG_ERR, "Skipping unknown option '%s' in %s", val->pzName, file);
		}
		prev = val;
	} while((val = optionNextValue(pov, prev)) != NULL);

	READ_RAW_MULTI_LINE("route", config->routes, config->routes_size);
	READ_RAW_MULTI_LINE("iroute", config->iroutes, config->iroutes_size);

	READ_RAW_MULTI_LINE("dns", config->dns, config->dns_size);
	if (config->dns_size == 0) {
		/* try aliases */
		READ_RAW_MULTI_LINE("ipv6-dns", config->dns, config->dns_size);
		READ_RAW_MULTI_LINE("ipv4-dns", config->dns, config->dns_size);
	}

	READ_RAW_MULTI_LINE("nbns", config->nbns, config->nbns_size);
	if (config->nbns_size == 0) {
		/* try aliases */
		READ_RAW_MULTI_LINE("ipv6-nbns", config->nbns, config->nbns_size);
		READ_RAW_MULTI_LINE("ipv4-nbns", config->nbns, config->nbns_size);
	}

	READ_RAW_STRING("cgroup", config->cgroup);
	READ_RAW_STRING("ipv4-network", config->ipv4_network);
	READ_RAW_STRING("ipv6-network", config->ipv6_network);
	READ_RAW_STRING("ipv4-netmask", config->ipv4_netmask);

	READ_RAW_NUMERIC("ipv6-prefix", prefix);
	if (prefix > 0) {
		config->ipv6_netmask = ipv6_prefix_to_mask(prefix);
		config->ipv6_prefix = prefix;
	}

	READ_RAW_NUMERIC("rx-data-per-sec", config->rx_per_sec);
	READ_RAW_NUMERIC("tx-data-per-sec", config->tx_per_sec);
	config->rx_per_sec /= 1000; /* in kb */
	config->tx_per_sec /= 1000; /* in kb */
	
	/* net-priority will contain the actual priority + 1,
	 * to allow having zero as uninitialized. */
	READ_RAW_PRIO_TOS("net-priority", config->net_priority);

	optionUnloadNested(pov);
	
	return 0;
}

void del_additional_config(struct group_cfg_st* config)
{
unsigned i;

	for(i=0;i<config->routes_size;i++) {
		free(config->routes[i]);
	}
	free(config->routes);

	for(i=0;i<config->iroutes_size;i++) {
		free(config->iroutes[i]);
	}
	free(config->iroutes);

	for(i=0;i<config->dns_size;i++) {
		free(config->dns[i]);
	}
	free(config->dns);

	for(i=0;i<config->nbns_size;i++) {
		free(config->nbns[i]);
	}
	free(config->nbns);

	free(config->cgroup);
	free(config->ipv4_network);
	free(config->ipv6_network);
	free(config->ipv4_netmask);
	free(config->ipv6_netmask);
}
