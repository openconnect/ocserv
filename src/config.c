/*
 * Copyright (C) 2013, 2014, 2015 Nikos Mavrogiannopoulos
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
#include <ocserv-args.h>
#include <autoopts/options.h>
#include <limits.h>
#include <common.h>
#include <ip-util.h>
#include <c-strcase.h>
#include <c-ctype.h>
#include <auth/pam.h>
#include <acct/pam.h>
#include <auth/radius.h>
#include <acct/radius.h>
#include <auth/plain.h>
#include <auth/gssapi.h>
#include <auth/common.h>
#include <sec-mod-sup-config.h>
#include <sec-mod-acct.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <netdb.h>

#include <vpn.h>
#include <main.h>
#include <tlslib.h>
#include <occtl/ctl.h>
#include "common-config.h"

#define OLD_DEFAULT_CFG_FILE "/etc/ocserv.conf"
#define DEFAULT_CFG_FILE "/etc/ocserv/ocserv.conf"

static char pid_file[_POSIX_PATH_MAX] = "";
static char cfg_file[_POSIX_PATH_MAX] = DEFAULT_CFG_FILE;

static void archive_cfg(struct perm_cfg_st* perm_config);

struct cfg_options {
	const char* name;
	unsigned type;
	unsigned mandatory;
	const tOptionValue* val;
};

#define ERRSTR "error: "
#define WARNSTR "warning: "
#define NOTESTR "note: "

static struct cfg_options available_options[] = {
	{ .name = "auth", .type = OPTION_MULTI_LINE, .mandatory = 1 },
	{ .name = "enable-auth", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "append-routes", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "expose-iroutes", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "route", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "no-route", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "select-group", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "custom-header", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "split-dns", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "acct", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "listen-host", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "listen-host-is-dyndns", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "dtls-psk", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "dtls-legacy", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "listen-proxy-proto", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "compression", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "no-compress-limit", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "tcp-port", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "max-ban-score", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "ban-points-wrong-password", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "ban-points-connection", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "ban-points-kkdcp", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "udp-port", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "keepalive", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "switch-to-tcp-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "dpd", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "mobile-dpd", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "rate-limit-ms", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "ocsp-response", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "server-cert", .type = OPTION_STRING, .mandatory = 1 },
	{ .name = "server-key", .type = OPTION_STRING, .mandatory = 1 },
	{ .name = "dh-params", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "pin-file", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "key-pin", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "srk-pin-file", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "srk-pin", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "user-profile", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "ca-cert", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "default-domain", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "crl", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "cert-user-oid", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "cert-group-oid", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "connect-script", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "host-update-script", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "disconnect-script", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "pid-file", .type = OPTION_STRING, .mandatory = 0 },
#ifdef HAVE_GSSAPI
	{ .name = "kkdcp", .type = OPTION_STRING, .mandatory = 0 },
#endif
	{ .name = "socket-file", .type = OPTION_STRING, .mandatory = 1 },
	{ .name = "listen-clear-file", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "occtl-socket-file", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "banner", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "use-seccomp", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "tunnel-all-dns", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "isolate-workers", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "predictable-ips", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "session-control", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "auto-select-group", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "default-select-group", .type = OPTION_STRING, .mandatory = 0 },
	/* this is alias for cisco-client-compat */
	{ .name = "always-require-cert", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "cisco-client-compat", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "deny-roaming", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "use-utmp", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "use-dbus", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "persistent-cookies", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "use-occtl", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "try-mtu-discovery", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "restrict-user-to-routes", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "restrict-user-to-ports", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "ping-leases", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "tls-priorities", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "chroot-dir", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "mtu", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "net-priority", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "output-buffer", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "cookie-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "cookie-rekey-time", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "session-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "stats-report-time", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "rekey-time", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "rekey-method", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "auth-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "idle-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "mobile-idle-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "max-clients", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "min-reauth-time", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "ban-reset-time", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "max-same-clients", .type = OPTION_NUMERIC, .mandatory = 0 },

	{ .name = "rx-data-per-sec", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "tx-data-per-sec", .type = OPTION_NUMERIC, .mandatory = 0 },

	{ .name = "run-as-user", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "run-as-group", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "device", .type = OPTION_STRING, .mandatory = 1 },
	{ .name = "cgroup", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "proxy-url", .type = OPTION_STRING, .mandatory = 0 },

	{ .name = "ipv4-network", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "ipv4-netmask", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "dns", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "ipv4-dns", .type = OPTION_MULTI_LINE, .mandatory = 0 }, /* alias dns */
	{ .name = "ipv6-dns", .type = OPTION_MULTI_LINE, .mandatory = 0 }, /* alias dns */
	{ .name = "nbns", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "ipv4-nbns", .type = OPTION_MULTI_LINE, .mandatory = 0 }, /* alias nbns */
	{ .name = "ipv6-nbns", .type = OPTION_MULTI_LINE, .mandatory = 0 }, /* alias nbns */

	{ .name = "ipv6-network", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "ipv6-prefix", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "ipv6-subnet-prefix", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "route-add-cmd", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "route-del-cmd", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "config-per-user", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "config-per-group", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "default-user-config", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "default-group-config", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "match-tls-dtls-ciphers", .type = OPTION_BOOLEAN, .mandatory = 0 },
};

static const tOptionValue* get_option(const char* name, unsigned * mand)
{
unsigned j;

	for (j=0;j<sizeof(available_options)/sizeof(available_options[0]);j++) {
		if (strcasecmp(name, available_options[j].name) == 0) {
			if (mand)
				*mand = available_options[j].mandatory;
			return available_options[j].val;
		}
	}

	return NULL;
}

#define READ_MULTI_LINE(name, s_name, num) { \
	val = get_option(name, &mand); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) { \
		if (add_multi_line_val(config, name, &s_name, &num, pov, val) < 0) { \
			fprintf(stderr, ERRSTR"memory\n"); \
			exit(1); \
		} \
	} else if (mand != 0) { \
		fprintf(stderr, ERRSTR"configuration option %s is mandatory.\n", name); \
		exit(1); \
	}}

#define READ_MULTI_BRACKET_LINE(name, s_name, s_name2, num) { \
	val = get_option(name, &mand); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) { \
		if (s_name == NULL || s_name2 == NULL) { \
			num = 0; \
			s_name = talloc_size(config, sizeof(char*)*DEFAULT_CONFIG_ENTRIES); \
			s_name2 = talloc_size(config, sizeof(char*)*DEFAULT_CONFIG_ENTRIES); \
			if (s_name == NULL || s_name2 == NULL) { \
				fprintf(stderr, ERRSTR"memory\n"); \
				exit(1); \
			} \
		} \
		do { \
		        char *xp; \
		        if (val && strcmp(val->pzName, name)!=0) \
				continue; \
		        s_name[num] = talloc_strdup(config, val->v.strVal); \
		        xp = strchr(s_name[num], '['); if (xp != NULL) *xp = 0; \
		        s_name2[num] = get_brackets_string1(config, val->v.strVal); \
		        num++; \
		        if (num>=DEFAULT_CONFIG_ENTRIES) \
		        break; \
	      } while((val = optionNextValue(pov, val)) != NULL); \
	      s_name[num] = NULL; \
	      s_name2[num] = NULL; \
	} else if (mand != 0) { \
		fprintf(stderr, ERRSTR"configuration option %s is mandatory.\n", name); \
		exit(1); \
	}}

#define PREAD_STRING(pool, name, s_name) { \
	val = get_option(name, &mand); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) { \
		unsigned len = strlen(val->v.strVal); \
		while(c_isspace(val->v.strVal[len-1])) \
			len--; \
		s_name = talloc_strndup(pool, val->v.strVal, len); \
	} else if (mand != 0) { \
		fprintf(stderr, ERRSTR"configuration option %s is mandatory.\n", name); \
		exit(1); \
	}}

#define READ_STRING(name, s_name) \
	PREAD_STRING(config, name, s_name)

#define READ_STATIC_STRING(name, s_name) { \
	val = get_option(name, &mand); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) \
		strlcpy(s_name, val->v.strVal, sizeof(s_name)); \
	else if (mand != 0) { \
		fprintf(stderr, ERRSTR"configuration option %s is mandatory.\n", name); \
		exit(1); \
	}}

#define READ_TF(name, s_name, def) \
	{ char* tmp_tf = NULL; \
		READ_STRING(name, tmp_tf); \
		if (tmp_tf == NULL) s_name = def; \
		else { \
			if (c_strcasecmp(tmp_tf, "true") == 0 || c_strcasecmp(tmp_tf, "yes") == 0) \
				s_name = 1; \
			else \
				s_name = 0; \
		} \
		talloc_free(tmp_tf); \
	}

#define READ_NUMERIC(name, s_name) { \
	val = get_option(name, &mand); \
	if (val != NULL) { \
		if (val->valType == OPARG_TYPE_NUMERIC) \
			s_name = val->v.longVal; \
		else if (val->valType == OPARG_TYPE_STRING) \
			s_name = atoi(val->v.strVal); \
	} else if (mand != 0) { \
		fprintf(stderr, ERRSTR"configuration option %s is mandatory.\n", name); \
		exit(1); \
	}}

#define READ_PRIO_TOS(name, s_name) { \
	val = get_option(name, &mand); \
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
	} else if (mand != 0) { \
		fprintf(stderr, ERRSTR"configuration option %s is mandatory.\n", name); \
		exit(1); \
	}}


static int handle_option(const tOptionValue* val)
{
unsigned j;

	for (j=0;j<sizeof(available_options)/sizeof(available_options[0]);j++) {
		if (strcasecmp(val->pzName, available_options[j].name) == 0) {
			if (available_options[j].val == NULL)
				available_options[j].val = val;
			return 1;
		}
	}

	return 0;
}

static void zero_options(void)
{
unsigned j;

	for (j=0;j<sizeof(available_options)/sizeof(available_options[0]);j++) {
		available_options[j].val = NULL;
	}
}


/* Parses the string ::1/prefix, to return prefix
 * and modify the string to contain the network only.
 */
unsigned extract_prefix(char *network)
{
	char *p;
	unsigned prefix;

	if (network == NULL)
		return 0;

	p = strchr(network, '/');

	if (p == NULL)
		return 0;

	prefix = atoi(p+1);
	*p = 0;

	return prefix;
}

typedef struct auth_types_st {
	const char *name;
	unsigned name_size;
	const struct auth_mod_st *mod;
	unsigned type;
	void *(*get_brackets_string)(struct perm_cfg_st *config, const char *);
} auth_types_st;

#define NAME(x) (x),(sizeof(x)-1)
static auth_types_st avail_auth_types[] =
{
#ifdef HAVE_PAM
	{NAME("pam"), &pam_auth_funcs, AUTH_TYPE_PAM, pam_get_brackets_string},
#endif
#ifdef HAVE_GSSAPI
	{NAME("gssapi"), &gssapi_auth_funcs, AUTH_TYPE_GSSAPI, gssapi_get_brackets_string},
#endif
#ifdef HAVE_RADIUS
	{NAME("radius"), &radius_auth_funcs, AUTH_TYPE_RADIUS, radius_get_brackets_string},
#endif
	{NAME("plain"), &plain_auth_funcs, AUTH_TYPE_PLAIN, plain_get_brackets_string},
	{NAME("certificate"), NULL, AUTH_TYPE_CERTIFICATE, NULL},
};

static void figure_auth_funcs(struct perm_cfg_st *config, char **auth, unsigned auth_size,
			      unsigned primary)
{
	unsigned j, i;
	unsigned found;

	if (auth == NULL)
		return;

	if (primary != 0) {
		/* Set the primary authentication methods */
		for (j=0;j<auth_size;j++) {
			found = 0;
			for (i=0;i<sizeof(avail_auth_types)/sizeof(avail_auth_types[0]);i++) {
				if (c_strncasecmp(auth[j], avail_auth_types[i].name, avail_auth_types[i].name_size) == 0) {
					if (avail_auth_types[i].get_brackets_string)
						config->auth[0].additional = avail_auth_types[i].get_brackets_string(config, auth[j]+avail_auth_types[i].name_size);

					if (config->auth[0].amod != NULL && avail_auth_types[i].mod != NULL) {
						fprintf(stderr, ERRSTR"%s: you cannot mix multiple authentication methods of this type\n", auth[j]);
						exit(1);
					}

					if (config->auth[0].amod == NULL)
						config->auth[0].amod = avail_auth_types[i].mod;
					config->auth[0].type |= avail_auth_types[i].type;
					if (config->auth[0].name == NULL) {
						config->auth[0].name = talloc_strdup(config, avail_auth_types[i].name);
					} else {
						char *tmp;
						tmp = talloc_asprintf(config, "%s+%s", config->auth[0].name, avail_auth_types[i].name);
						talloc_free(config->auth[0].name);
						config->auth[0].name = tmp;
					}
					config->auth[0].enabled = 1;
					config->auth_methods = 1;
					found = 1;
					break;
				}
			}

			if (found == 0) {
				fprintf(stderr, ERRSTR"unknown or unsupported auth method: %s\n", auth[j]);
				exit(1);
			}
			talloc_free(auth[j]);
		}
		fprintf(stderr, NOTESTR"setting '%s' as primary authentication method\n", config->auth[0].name);
	} else {
		unsigned x = config->auth_methods;
		/* Append authentication methods (alternative options) */
		for (j=0;j<auth_size;j++) {
			found = 0;
			for (i=0;i<sizeof(avail_auth_types)/sizeof(avail_auth_types[0]);i++) {
				if (c_strncasecmp(auth[j], avail_auth_types[i].name, avail_auth_types[i].name_size) == 0) {
					if (avail_auth_types[i].get_brackets_string)
						config->auth[x].additional = avail_auth_types[i].get_brackets_string(config, auth[j]+avail_auth_types[i].name_size);
				
					config->auth[x].name = talloc_strdup(config, avail_auth_types[i].name);
					fprintf(stderr, NOTESTR"enabling '%s' as authentication method\n", avail_auth_types[i].name);

					config->auth[x].amod = avail_auth_types[i].mod;
					config->auth[x].type |= avail_auth_types[i].type;
					config->auth[x].enabled = 1;
					found = 1;
					x++;
					if (x >= MAX_AUTH_METHODS) {
						fprintf(stderr, ERRSTR"you cannot enable more than %d authentication methods\n", x);
						exit(1);
					}
					break;
				}
			}

			if (found == 0) {
				fprintf(stderr, ERRSTR"unknown or unsupported auth method: %s\n", auth[j]);
				exit(1);
			}
			talloc_free(auth[j]);
		}
		config->auth_methods = x;
	}
	talloc_free(auth);
}

typedef struct acct_types_st {
	const char *name;
	unsigned name_size;
	const struct acct_mod_st *mod;
	void *(*get_brackets_string)(struct perm_cfg_st *config, const char *);
} acct_types_st;

static acct_types_st avail_acct_types[] =
{
#ifdef HAVE_RADIUS
	{NAME("radius"), &radius_acct_funcs, radius_get_brackets_string},
#endif
#ifdef HAVE_PAM
	{NAME("pam"), &pam_acct_funcs, NULL},
#endif
};

static void figure_acct_funcs(struct perm_cfg_st *config, const char *acct)
{
	unsigned i;
	unsigned found = 0;

	/* Set the accounting method */
	for (i=0;i<sizeof(avail_acct_types)/sizeof(avail_acct_types[0]);i++) {
		if (c_strncasecmp(acct, avail_acct_types[i].name, avail_acct_types[i].name_size) == 0) {
			if (avail_acct_types[i].mod == NULL)
				continue;

			if (avail_acct_types[i].get_brackets_string)
				config->acct.additional = avail_acct_types[i].get_brackets_string(config, acct+avail_acct_types[i].name_size);

			if ((avail_acct_types[i].mod->auth_types & config->auth[0].type) == 0) {
				fprintf(stderr, ERRSTR"you cannot mix the '%s' accounting method with the '%s' authentication method\n", acct, config->auth[0].name);
				exit(1);
			}

			config->acct.amod = avail_acct_types[i].mod;
			config->acct.name = avail_acct_types[i].name;
			found = 1;
			break;
		}
	}

	if (found == 0) {
		fprintf(stderr, ERRSTR"unknown or unsupported accounting method: %s\n", acct);
		exit(1);
	}
	fprintf(stderr, NOTESTR"setting '%s' as accounting method\n", config->acct.name);
}

#ifdef HAVE_GSSAPI
static void parse_kkdcp(struct cfg_st *config, char **urlfw, unsigned urlfw_size)
{
	unsigned i, j;
	char *path, *server, *port, *realm;
	struct addrinfo hints, *res;
	int ret;
	struct kkdcp_st *kkdcp;
	struct kkdcp_realm_st *kkdcp_realm;

	config->kkdcp = talloc_zero_size(config, urlfw_size*sizeof(kkdcp_st));
	if (config->kkdcp == NULL) {
		fprintf(stderr, ERRSTR"memory\n");
		exit(1);
	}

	config->kkdcp_size = 0;

	for (i=0;i<urlfw_size;i++) {
		memset(&hints, 0, sizeof(hints));

		parse_kkdcp_string(urlfw[i], &hints.ai_socktype, &port, &server, &path, &realm);

		ret = getaddrinfo(server, port, &hints, &res);
		if (ret != 0) {
			fprintf(stderr, ERRSTR"getaddrinfo(%s) failed: %s\n", server,
				gai_strerror(ret));
			exit(1);
		}

		kkdcp = NULL;
		/* check if the path is already added */
		for (j=0;j<config->kkdcp_size;j++) {
			if (strcmp(path, config->kkdcp[j].url) == 0) {
				kkdcp = &config->kkdcp[j];
			}
		}

		if (kkdcp == NULL) {
			kkdcp = &config->kkdcp[i];
			kkdcp->url = talloc_strdup(config->kkdcp, path);
			config->kkdcp_size++;
		}

		if (kkdcp->realms_size >= MAX_KRB_REALMS) {
			fprintf(stderr, ERRSTR"reached maximum number (%d) of realms per URL\n", MAX_KRB_REALMS);
			exit(1);
		}

		kkdcp_realm = &kkdcp->realms[kkdcp->realms_size];

		memcpy(&kkdcp_realm->addr, res->ai_addr, res->ai_addrlen);
		kkdcp_realm->addr_len = res->ai_addrlen;
		kkdcp_realm->ai_family = res->ai_family;
		kkdcp_realm->ai_socktype = res->ai_socktype;
		kkdcp_realm->ai_protocol = res->ai_protocol;

		kkdcp_realm->realm = talloc_strdup(config->kkdcp, realm);

		freeaddrinfo(res);  
		kkdcp->realms_size++;
	}

}
#endif


static void append_iroutes_from_file(struct cfg_st *config, const char *file)
{
	tOptionValue const * pov;
	const tOptionValue* val;
	int ret;
	unsigned j;

	pov = configFileLoad(file);
	if (pov == NULL)
		return;

	val = optionGetValue(pov, NULL);
	if (val == NULL)
		goto exit;

	ret = add_multi_line_val(config, "iroute", &config->known_iroutes,
				 &config->known_iroutes_size, pov, val);
	if (ret < 0) {
		fprintf(stderr, ERRSTR"cannot load iroute from %s\n", file);
	}

	for (j=0;j<config->known_iroutes_size;j++) {
		if (ip_route_sanity_check(config->known_iroutes, &config->known_iroutes[j]) != 0)
			exit(1);
	}


 exit:
	optionUnloadNested(pov);
	return;
}

static void load_iroutes(struct cfg_st *config)
{
	DIR *dir;
	struct dirent *r;
	char path[_POSIX_PATH_MAX];

	if (config->per_user_dir == NULL)
		return;

	dir = opendir(config->per_user_dir);
	if (dir != NULL) {
		do {
			r = readdir(dir);
			if (r != NULL && r->d_type == DT_REG) {
				snprintf(path, sizeof(path), "%s/%s", config->per_user_dir, r->d_name);
				append_iroutes_from_file(config, path);
			}
		} while(r != NULL);
		closedir(dir);
	}
}

static void parse_cfg_file(void *pool, const char* file, struct perm_cfg_st *perm_config, unsigned reload)
{
tOptionValue const * pov;
const tOptionValue* val, *prev;
unsigned j, i, mand, ret;
char** auth = NULL;
size_t auth_size = 0;
unsigned prefix = 0, auto_select_group = 0;
unsigned prefix4 = 0;
char *tmp;
unsigned force_cert_auth;
struct cfg_st *config = perm_config->config;
#ifdef HAVE_GSSAPI
char **urlfw = NULL;
size_t urlfw_size = 0;
#endif

	pov = configFileLoad(file);
	if (pov == NULL && file != NULL && strcmp(file, DEFAULT_CFG_FILE) == 0)
		pov = configFileLoad(OLD_DEFAULT_CFG_FILE);

	if (pov == NULL) {
		fprintf(stderr, ERRSTR"cannot load config file %s\n", file);
		exit(1);
	}

	zero_options();

	val = optionGetValue(pov, NULL);
	if (val == NULL) {
		fprintf(stderr, ERRSTR"no configuration directives found.\n");
		exit(1);
	}

	do {
		if (handle_option(val) == 0) {
			fprintf(stderr, WARNSTR"skipping unknown option '%s'\n", val->pzName);
		}
		prev = val;
	} while((val = optionNextValue(pov, prev)) != NULL);

	if (reload == 0) {
		perm_config->sup_config_type = SUP_CONFIG_FILE;

		READ_MULTI_LINE("auth", auth, auth_size);
		figure_auth_funcs(perm_config, auth, auth_size, 1);
		auth = NULL;
		auth_size = 0;

		READ_MULTI_LINE("enable-auth", auth, auth_size);
		figure_auth_funcs(perm_config, auth, auth_size, 0);
		auth = NULL;
		auth_size = 0;

		if (perm_config->auth[0].enabled == 0) {
			fprintf(stderr, ERRSTR"no authentication method was specified!\n");
			exit(1);
		}

		tmp = NULL;
		READ_STRING("acct", tmp);
		if (tmp != NULL) {
			figure_acct_funcs(perm_config, tmp);
			talloc_free(tmp);
		}

		PREAD_STRING(pool, "listen-host", perm_config->listen_host);
		PREAD_STRING(pool, "listen-clear-file", perm_config->unix_conn_file);
		READ_NUMERIC("tcp-port", perm_config->port);
		READ_NUMERIC("udp-port", perm_config->udp_port);

		val = get_option("run-as-user", NULL);
		if (val != NULL && val->valType == OPARG_TYPE_STRING) {
			const struct passwd* pwd = getpwnam(val->v.strVal);
			if (pwd == NULL) {
				fprintf(stderr, ERRSTR"unknown user: %s\n", val->v.strVal);
				exit(1);
			}
			perm_config->uid = pwd->pw_uid;
		}

		val = get_option("run-as-group", NULL);
		if (val != NULL && val->valType == OPARG_TYPE_STRING) {
			const struct group *grp = getgrnam(val->v.strVal);
			if (grp == NULL) {
				fprintf(stderr, ERRSTR"unknown group: %s\n", val->v.strVal);
				exit(1);
			}
			perm_config->gid = grp->gr_gid;
		}

		READ_MULTI_LINE("server-cert", perm_config->cert, perm_config->cert_size);
		READ_MULTI_LINE("server-key", perm_config->key, perm_config->key_size);
		READ_STRING("dh-params", perm_config->dh_params_file);
		READ_STRING("pin-file", perm_config->pin_file);
		READ_STRING("srk-pin-file", perm_config->srk_pin_file);
		READ_STRING("ca-cert", perm_config->ca);

		READ_STRING("key-pin", perm_config->key_pin);
		READ_STRING("srk-pin", perm_config->srk_pin);

		PREAD_STRING(perm_config, "socket-file", perm_config->socket_file_prefix);
		PREAD_STRING(perm_config, "occtl-socket-file", perm_config->occtl_socket_file);
		if (perm_config->occtl_socket_file == NULL)
			perm_config->occtl_socket_file = talloc_strdup(perm_config, OCCTL_UNIX_SOCKET);

		PREAD_STRING(perm_config, "chroot-dir", perm_config->chroot_dir);

		list_head_init(&perm_config->attic);
	}

	perm_config->config = talloc_zero(perm_config, struct cfg_st);
	if (perm_config->config == NULL)
		exit(1);

	config = perm_config->config;
	pool = config;

	config->usage_count = talloc_zero(config, int);
	if (config->usage_count == NULL) {
		fprintf(stderr, ERRSTR"memory\n");
		exit(1);
	}

	/* When adding allocated data, remember to modify
	 * reload_cfg_file();
	 */
	READ_TF("listen-host-is-dyndns", config->is_dyndns, 0);
	READ_TF("listen-proxy-proto", config->listen_proxy_proto, 0);
	READ_TF("append-routes", config->append_routes, 0);

#ifdef HAVE_GSSAPI
	READ_MULTI_LINE("kkdcp", urlfw, urlfw_size);
	if (urlfw_size > 0) {
		parse_kkdcp(config, urlfw, urlfw_size);
		talloc_free(urlfw);
	}
#endif

	READ_TF("tunnel-all-dns", config->tunnel_all_dns, 0);

	READ_NUMERIC("keepalive", config->keepalive);
	READ_NUMERIC("switch-to-tcp-timeout", config->switch_to_tcp_timeout);
	READ_NUMERIC("dpd", config->dpd);
	if (config->dpd == 0)
		config->dpd = DEFAULT_DPD_TIME;

	READ_NUMERIC("mobile-dpd", config->mobile_dpd);
	if (config->mobile_dpd == 0)
		config->mobile_dpd = config->dpd;

	READ_NUMERIC("rate-limit-ms", config->rate_limit_ms);

	READ_STRING("ocsp-response", config->ocsp_response);

	READ_STRING("user-profile", config->xml_config_file);

	READ_STRING("default-domain", config->default_domain);
	READ_STRING("crl", config->crl);
	READ_STRING("cert-user-oid", config->cert_user_oid);
	READ_STRING("cert-group-oid", config->cert_group_oid);

	READ_STRING("connect-script", config->connect_script);
	READ_STRING("host-update-script", config->host_update_script);
	READ_STRING("disconnect-script", config->disconnect_script);

	if (reload == 0 && pid_file[0] == 0)
		READ_STATIC_STRING("pid-file", pid_file);


	val = get_option("session-control", NULL);
	if (val != NULL) {
		fprintf(stderr, WARNSTR"the option 'session-control' is deprecated\n");
	}

	READ_STRING("banner", config->banner);

	READ_TF("dtls-legacy", config->dtls_legacy, 1);
	READ_TF("cisco-client-compat", config->cisco_client_compat, 0);
	if (config->cisco_client_compat) {
		if (!config->dtls_legacy) {
			fprintf(stderr, NOTESTR"the cisco-client-compat option implies dtls-legacy = true; enabling\n");
		}
		config->dtls_legacy = 1;
	}

	READ_TF("always-require-cert", force_cert_auth, 1);
	if (force_cert_auth == 0) {
		fprintf(stderr, NOTESTR"'always-require-cert' was replaced by 'cisco-client-compat'\n");
		config->cisco_client_compat = 1;
	}

	READ_TF("dtls-psk", config->dtls_psk, 1);
	READ_TF("match-tls-dtls-ciphers", config->match_dtls_and_tls, 0);
	if (config->match_dtls_and_tls) {
		if (config->dtls_legacy) {
			fprintf(stderr, ERRSTR"'match-tls-dtls-ciphers' cannot be applied when 'dtls-legacy' or 'cisco-client-compat' is on\n");
			exit(1);
		}
	}

	READ_TF("compression", config->enable_compression, 0);
	READ_NUMERIC("no-compress-limit", config->no_compress_limit);
	if (config->no_compress_limit == 0)
		config->no_compress_limit = DEFAULT_NO_COMPRESS_LIMIT;
	if (config->no_compress_limit < MIN_NO_COMPRESS_LIMIT)
		config->no_compress_limit = MIN_NO_COMPRESS_LIMIT;

	READ_TF("use-seccomp", config->isolate, 0);
	if (config->isolate) {
		fprintf(stderr, NOTESTR"'use-seccomp' was replaced by 'isolate-workers'\n");
	} else {
		READ_TF("isolate-workers", config->isolate, 0);
	}
#if !defined(HAVE_LIBSECCOMP)
	if (config->isolate != 0) {
		fprintf(stderr, ERRSTR"'isolate-workers' is set to true, but not compiled with seccomp or Linux namespaces support\n");
	}
#endif

	READ_TF("predictable-ips", config->predictable_ips, 1);
	READ_TF("use-utmp", config->use_utmp, 1);
	READ_TF("use-dbus", config->use_dbus, 0);
	if (config->use_dbus != 0) {
		fprintf(stderr, NOTESTR"'use-dbus' was replaced by 'use-occtl'\n");
		config->use_occtl = config->use_dbus;
	} else {
		READ_TF("use-occtl", config->use_occtl, 0);
		if (config->use_occtl == 0)
			config->use_dbus = 0;
		else
			config->use_dbus = 1;
	}

	READ_TF("try-mtu-discovery", config->try_mtu, 0);
	READ_TF("ping-leases", config->ping_leases, 0);

	READ_TF("restrict-user-to-routes", config->restrict_user_to_routes, 0);

	tmp = NULL;
	READ_STRING("restrict-user-to-ports", tmp);
	if (tmp) {
		ret = cfg_parse_ports(pool, &config->fw_ports, &config->n_fw_ports, tmp);
		if (ret < 0) {
			fprintf(stderr, ERRSTR"cannot parse restrict-user-to-ports\n");
			exit(1);
		}
		talloc_free(tmp);
	}

	READ_STRING("tls-priorities", config->priorities);

	READ_NUMERIC("mtu", config->default_mtu);

	READ_PRIO_TOS("net-priority", config->net_priority);

	READ_NUMERIC("output-buffer", config->output_buffer);

	READ_NUMERIC("rx-data-per-sec", config->rx_per_sec);
	READ_NUMERIC("tx-data-per-sec", config->tx_per_sec);
	config->rx_per_sec /= 1000; /* in kb */
	config->tx_per_sec /= 1000;

	READ_TF("deny-roaming", config->deny_roaming, 0);

	READ_NUMERIC("stats-report-time", config->stats_report_time);

	config->rekey_time = -1;
	READ_NUMERIC("rekey-time", config->rekey_time);
	if (config->rekey_time == -1) {
		config->rekey_time = 24*60*60;
	}

	tmp = NULL;
	READ_STRING("rekey-method", tmp);
	if (tmp == NULL || strcmp(tmp, "ssl") == 0)
		config->rekey_method = REKEY_METHOD_SSL;
	else if (strcmp(tmp, "new-tunnel") == 0)
		config->rekey_method = REKEY_METHOD_NEW_TUNNEL;
	else {
		fprintf(stderr, ERRSTR"unknown rekey method '%s'\n", tmp);
		exit(1);
	}
	talloc_free(tmp); tmp = NULL;

	READ_NUMERIC("cookie-timeout", config->cookie_timeout);
	if (config->cookie_timeout == 0)
		config->cookie_timeout = DEFAULT_COOKIE_RECON_TIMEOUT;
	READ_TF("persistent-cookies", config->persistent_cookies, 0);

	READ_NUMERIC("session-timeout", config->session_timeout);

	READ_NUMERIC("auth-timeout", config->auth_timeout);
	if (config->auth_timeout == 0) {
		config->auth_timeout = DEFAULT_AUTH_TIMEOUT_SECS;
	}

	READ_NUMERIC("idle-timeout", config->idle_timeout);

	config->mobile_idle_timeout = -1;
	READ_NUMERIC("mobile-idle-timeout", config->mobile_idle_timeout);
	if (config->mobile_idle_timeout == -1)
		config->mobile_idle_timeout = config->idle_timeout;

	READ_NUMERIC("max-clients", config->max_clients);
	READ_NUMERIC("min-reauth-time", config->min_reauth_time);
	config->ban_reset_time = -1;
	READ_NUMERIC("ban-reset-time", config->ban_reset_time);
	if (config->ban_reset_time == -1)
		config->ban_reset_time = DEFAULT_BAN_RESET_TIME;

	config->max_ban_score = -1;
	READ_NUMERIC("max-ban-score", config->max_ban_score);
	if (config->max_ban_score == -1)
		config->max_ban_score = DEFAULT_MAX_BAN_SCORE;

	config->ban_points_wrong_password = DEFAULT_PASSWORD_POINTS;
	READ_NUMERIC("ban-points-wrong-password", config->ban_points_wrong_password);
	config->ban_points_connect = DEFAULT_CONNECT_POINTS;
	READ_NUMERIC("ban-points-connection", config->ban_points_connect);
	config->ban_points_kkdcp = DEFAULT_KKDCP_POINTS;
	READ_NUMERIC("ban-points-kkdcp", config->ban_points_kkdcp);

	READ_NUMERIC("max-same-clients", config->max_same_clients);

	READ_STATIC_STRING("device", config->network.name);
	READ_STRING("cgroup", config->cgroup);
	READ_STRING("proxy-url", config->proxy_url);

	READ_STRING("ipv4-network", config->network.ipv4);

	prefix4 = extract_prefix(config->network.ipv4);
	if (prefix4 == 0) {
		READ_STRING("ipv4-netmask", config->network.ipv4_netmask);
	} else {
		config->network.ipv4_netmask = ipv4_prefix_to_strmask(config, prefix4);
	}

	READ_STRING("ipv6-network", config->network.ipv6);
	/* read subnet prefix */
	READ_NUMERIC("ipv6-subnet-prefix", prefix);
	if (prefix > 0) {
		config->network.ipv6_subnet_prefix = prefix;

		if (valid_ipv6_prefix(prefix) == 0) {
			fprintf(stderr, ERRSTR"invalid IPv6 subnet prefix: %u\n", prefix);
			exit(1);
		}
	}

	/* read net prefix */
	prefix = extract_prefix(config->network.ipv6);
	if (prefix == 0) {
		READ_NUMERIC("ipv6-prefix", prefix);
	}

	if (prefix > 0) {
		config->network.ipv6_prefix = prefix;

		if (valid_ipv6_prefix(prefix) == 0) {
			fprintf(stderr, ERRSTR"invalid IPv6 prefix: %u\n", prefix);
			exit(1);
		}
	}

	if (config->network.ipv6_subnet_prefix == 0) {
		config->network.ipv6_subnet_prefix = 128;
	} else if (config->network.ipv6_prefix >= config->network.ipv6_subnet_prefix) {
		fprintf(stderr, ERRSTR"the subnet prefix (%u) cannot be smaller or equal to network's (%u)\n", 
				config->network.ipv6_subnet_prefix, config->network.ipv6_prefix);
		exit(1);
	}

	READ_MULTI_LINE("custom-header", config->custom_header, config->custom_header_size);
	READ_MULTI_LINE("split-dns", config->split_dns, config->split_dns_size);

	READ_MULTI_LINE("route", config->network.routes, config->network.routes_size);
	for (j=0;j<config->network.routes_size;j++) {
		if (ip_route_sanity_check(config->network.routes, &config->network.routes[j]) != 0)
			exit(1);

		if (strcmp(config->network.routes[j], "0.0.0.0/0") == 0 ||
		    strcmp(config->network.routes[j], "default") == 0) {
		    	/* set default route */
			for (i=0;i<j;i++)
				talloc_free(config->network.routes[i]);
			config->network.routes_size = 0;
			break;
		}
	}

	READ_MULTI_LINE("no-route", config->network.no_routes, config->network.no_routes_size);
	for (j=0;j<config->network.no_routes_size;j++) {
		if (ip_route_sanity_check(config->network.no_routes, &config->network.no_routes[j]) != 0)
			exit(1);
	}

	READ_STRING("default-select-group", config->default_select_group);
	READ_TF("auto-select-group", auto_select_group, 0);

	if (auto_select_group != 0 && perm_config->auth[0].amod != NULL && perm_config->auth[0].amod->group_list != NULL) {
		perm_config->auth[0].amod->group_list(config, perm_config->auth[0].additional, &config->group_list, &config->group_list_size);
	} else {
		READ_MULTI_BRACKET_LINE("select-group",
				config->group_list,
				config->friendly_group_list,
				config->group_list_size);
	}

	READ_MULTI_LINE("dns", config->network.dns, config->network.dns_size);
	if (config->network.dns_size == 0) {
		/* try the aliases */
		READ_MULTI_LINE("ipv6-dns", config->network.dns, config->network.dns_size);
		READ_MULTI_LINE("ipv4-dns", config->network.dns, config->network.dns_size);
	}

	for (j=0;j<config->network.dns_size;j++) {
		if (strcmp(config->network.dns[j], "local") == 0) {
			fprintf(stderr, ERRSTR"the 'local' DNS keyword is no longer supported.\n");
			exit(1);
		}
	}

	READ_MULTI_LINE("nbns", config->network.nbns, config->network.nbns_size);
	if (config->network.nbns_size == 0) {
		/* try the aliases */
		READ_MULTI_LINE("ipv6-nbns", config->network.nbns, config->network.nbns_size);
		READ_MULTI_LINE("ipv4-nbns", config->network.nbns, config->network.nbns_size);
	}

	READ_STRING("route-add-cmd", config->route_add_cmd);
	READ_STRING("route-del-cmd", config->route_del_cmd);
	READ_STRING("config-per-user", config->per_user_dir);
	READ_STRING("config-per-group", config->per_group_dir);

	if (config->per_user_dir || config->per_group_dir) {
		if (perm_config->sup_config_type != SUP_CONFIG_FILE) {
			fprintf(stderr, ERRSTR"specified config-per-user or config-per-group but supplemental config is '%s'\n",
				sup_config_name(perm_config->sup_config_type));
			exit(1);
		}
	}

	if (config->per_user_dir) {
		READ_TF("expose-iroutes", i, 0);
		if (i != 0) {
			load_iroutes(config);
		}
	}

	READ_STRING("default-user-config", config->default_user_conf);
	READ_STRING("default-group-config", config->default_group_conf);

	fprintf(stderr, NOTESTR"setting '%s' as supplemental config option\n", sup_config_name(perm_config->sup_config_type));

	optionUnloadNested(pov);
}


/* sanity checks on config */
static void check_cfg(struct perm_cfg_st *perm_config)
{
	if (perm_config->config->network.ipv4 == NULL && perm_config->config->network.ipv6 == NULL) {
		fprintf(stderr, ERRSTR"no ipv4-network or ipv6-network options set.\n");
		exit(1);
	}

	if (perm_config->config->network.ipv4 != NULL && perm_config->config->network.ipv4_netmask == NULL) {
		fprintf(stderr, ERRSTR"no mask found for IPv4 network.\n");
		exit(1);
	}

	if (perm_config->config->network.ipv6 != NULL && perm_config->config->network.ipv6_prefix == 0) {
		fprintf(stderr, ERRSTR"no prefix found for IPv6 network.\n");
		exit(1);
	}

	if (perm_config->config->banner && strlen(perm_config->config->banner) > MAX_BANNER_SIZE) {
		fprintf(stderr, ERRSTR"banner size is too long\n");
		exit(1);
	}

	if (perm_config->cert_size != perm_config->key_size) {
		fprintf(stderr, ERRSTR"the specified number of keys doesn't match the certificates\n");
		exit(1);
	}

	if (perm_config->auth[0].type & AUTH_TYPE_CERTIFICATE && perm_config->auth_methods == 1) {
		if (perm_config->config->cisco_client_compat == 0)
			perm_config->config->cert_req = GNUTLS_CERT_REQUIRE;
		else
			perm_config->config->cert_req = GNUTLS_CERT_REQUEST;
	} else {
		unsigned i;
		for (i=0;i<perm_config->auth_methods;i++) {
			if (perm_config->auth[i].type & AUTH_TYPE_CERTIFICATE) {
				perm_config->config->cert_req = GNUTLS_CERT_REQUEST;
				break;
			}
		}
	}

	if (perm_config->config->cert_req != 0 && perm_config->config->cert_user_oid == NULL) {
		fprintf(stderr, ERRSTR"a certificate is requested by the option 'cert-user-oid' is not set\n");
		exit(1);
	}

	if (perm_config->unix_conn_file != NULL && (perm_config->config->cert_req != 0)) {
		if (perm_config->config->listen_proxy_proto == 0) {
			fprintf(stderr, ERRSTR"the option 'listen-clear-file' cannot be combined with 'auth=certificate'\n");
			exit(1);
		}
	}

	if (perm_config->cert && perm_config->cert_hash == NULL) {
		perm_config->cert_hash = calc_sha1_hash(perm_config, perm_config->cert[0], 1);
	}

	if (perm_config->config->xml_config_file) {
		perm_config->config->xml_config_hash = calc_sha1_hash(perm_config->config, perm_config->config->xml_config_file, 0);
		if (perm_config->config->xml_config_hash == NULL && perm_config->chroot_dir != NULL) {
			char path[_POSIX_PATH_MAX];

			snprintf(path, sizeof(path), "%s/%s", perm_config->chroot_dir, perm_config->config->xml_config_file);
			perm_config->config->xml_config_hash = calc_sha1_hash(perm_config->config, path, 0);

			if (perm_config->config->xml_config_hash == NULL) {
				fprintf(stderr, ERRSTR"cannot open file '%s'\n", path);
				exit(1);
			}
		}
		if (perm_config->config->xml_config_hash == NULL) {
			fprintf(stderr, ERRSTR"cannot open file '%s'\n", perm_config->config->xml_config_file);
			exit(1);
		}
	}

	if (perm_config->config->keepalive == 0)
		perm_config->config->keepalive = 3600;

	if (perm_config->config->dpd == 0)
		perm_config->config->dpd = 60;

	if (perm_config->config->priorities == NULL)
		perm_config->config->priorities = talloc_strdup(perm_config->config, "NORMAL:%SERVER_PRECEDENCE:%COMPAT");
}

int cmd_parser (void *pool, int argc, char **argv, struct perm_cfg_st** config)
{
	*config = talloc_zero(pool, struct perm_cfg_st);
	if (*config == NULL)
		exit(1);

	optionProcess( &ocservOptions, argc, argv);
  
	if (HAVE_OPT(FOREGROUND))
		(*config)->foreground = 1;

	if (HAVE_OPT(PID_FILE)) {
		strlcpy(pid_file, OPT_ARG(PID_FILE), sizeof(pid_file));
	}

	if (HAVE_OPT(DEBUG))
		(*config)->debug = OPT_VALUE_DEBUG;

	if (HAVE_OPT(CONFIG)) {
		strlcpy(cfg_file, OPT_ARG(CONFIG), sizeof(cfg_file));
	} else if (access(cfg_file, R_OK) != 0) {
		fprintf(stderr, "%s -c [config]\nUse %s --help for more information.\n", argv[0], argv[0]);
		exit(1);
	}

	parse_cfg_file(pool, cfg_file, *config, 0);

	check_cfg(*config);

	if (HAVE_OPT(TEST_CONFIG))
		exit(0);

	return 0;

}

static void archive_cfg(struct perm_cfg_st* perm_config)
{
	attic_entry_st *e;

	/* we don't clear anything as it may be referenced by some
	 * client (proc_st). We move everything to attic and
	 * once nothing is in use we clear that */

	e = talloc(perm_config, attic_entry_st);
	if (e == NULL) {
		/* we leak, but better than crashing */
		return;
	}

	e->usage_count = perm_config->config->usage_count;

	/* we rely on talloc doing that recursively */
	talloc_steal(e, perm_config->config);
	perm_config->config = NULL;

	if (e->usage_count == NULL || *e->usage_count == 0) {
		talloc_free(e);
	} else {
		list_add(&perm_config->attic, &e->list);
	}

	return;
}

void clear_cfg(struct perm_cfg_st* perm_config)
{
	/* we rely on talloc doing that recursively */
	talloc_free(perm_config->config);
	perm_config->config = NULL;

	return;
}

static void append(const char *option)
{
	static int have_previous_val = 0;

	if (have_previous_val == 0) {
		have_previous_val = 1;
	} else {
		fprintf(stderr, ", ");
	}
	fprintf(stderr, "%s", option);
}

void print_version(tOptions *opts, tOptDesc *desc)
{
	const char *p;

	fputs(OCSERV_FULL_VERSION, stderr);
	fprintf(stderr, "\n\nCompiled with: ");
#ifdef HAVE_LIBSECCOMP
	append("seccomp");
#endif
#ifdef HAVE_LIBWRAP
	append("tcp-wrappers");
#endif
#ifdef HAVE_LIBOATH
	append("oath");
#endif
#ifdef HAVE_RADIUS
	append("radius");
#endif
#ifdef HAVE_GSSAPI
	append("gssapi");
#endif
#ifdef HAVE_PAM
	append("PAM");
#endif
#ifdef HAVE_PKCS11
	append("PKCS#11");
#endif
#ifdef ANYCONNECT_CLIENT_COMPAT
	append("AnyConnect");
#endif
	fprintf(stderr, "\n");

	p = gnutls_check_version(NULL);
	if (strcmp(p, GNUTLS_VERSION) != 0) {
		fprintf(stderr, "GnuTLS version: %s (compiled with %s)\n", p, GNUTLS_VERSION);
	} else {
		fprintf(stderr, "GnuTLS version: %s\n", p);
	}

	exit(0);
}


void reload_cfg_file(void *pool, struct perm_cfg_st* perm_config, unsigned archive)
{
	if (archive)
		archive_cfg(perm_config);
	else
		clear_cfg(perm_config);

	parse_cfg_file(pool, cfg_file, perm_config, 1);

	check_cfg(perm_config);

	return;
}

void write_pid_file(void)
{
FILE* fp;

	if (pid_file[0]==0)
		return;

	fp = fopen(pid_file, "w");
	if (fp == NULL) {
		fprintf(stderr, ERRSTR"cannot open pid file '%s'\n", pid_file);
		exit(1);
	}

	fprintf(fp, "%u", (unsigned)getpid());
	fclose(fp);
}

void remove_pid_file(void)
{
	if (pid_file[0]==0)
		return;

	remove(pid_file);
}

int add_multi_line_val(void *pool, const char *name, char ***s_name, size_t *num,
		       tOptionValue const *pov,
		       const tOptionValue *val)
{
	unsigned _max = DEFAULT_CONFIG_ENTRIES;
	void *tmp;

	if (*s_name == NULL) {
		*num = 0;
		*s_name = talloc_array(pool, char*, _max);
		if (*s_name == NULL)
			return -1;
	}

	do {
	        if (val && strcmp(val->pzName, name)!=0)
			continue;

	        if (*num >= _max-1) {
	        	_max += 128;
	        	tmp = talloc_realloc(pool, *s_name, char*, _max);
			if (tmp == NULL)
				return -1;
			*s_name = tmp;
	        }

	        (*s_name)[*num] = talloc_strdup(*s_name, val->v.strVal);
	        (*num)++;
      } while((val = optionNextValue(pov, val)) != NULL);
      (*s_name)[*num] = NULL;
      return 0;
}

void clear_old_configs(struct perm_cfg_st* config)
{
	attic_entry_st *e, *pos;

	/* go through the attic and clear old configurations if unused */
	list_for_each_safe(&config->attic, e, pos, list) {
		if (*e->usage_count == 0) {
			list_del(&e->list);
			talloc_free(e);
		}
	}
}
