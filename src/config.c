/*
 * Copyright (C) 2013, 2014 Nikos Mavrogiannopoulos
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
#include <c-ctype.h>
#include <auth/pam.h>
#include <auth/plain.h>

#include <vpn.h>
#include <cookies.h>
#include <main.h>
#include <ctl.h>
#include <tlslib.h>

#define OLD_DEFAULT_CFG_FILE "/etc/ocserv.conf"
#define DEFAULT_CFG_FILE "/etc/ocserv/ocserv.conf"

static char pid_file[_POSIX_PATH_MAX] = "";
static const char* cfg_file = DEFAULT_CFG_FILE;

struct cfg_options {
	const char* name;
	unsigned type;
	unsigned mandatory;
	const tOptionValue* val;
};

static struct cfg_options available_options[] = {
	{ .name = "auth", .type = OPTION_MULTI_LINE, .mandatory = 1 },
	{ .name = "route", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "select-group", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "custom-header", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "split-dns", .type = OPTION_MULTI_LINE, .mandatory = 0 },
	{ .name = "listen-host", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "tcp-port", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "udp-port", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "keepalive", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "dpd", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "mobile-dpd", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "rate-limit-ms", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "ocsp-response", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "server-cert", .type = OPTION_STRING, .mandatory = 1 },
	{ .name = "server-key", .type = OPTION_STRING, .mandatory = 1 },
	{ .name = "dh-params", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "pin-file", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "srk-pin-file", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "user-profile", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "ca-cert", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "default-domain", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "crl", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "cert-user-oid", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "cert-group-oid", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "connect-script", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "disconnect-script", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "pid-file", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "socket-file", .type = OPTION_STRING, .mandatory = 1 },
	{ .name = "listen-clear-file", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "occtl-socket-file", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "banner", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "use-seccomp", .type = OPTION_BOOLEAN, .mandatory = 0 },
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
	{ .name = "use-occtl", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "try-mtu-discovery", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "ping-leases", .type = OPTION_BOOLEAN, .mandatory = 0 },
	{ .name = "tls-priorities", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "chroot-dir", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "mtu", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "net-priority", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "output-buffer", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "cookie-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "rekey-time", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "rekey-method", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "auth-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "idle-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "mobile-idle-timeout", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "max-clients", .type = OPTION_NUMERIC, .mandatory = 0 },
	{ .name = "min-reauth-time", .type = OPTION_NUMERIC, .mandatory = 0 },
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
	{ .name = "route-add-cmd", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "route-del-cmd", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "config-per-user", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "config-per-group", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "default-user-config", .type = OPTION_STRING, .mandatory = 0 },
	{ .name = "default-group-config", .type = OPTION_STRING, .mandatory = 0 },
};

static char *get_brackets_string(void *pool, const char *str);

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
		if (s_name == NULL) { \
			num = 0; \
			s_name = talloc_size(config, sizeof(char*)*MAX_CONFIG_ENTRIES); \
			if (s_name == NULL) { \
				fprintf(stderr, "memory error\n"); \
				exit(1); \
			} \
		} \
		do { \
		        if (val && !strcmp(val->pzName, name)==0) \
				continue; \
		        s_name[num] = talloc_strdup(config, val->v.strVal); \
		        num++; \
		        if (num>=MAX_CONFIG_ENTRIES) \
		        break; \
	      } while((val = optionNextValue(pov, val)) != NULL); \
	      s_name[num] = NULL; \
	} else if (mand != 0) { \
		fprintf(stderr, "Configuration option %s is mandatory.\n", name); \
		exit(1); \
	}}

#define READ_MULTI_BRACKET_LINE(name, s_name, s_name2, num) { \
	val = get_option(name, &mand); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) { \
		if (s_name == NULL || s_name2 == NULL) { \
			num = 0; \
			s_name = talloc_size(config, sizeof(char*)*MAX_CONFIG_ENTRIES); \
			s_name2 = talloc_size(config, sizeof(char*)*MAX_CONFIG_ENTRIES); \
			if (s_name == NULL || s_name2 == NULL) { \
				fprintf(stderr, "memory error\n"); \
				exit(1); \
			} \
		} \
		do { \
		        char *xp; \
		        if (val && !strcmp(val->pzName, name)==0) \
				continue; \
		        s_name[num] = talloc_strdup(config, val->v.strVal); \
		        xp = strchr(s_name[num], '['); if (xp != NULL) *xp = 0; \
		        s_name2[num] = get_brackets_string(config, val->v.strVal); \
		        num++; \
		        if (num>=MAX_CONFIG_ENTRIES) \
		        break; \
	      } while((val = optionNextValue(pov, val)) != NULL); \
	      s_name[num] = NULL; \
	      s_name2[num] = NULL; \
	} else if (mand != 0) { \
		fprintf(stderr, "Configuration option %s is mandatory.\n", name); \
		exit(1); \
	}}

#define READ_STRING(name, s_name) { \
	val = get_option(name, &mand); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) \
		s_name = talloc_strdup(config, val->v.strVal); \
	else if (mand != 0) { \
		fprintf(stderr, "Configuration option %s is mandatory.\n", name); \
		exit(1); \
	}}

#define READ_STATIC_STRING(name, s_name) { \
	val = get_option(name, &mand); \
	if (val != NULL && val->valType == OPARG_TYPE_STRING) \
		snprintf(s_name, sizeof(s_name), "%s", val->v.strVal); \
	else if (mand != 0) { \
		fprintf(stderr, "Configuration option %s is mandatory.\n", name); \
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
		fprintf(stderr, "Configuration option %s is mandatory.\n", name); \
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
		fprintf(stderr, "Configuration option %s is mandatory.\n", name); \
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

static char *get_brackets_string(void *pool, const char *str)
{
	char *p, *p2;
	unsigned len;

	p = strchr(str, '[');
	if (p == NULL) {
		return NULL;
	}
	p++;
	while (c_isspace(*p))
		p++;

	p2 = strchr(p, ']');
	if (p2 == NULL) {
		fprintf(stderr, "error parsing %s\n", str);
		exit(1);
	}

	len = p2 - p;

	return talloc_strndup(pool, p, len);
}

static void parse_cfg_file(const char* file, struct cfg_st *config, unsigned reload)
{
tOptionValue const * pov;
const tOptionValue* val, *prev;
unsigned j, i, mand;
char** auth = NULL;
unsigned auth_size = 0;
unsigned prefix = 0, auto_select_group = 0;
const struct auth_mod_st *amod = NULL;
char *tmp;
unsigned force_cert_auth;

	pov = configFileLoad(file);
	if (pov == NULL && file != NULL && strcmp(file, DEFAULT_CFG_FILE) == 0)
		pov = configFileLoad(OLD_DEFAULT_CFG_FILE);

	if (pov == NULL) {
		fprintf(stderr, "Error loading config file %s\n", file);
		exit(1);
	}

	zero_options();

	val = optionGetValue(pov, NULL);
	if (val == NULL) {
		fprintf(stderr, "No configuration directives found.\n");
		exit(1);
	}

	do {
		if (handle_option(val) == 0) {
			fprintf(stderr, "Skipping unknown option '%s'\n", val->pzName);
		}
		prev = val;
	} while((val = optionNextValue(pov, prev)) != NULL);

	READ_MULTI_LINE("auth", auth, auth_size);
	for (j=0;j<auth_size;j++) {
		if (c_strncasecmp(auth[j], "pam", 3) == 0) {
			config->auth_additional = get_brackets_string(config, auth[j]+3);
			if ((config->auth_types & AUTH_TYPE_USERNAME_PASS) != 0) {
				fprintf(stderr, "You cannot mix multiple username/password authentication methods\n");
				exit(1);
			}
#ifdef HAVE_PAM
			config->auth_types |= AUTH_TYPE_PAM;
			amod = &pam_auth_funcs;
#else
			fprintf(stderr, "PAM support is disabled\n");
			exit(1);
#endif
		} else if (strncasecmp(auth[j], "plain", 5) == 0) {
			if ((config->auth_types & AUTH_TYPE_USERNAME_PASS) != 0) {
				fprintf(stderr, "You cannot mix multiple username/password authentication methods\n");
				exit(1);
			}

			config->auth_additional = get_brackets_string(config, auth[j]+5);
			if (config->auth_additional == NULL) {
				fprintf(stderr, "Format error in %s\n", auth[j]);
				exit(1);
			}
			amod = &plain_auth_funcs;
			config->auth_types |= AUTH_TYPE_PLAIN;
		} else if (c_strcasecmp(auth[j], "certificate") == 0) {
			config->auth_types |= AUTH_TYPE_CERTIFICATE;
		} else if (c_strcasecmp(auth[j], "certificate[optional]") == 0) {
			config->auth_types |= AUTH_TYPE_CERTIFICATE_OPT;
		} else {
			fprintf(stderr, "Unknown auth method: %s\n", auth[j]);
			exit(1);
		}
		talloc_free(auth[j]);
	}
	talloc_free(auth);

	/* When adding allocated data, remember to modify
	 * reload_cfg_file();
	 */
	READ_STRING("listen-host", config->name);

	READ_NUMERIC("tcp-port", config->port);
	READ_NUMERIC("udp-port", config->udp_port);
	READ_NUMERIC("keepalive", config->keepalive);
	READ_NUMERIC("dpd", config->dpd);
	if (config->dpd == 0)
		config->dpd = DEFAULT_DPD_TIME;

	READ_NUMERIC("mobile-dpd", config->mobile_dpd);
	if (config->mobile_dpd == 0)
		config->mobile_dpd = config->dpd;

	READ_NUMERIC("rate-limit-ms", config->rate_limit_ms);

	READ_STRING("ocsp-response", config->ocsp_response);
	READ_MULTI_LINE("server-cert", config->cert, config->cert_size);
	READ_MULTI_LINE("server-key", config->key, config->key_size);
	READ_STRING("dh-params", config->dh_params_file);
	READ_STRING("pin-file", config->pin_file);
	READ_STRING("srk-pin-file", config->srk_pin_file);
#ifdef ANYCONNECT_CLIENT_COMPAT
	READ_STRING("user-profile", config->xml_config_file);
#endif

	READ_STRING("ca-cert", config->ca);
	READ_STRING("default-domain", config->default_domain);
	READ_STRING("crl", config->crl);
	READ_STRING("cert-user-oid", config->cert_user_oid);
	READ_STRING("cert-group-oid", config->cert_group_oid);

	READ_STRING("connect-script", config->connect_script);
	READ_STRING("disconnect-script", config->disconnect_script);

	if (reload == 0 && pid_file[0] == 0)
		READ_STATIC_STRING("pid-file", pid_file);

	READ_STRING("listen-clear-file", config->unix_conn_file);
	if (config->unix_conn_file != NULL && (config->auth_types & AUTH_TYPE_CERTIFICATE)) {
		fprintf(stderr, "The option 'listen-clear-file' cannot be combined with 'auth=certificate'\n");
		exit(1);
	}

	READ_STRING("socket-file", config->socket_file_prefix);
	READ_STRING("occtl-socket-file", config->occtl_socket_file);
	if (config->occtl_socket_file == NULL)
		config->occtl_socket_file = talloc_strdup(config, OCCTL_UNIX_SOCKET);

	if (config->auth_types & AUTH_TYPE_USERNAME_PASS) {
		READ_TF("session-control", config->session_control, 0);
	}

	READ_STRING("banner", config->banner);
	READ_TF("cisco-client-compat", config->cisco_client_compat, 0);
	READ_TF("always-require-cert", force_cert_auth, 1);
	if (force_cert_auth == 0) {
		fprintf(stderr, "note that 'always-require-cert' was replaced by 'cisco-client-compat'\n");
		config->cisco_client_compat = 1;
	}

	READ_TF("use-seccomp", config->seccomp, 0);
	READ_TF("predictable-ips", config->predictable_ips, 1);
	READ_TF("use-utmp", config->use_utmp, 1);
	READ_TF("use-dbus", config->use_dbus, 0);
	if (config->use_dbus != 0) {
		fprintf(stderr, "note that 'use-dbus' was replaced by 'use-occtl'\n");
		config->use_occtl = config->use_dbus;
	} else {
		READ_TF("use-occtl", config->use_occtl, 0);
		if (config->use_occtl == 0)
			config->use_dbus = 0;
	}

	READ_TF("try-mtu-discovery", config->try_mtu, 0);
	READ_TF("ping-leases", config->ping_leases, 0);

	READ_STRING("tls-priorities", config->priorities);
	READ_STRING("chroot-dir", config->chroot_dir);

	READ_NUMERIC("mtu", config->default_mtu);

	READ_PRIO_TOS("net-priority", config->net_priority);

	READ_NUMERIC("output-buffer", config->output_buffer);

	READ_NUMERIC("rx-data-per-sec", config->rx_per_sec);
	READ_NUMERIC("tx-data-per-sec", config->tx_per_sec);
	config->rx_per_sec /= 1000; /* in kb */
	config->tx_per_sec /= 1000;

	READ_TF("deny-roaming", config->deny_roaming, 0);

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
		fprintf(stderr, "Unknown rekey method '%s'\n", tmp);
		exit(1);
	}
	talloc_free(tmp); tmp = NULL;

	READ_NUMERIC("cookie-timeout", config->cookie_timeout);
	if (config->cookie_timeout == 0)
		config->cookie_timeout = DEFAULT_COOKIE_RECON_TIMEOUT;

	READ_NUMERIC("auth-timeout", config->auth_timeout);
	READ_NUMERIC("idle-timeout", config->idle_timeout);

	config->mobile_idle_timeout = -1;
	READ_NUMERIC("mobile-idle-timeout", config->mobile_idle_timeout);
	if (config->mobile_idle_timeout == -1)
		config->mobile_idle_timeout = config->idle_timeout;

	READ_NUMERIC("max-clients", config->max_clients);
	READ_NUMERIC("min-reauth-time", config->min_reauth_time);
	READ_NUMERIC("max-same-clients", config->max_same_clients);

	val = get_option("run-as-user", NULL);
	if (val != NULL && val->valType == OPARG_TYPE_STRING) {
		const struct passwd* pwd = getpwnam(val->v.strVal);
		if (pwd == NULL) {
			fprintf(stderr, "Unknown user: %s\n", val->v.strVal);
			exit(1);
		}
		config->uid = pwd->pw_uid;
	}

	val = get_option("run-as-group", NULL);
	if (val != NULL && val->valType == OPARG_TYPE_STRING) {
		const struct group *grp = getgrnam(val->v.strVal);
		if (grp == NULL) {
			fprintf(stderr, "Unknown group: %s\n", val->v.strVal);
			exit(1);
		}
		config->gid = grp->gr_gid;
	}

	READ_STATIC_STRING("device", config->network.name);
	READ_STRING("cgroup", config->cgroup);
	READ_STRING("proxy-url", config->proxy_url);

	READ_STRING("ipv4-network", config->network.ipv4);
	READ_STRING("ipv4-netmask", config->network.ipv4_netmask);

	READ_STRING("ipv6-network", config->network.ipv6);

	READ_NUMERIC("ipv6-prefix", prefix);
	if (prefix > 0) {
		config->network.ipv6_netmask = ipv6_prefix_to_mask(config, prefix);
		config->network.ipv6_prefix = prefix;

		if (config->network.ipv6_netmask == NULL) {
			fprintf(stderr, "invalid IPv6 prefix: %u\n", prefix);
			exit(1);
		}
	}

	READ_MULTI_LINE("custom-header", config->custom_header, config->custom_header_size);
	READ_MULTI_LINE("split-dns", config->split_dns, config->split_dns_size);

	READ_MULTI_LINE("route", config->network.routes, config->network.routes_size);
	for (j=0;j<config->network.routes_size;j++) {
		if (strcmp(config->network.routes[j], "0.0.0.0/0") == 0 ||
		    strcmp(config->network.routes[j], "default") == 0) {
		    	/* set default route */
			for (i=0;i<j;i++)
				free(config->network.routes[i]);
			config->network.routes_size = 0;
			break;
		}
	}

	READ_STRING("default-select-group", config->default_select_group);
	READ_TF("auto-select-group", auto_select_group, 0);
	if (auto_select_group != 0 && amod != NULL && amod->group_list != NULL) {
		amod->group_list(config, config->auth_additional, &config->group_list, &config->group_list_size);
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
			fprintf(stderr, "The 'local' DNS keyword is no longer supported.\n");
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

	READ_STRING("default-user-config", config->default_user_conf);
	READ_STRING("default-group-config", config->default_group_conf);

	optionUnloadNested(pov);
}


/* sanity checks on config */
static void check_cfg(struct cfg_st *config)
{
	if (config->network.ipv4 == NULL && config->network.ipv6 == NULL) {
		fprintf(stderr, "No ipv4-network or ipv6-network options set.\n");
		exit(1);
	}

	if (config->network.ipv4 != NULL && config->network.ipv4_netmask == NULL) {
		fprintf(stderr, "No mask found for IPv4 network.\n");
		exit(1);
	}

	if (config->network.ipv6 != NULL && config->network.ipv6_netmask == NULL) {
		fprintf(stderr, "No mask found for IPv6 network.\n");
		exit(1);
	}

	if (config->banner && strlen(config->banner) > MAX_BANNER_SIZE) {
		fprintf(stderr, "Banner size is too long\n");
		exit(1);
	}

	if (config->cert_size != config->key_size) {
		fprintf(stderr, "The specified number of keys doesn't match the certificates\n");
		exit(1);
	}

	if (config->auth_types & AUTH_TYPE_CERTIFICATE) {
		if (config->cisco_client_compat == 0 && ((config->auth_types & AUTH_TYPE_CERTIFICATE_OPT) != AUTH_TYPE_CERTIFICATE_OPT))
			config->cert_req = GNUTLS_CERT_REQUIRE;
		else
			config->cert_req = GNUTLS_CERT_REQUEST;
	}

	if (config->auth_additional != NULL && (config->auth_types & AUTH_TYPE_PLAIN) == AUTH_TYPE_PLAIN) {
		if (access(config->auth_additional, R_OK) != 0) {
			fprintf(stderr, "cannot access password file '%s'\n", config->auth_additional);
			exit(1);
		}
	}

#ifdef ANYCONNECT_CLIENT_COMPAT
	if (config->cert) {
		config->cert_hash = calc_sha1_hash(config, config->cert[0], 1);
	}

	if (config->xml_config_file) {
		config->xml_config_hash = calc_sha1_hash(config, config->xml_config_file, 0);
		if (config->xml_config_hash == NULL && config->chroot_dir != NULL) {
			char path[_POSIX_PATH_MAX];

			snprintf(path, sizeof(path), "%s/%s", config->chroot_dir, config->xml_config_file);
			config->xml_config_hash = calc_sha1_hash(config, path, 0);

			if (config->xml_config_hash == NULL) {
				fprintf(stderr, "Cannot open file '%s'\n", path);
				exit(1);
			}
		}
		if (config->xml_config_hash == NULL) {
			fprintf(stderr, "Cannot open file '%s'\n", config->xml_config_file);
			exit(1);
		}
	}
#endif

	if (config->keepalive == 0)
		config->keepalive = 3600;

	if (config->dpd == 0)
		config->keepalive = 60;

	if (config->priorities == NULL)
		config->priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT";
}

int cmd_parser (void *pool, int argc, char **argv, struct cfg_st** config)
{

	*config = talloc_zero(pool, struct cfg_st);

	optionProcess( &ocservOptions, argc, argv);
  
	if (HAVE_OPT(FOREGROUND))
		(*config)->foreground = 1;

	if (HAVE_OPT(PID_FILE)) {
		snprintf(pid_file, sizeof(pid_file), "%s", OPT_ARG(PID_FILE));
	}

	if (HAVE_OPT(DEBUG))
		(*config)->debug = OPT_VALUE_DEBUG;

	if (HAVE_OPT(CONFIG)) {
		cfg_file = OPT_ARG(CONFIG);
	} else if (access(cfg_file, R_OK) != 0) {
		fprintf(stderr, "%s -c [config]\nUse %s --help for more information.\n", argv[0], argv[0]);
		exit(1);
	}

	parse_cfg_file(cfg_file, *config, 0);

	check_cfg(*config);

	return 0;

}

#define DEL(x) {talloc_free(x);x=NULL;}
void clear_cfg_file(struct cfg_st* config)
{
unsigned i;

#ifdef ANYCONNECT_CLIENT_COMPAT
	DEL(config->xml_config_file);
	DEL(config->xml_config_hash);
	DEL(config->cert_hash);
#endif
	DEL(config->cgroup);
	DEL(config->route_add_cmd);
	DEL(config->route_del_cmd);
	DEL(config->per_user_dir);
	DEL(config->per_group_dir);
	DEL(config->socket_file_prefix);
	DEL(config->default_domain);
	DEL(config->auth_additional);
	DEL(config->ocsp_response);
	DEL(config->banner);
	DEL(config->dh_params_file);
	DEL(config->name);
	DEL(config->pin_file);
	DEL(config->srk_pin_file);
	DEL(config->ca);
	DEL(config->crl);
	DEL(config->cert_user_oid);
	DEL(config->cert_group_oid);
	DEL(config->priorities);
	DEL(config->chroot_dir);
	DEL(config->connect_script);
	DEL(config->disconnect_script);
	DEL(config->proxy_url);

	DEL(config->network.ipv4);
	DEL(config->network.ipv4_netmask);
	DEL(config->network.ipv6);
	DEL(config->network.ipv6_netmask);
	for (i=0;i<config->network.routes_size;i++)
		DEL(config->network.routes[i]);
	DEL(config->network.routes);
	for (i=0;i<config->network.dns_size;i++)
		DEL(config->network.dns[i]);
	DEL(config->network.dns);
	for (i=0;i<config->network.nbns_size;i++)
		DEL(config->network.nbns[i]);
	DEL(config->network.nbns);
	for (i=0;i<config->key_size;i++)
		DEL(config->key[i]);
	DEL(config->key);
	for (i=0;i<config->cert_size;i++)
		DEL(config->cert[i]);
	DEL(config->cert);
	for (i=0;i<config->custom_header_size;i++)
		DEL(config->custom_header[i]);
	DEL(config->custom_header);
	for (i=0;i<config->split_dns_size;i++)
		DEL(config->split_dns[i]);
	DEL(config->split_dns);
	for (i=0;i<config->group_list_size;i++)
		DEL(config->group_list[i]);
	DEL(config->group_list);
	DEL(config->default_select_group);
#ifdef HAVE_LIBTALLOC
	/* our included talloc don't include that */
	talloc_free_children(config);
#endif
	memset(config, 0, sizeof(*config));

	return;
}

void print_version(tOptions *opts, tOptDesc *desc)
{
	const char *p;

	fputs(OCSERV_FULL_VERSION, stderr);
	fprintf(stderr, "\n\nCompiled with ");
#ifdef HAVE_LIBSECCOMP
	fprintf(stderr, "seccomp, ");
#endif
#ifdef HAVE_LIBWRAP
	fprintf(stderr, "tcp-wrappers, ");
#endif
#ifdef HAVE_PAM
	fprintf(stderr, "PAM, ");
#endif
#ifdef HAVE_PKCS11
	fprintf(stderr, "PKCS#11, ");
#endif
#ifdef ANYCONNECT_CLIENT_COMPAT
	fprintf(stderr, "AnyConnect, ");
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

void reload_cfg_file(void *pool, struct cfg_st* config)
{
	clear_cfg_file(config);
	memset(config, 0, sizeof(*config));

	parse_cfg_file(cfg_file, config, 1);

	check_cfg(config);

	return;
}

void write_pid_file(void)
{
FILE* fp;

	if (pid_file[0]==0)
		return;

	fp = fopen(pid_file, "w");
	if (fp == NULL) {
		fprintf(stderr, "Cannot open pid file '%s'\n", pid_file);
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
