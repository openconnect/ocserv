/*
 * Copyright (C) 2013-2017 Nikos Mavrogiannopoulos
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
#include <auth/pam.h>
#include <acct/pam.h>
#include <auth/radius.h>
#include <acct/radius.h>
#include <auth/plain.h>
#include <auth/gssapi.h>
#include <auth/common.h>
#include <sec-mod-sup-config.h>
#include <sec-mod-acct.h>
#include "inih/ini.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <netdb.h>

#include <vpn.h>
#include <main.h>
#include <tlslib.h>
#include <occtl/ctl.h>
#include "common-config.h"

#include <getopt.h>

#define OLD_DEFAULT_CFG_FILE "/etc/ocserv.conf"
#define DEFAULT_CFG_FILE "/etc/ocserv/ocserv.conf"

static void print_version(void);

static char pid_file[_POSIX_PATH_MAX] = "";
static char cfg_file[_POSIX_PATH_MAX] = DEFAULT_CFG_FILE;

static void archive_cfg(struct perm_cfg_st* perm_config);

#define ERRSTR "error: "
#define WARNSTR "warning: "
#define NOTESTR "note: "

#define READ_MULTI_LINE(varname, num) { \
	if (_add_multi_line_val(pool, &varname, &num, value) < 0) { \
		fprintf(stderr, ERRSTR"memory\n"); \
		exit(1); \
	}}

#define READ_MULTI_BRACKET_LINE(varname, varname2, num) { \
	if (varname == NULL || varname2 == NULL) { \
		num = 0; \
		varname = talloc_size(pool, sizeof(char*)*DEFAULT_CONFIG_ENTRIES); \
		varname2 = talloc_size(pool, sizeof(char*)*DEFAULT_CONFIG_ENTRIES); \
		if (varname == NULL || varname2 == NULL) { \
			fprintf(stderr, ERRSTR"memory\n"); \
			exit(1); \
		} \
	} \
	if (num < DEFAULT_CONFIG_ENTRIES) { \
		char *xp; \
		varname[num] = talloc_strdup(pool, value); \
		xp = strchr(varname[num], '['); if (xp != NULL) *xp = 0; \
		varname2[num] = get_brackets_string1(pool, value); \
		num++; \
		varname[num] = NULL; \
		varname2[num] = NULL; \
	}}

#define PREAD_STRING(pool, varname) { \
	unsigned len = strlen(value); \
	while(c_isspace(value[len-1])) \
		len--; \
	varname = talloc_strndup(pool, value, len); \
	}

#define READ_STRING(varname) \
	PREAD_STRING(pool, varname)

#define READ_STATIC_STRING(varname) { \
	strlcpy(varname, value, sizeof(varname)); \
	}

#define READ_TF(varname) {\
	if (c_strcasecmp(value, "true") == 0 || c_strcasecmp(value, "yes") == 0) \
		varname = 1; \
	else \
		varname = 0; \
	}

#define READ_NUMERIC(varname) { \
	varname = strtol(value, NULL, 10); \
	}

#define READ_PRIO_TOS(varname) \
	if (strncmp(value, "0x", 2) == 0) { \
		varname = strtol(value, NULL, 16); \
		varname = TOS_PACK(varname); \
	} else { \
		varname = strtol(value, NULL, 10); \
		varname++; \
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

	if (acct == NULL)
		return;

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

struct iroute_ctx {
	struct cfg_st *config;
	const char *file;
};

char *sanitize_config_value(void *pool, const char *value)
{
	ssize_t len = strlen(value);
	unsigned i = 0;

	while(c_isspace(value[len-1]) || value[len-1] == '"')
		len--;

	while(c_isspace(value[i]) || value[i] == '"') {
		i++;
		len--;
	}

	if (len < 0)
		return NULL;

	return talloc_strndup(pool, &value[i], len); \

}

static int iroutes_handler(void *_ctx, const char *section, const char *name, const char* _value)
{
	struct iroute_ctx *ctx = _ctx;
	int ret;
	char *value;

	if (section != NULL && section[0] != 0) {
		fprintf(stderr, WARNSTR"skipping unknown section '%s'\n", section);
		return 0;
	}

	if (strcmp(name, "iroute")!=0)
		return 0;

	value = sanitize_config_value(ctx->config, _value);
	if (value == NULL)
		return 0;

	ret = _add_multi_line_val(ctx->config, &ctx->config->known_iroutes,
				 &ctx->config->known_iroutes_size, value);
	if (ret < 0) {
		fprintf(stderr, ERRSTR"cannot load iroute from %s\n", ctx->file);
	}

	talloc_free(value);
	return 0;
}

static void append_iroutes_from_file(struct cfg_st *config, const char *file)
{
	struct iroute_ctx ctx;
	int ret;
	unsigned j;

	ctx.file = file;
	ctx.config = config;

	ret = ini_parse(file, iroutes_handler, &ctx);
	if (ret < 0)
		return;

	for (j=0;j<config->known_iroutes_size;j++) {
		if (ip_route_sanity_check(config->known_iroutes, &config->known_iroutes[j]) != 0)
			exit(1);
	}

	return;
}

static void load_iroutes(struct cfg_st *config)
{
	DIR *dir;
	struct dirent *r;
	int ret;
	char path[_POSIX_PATH_MAX];

	if (config->per_user_dir == NULL)
		return;

	dir = opendir(config->per_user_dir);
	if (dir != NULL) {
		do {
			r = readdir(dir);
			if (r != NULL && r->d_type == DT_REG) {
				ret = snprintf(path, sizeof(path), "%s/%s", config->per_user_dir, r->d_name);
				if (ret != (int)strlen(path)) {
					fprintf(stderr, NOTESTR"path name too long and truncated: %s\n", path);
				}
				append_iroutes_from_file(config, path);
			}
		} while(r != NULL);
		closedir(dir);
	}
}

struct ini_ctx_st {
	struct perm_cfg_st *perm_config;
	unsigned reload;
	const char *file;

	char *acct;
	char** auth;
	size_t auth_size;
	char** eauth;
	size_t eauth_size;
	unsigned expose_iroutes;
	unsigned auto_select_group;
#ifdef HAVE_GSSAPI
	char **urlfw;
	size_t urlfw_size;
#endif
};

static int cfg_ini_handler(void *_ctx, const char *section, const char *name, const char *_value)
{
	struct ini_ctx_st *ctx = _ctx;
	unsigned use_dbus;
	void *pool;
	struct perm_cfg_st *perm_config = ctx->perm_config;
	struct cfg_st *config = perm_config->config;
	unsigned reload = ctx->reload;
	int ret;
	unsigned stage1_found = 1;
	unsigned force_cert_auth;
	unsigned prefix = 0;
	unsigned prefix4 = 0;
	char *value;

	if (section != NULL && section[0] != 0) {
		if (reload == 0)
			fprintf(stderr, WARNSTR"skipping unknown section '%s'\n", section);
		return 0;
	}

	value = sanitize_config_value(config, _value);
	if (value == NULL)
		return 0;

	/* read persistent configuration */
	if (reload == 0) {
		pool = ctx->perm_config;

		if (strcmp(name, "auth") == 0) {
			READ_MULTI_LINE(ctx->auth, ctx->auth_size);
		} else if (strcmp(name, "enable-auth") == 0) {
			READ_MULTI_LINE(ctx->eauth, ctx->eauth_size);
		} else if (strcmp(name, "acct") == 0) {
			ctx->acct = talloc_strdup(pool, value);
		} else if (strcmp(name, "listen-host") == 0) {
			PREAD_STRING(pool, perm_config->listen_host);
		} else if (strcmp(name, "listen-clear-file") == 0) {
			PREAD_STRING(pool, perm_config->unix_conn_file);
		} else if (strcmp(name, "tcp-port") == 0) {
			READ_NUMERIC(perm_config->port);
		} else if (strcmp(name, "udp-port") == 0) {
			READ_NUMERIC(perm_config->udp_port);
		} else if (strcmp(name, "run-as-user") == 0) {
			const struct passwd* pwd = getpwnam(value);
			if (pwd == NULL) {
				fprintf(stderr, ERRSTR"unknown user: %s\n", value);
				exit(1);
			}
			perm_config->uid = pwd->pw_uid;
		} else if (strcmp(name, "run-as-group") == 0) {
			const struct group* grp = getgrnam(value);
			if (grp == NULL) {
				fprintf(stderr, ERRSTR"unknown group: %s\n", value);
				exit(1);
			}
			perm_config->gid = grp->gr_gid;
		} else if (strcmp(name, "server-cert") == 0) {
			READ_MULTI_LINE(perm_config->cert, perm_config->cert_size);
		} else if (strcmp(name, "server-key") == 0) {
			READ_MULTI_LINE(perm_config->key, perm_config->key_size);
		} else if (strcmp(name, "dh-params") == 0) {
			READ_STRING(perm_config->dh_params_file);
		} else if (strcmp(name, "pin-file") == 0) {
			READ_STRING(perm_config->pin_file);
		} else if (strcmp(name, "srk-pin-file") == 0) {
			READ_STRING(perm_config->srk_pin_file);
		} else if (strcmp(name, "ca-cert") == 0) {
			READ_STRING(perm_config->ca);
		} else if (strcmp(name, "key-pin") == 0) {
			READ_STRING(perm_config->key_pin);
		} else if (strcmp(name, "srk-pin") == 0) {
			READ_STRING(perm_config->srk_pin);
		} else if (strcmp(name, "socket-file") == 0) {
			PREAD_STRING(perm_config, perm_config->socket_file_prefix);
		} else if (strcmp(name, "occtl-socket-file") == 0) {
			PREAD_STRING(perm_config, perm_config->occtl_socket_file);
		} else if (strcmp(name, "chroot-dir") == 0) {
			PREAD_STRING(perm_config, perm_config->chroot_dir);
		} else if (strcmp(name, "server-stats-reset-time") == 0) {
			/* cannot be modified as it would require sec-mod to
			 * re-read configuration too */
			READ_NUMERIC(perm_config->stats_reset_time);
		} else if (strcmp(name, "pid-file") == 0 && pid_file[0] == 0) {
			READ_STATIC_STRING(pid_file);
		} else {
			stage1_found = 0;
		}

		if (stage1_found)
			goto exit;
	}


	/* read the rest of the (non-permanent) configuration */
	pool = ctx->perm_config->config;

	/* When adding allocated data, remember to modify
	 * reload_cfg_file();
	 */
	if (strcmp(name, "listen-host-is-dyndns") == 0) {
		READ_TF(config->is_dyndns);
	} else if (strcmp(name, "listen-proxy-proto") == 0) {
		READ_TF(config->listen_proxy_proto);
	} else if (strcmp(name, "append-routes") == 0) {
		READ_TF(config->append_routes);
#ifdef HAVE_GSSAPI
	} else if (strcmp(name, "kkdcp") == 0) {
		READ_MULTI_LINE(ctx->urlfw, ctx->urlfw_size);
#endif
	} else if (strcmp(name, "tunnel-all-dns") == 0) {
		READ_TF(config->tunnel_all_dns);
	} else if (strcmp(name, "keepalive") == 0) {
		READ_NUMERIC(config->keepalive);
	} else if (strcmp(name, "switch-to-tcp-timeout") == 0) {
		READ_NUMERIC(config->switch_to_tcp_timeout);
	} else if (strcmp(name, "dpd") == 0) {
		READ_NUMERIC(config->dpd);
	} else if (strcmp(name, "mobile-dpd") == 0) {
		READ_NUMERIC(config->mobile_dpd);
	} else if (strcmp(name, "rate-limit-ms") == 0) {
		READ_NUMERIC(config->rate_limit_ms);
	} else if (strcmp(name, "ocsp-response") == 0) {
		READ_STRING(config->ocsp_response);
	} else if (strcmp(name, "user-profile") == 0) {
		READ_STRING(config->xml_config_file);
	} else if (strcmp(name, "default-domain") == 0) {
		READ_STRING(config->default_domain);
	} else if (strcmp(name, "crl") == 0) {
		READ_STRING(config->crl);
	} else if (strcmp(name, "cert-user-oid") == 0) {
		READ_STRING(config->cert_user_oid);
	} else if (strcmp(name, "cert-group-oid") == 0) {
		READ_STRING(config->cert_group_oid);
	} else if (strcmp(name, "connect-script") == 0) {
		READ_STRING(config->connect_script);
	} else if (strcmp(name, "host-update-script") == 0) {
		READ_STRING(config->host_update_script);
	} else if (strcmp(name, "disconnect-script") == 0) {
		READ_STRING(config->disconnect_script);
	} else if (strcmp(name, "session-control") == 0) {
		fprintf(stderr, WARNSTR"the option 'session-control' is deprecated\n");
	} else if (strcmp(name, "banner") == 0) {
		READ_STRING(config->banner);
	} else if (strcmp(name, "dtls-legacy") == 0) {
		READ_TF(config->dtls_legacy);
	} else if (strcmp(name, "cisco-client-compat") == 0) {
		READ_TF(config->cisco_client_compat);
	} else if (strcmp(name, "always-require-cert") == 0) {
		READ_TF(force_cert_auth);
		if (force_cert_auth == 0) {
			fprintf(stderr, NOTESTR"'always-require-cert' was replaced by 'cisco-client-compat'\n");
			config->cisco_client_compat = 1;
		}
	} else if (strcmp(name, "dtls-psk") == 0) {
		READ_TF(config->dtls_psk);
	} else if (strcmp(name, "match-tls-dtls-ciphers") == 0) {
		READ_TF(config->match_dtls_and_tls);
	} else if (strcmp(name, "compression") == 0) {
		READ_TF(config->enable_compression);
	} else if (strcmp(name, "no-compress-limit") == 0) {
		READ_NUMERIC(config->no_compress_limit);
	} else if (strcmp(name, "use-seccomp") == 0) {
		READ_TF(config->isolate);
		if (config->isolate)
			fprintf(stderr, NOTESTR"'use-seccomp' was replaced by 'isolate-workers'\n");
	} else if (strcmp(name, "isolate-workers") == 0) {
		READ_TF(config->isolate);
	} else if (strcmp(name, "predictable-ips") == 0) {
		READ_TF(config->predictable_ips);
	} else if (strcmp(name, "use-utmp") == 0) {
		READ_TF(config->use_utmp);
	} else if (strcmp(name, "use-dbus") == 0) {
		READ_TF(use_dbus);
		if (use_dbus != 0) {
			fprintf(stderr, NOTESTR"'use-dbus' was replaced by 'use-occtl'\n");
			config->use_occtl = use_dbus;
		}
	} else if (strcmp(name, "use-occtl") == 0) {
		READ_TF(config->use_occtl);
	} else if (strcmp(name, "try-mtu-discovery") == 0) {
		READ_TF(config->try_mtu);
	} else if (strcmp(name, "ping-leases") == 0) {
		READ_TF(config->ping_leases);
	} else if (strcmp(name, "restrict-user-to-routes") == 0) {
		READ_TF(config->restrict_user_to_routes);
	} else if (strcmp(name, "restrict-user-to-ports") == 0) {
		ret = cfg_parse_ports(pool, &config->fw_ports, &config->n_fw_ports, value);
		if (ret < 0) {
			fprintf(stderr, ERRSTR"cannot parse restrict-user-to-ports\n");
			exit(1);
		}
	} else if (strcmp(name, "tls-priorities") == 0) {
		READ_STRING(config->priorities);
	} else if (strcmp(name, "mtu") == 0) {
		READ_NUMERIC(config->default_mtu);
	} else if (strcmp(name, "net-priority") == 0) {
		READ_PRIO_TOS(config->net_priority);
	} else if (strcmp(name, "output-buffer") == 0) {
		READ_NUMERIC(config->output_buffer);
	} else if (strcmp(name, "rx-data-per-sec") == 0) {
		READ_NUMERIC(config->rx_per_sec);
		config->rx_per_sec /= 1000; /* in kb */
	} else if (strcmp(name, "tx-data-per-sec") == 0) {
		READ_NUMERIC(config->tx_per_sec);
		config->tx_per_sec /= 1000; /* in kb */
	} else if (strcmp(name, "deny-roaming") == 0) {
		READ_TF(config->deny_roaming);
	} else if (strcmp(name, "stats-report-time") == 0) {
		READ_NUMERIC(config->stats_report_time);
	} else if (strcmp(name, "rekey-time") == 0) {
		READ_NUMERIC(config->rekey_time);
	} else if (strcmp(name, "rekey-method") == 0) {
		if (strcmp(value, "ssl") == 0)
			config->rekey_method = REKEY_METHOD_SSL;
		else if (strcmp(value, "new-tunnel") == 0)
			config->rekey_method = REKEY_METHOD_NEW_TUNNEL;
		else {
			fprintf(stderr, ERRSTR"unknown rekey method '%s'\n", value);
			exit(1);
		}
	} else if (strcmp(name, "cookie-timeout") == 0) {
		READ_NUMERIC(config->cookie_timeout);
	} else if (strcmp(name, "persistent-cookies") == 0) {
		READ_TF(config->persistent_cookies);
	} else if (strcmp(name, "session-timeout") == 0) {
		READ_NUMERIC(config->session_timeout);
	} else if (strcmp(name, "auth-timeout") == 0) {
		READ_NUMERIC(config->auth_timeout);
	} else if (strcmp(name, "idle-timeout") == 0) {
		READ_NUMERIC(config->idle_timeout);
	} else if (strcmp(name, "mobile-idle-timeout") == 0) {
		READ_NUMERIC(config->mobile_idle_timeout);
	} else if (strcmp(name, "max-clients") == 0) {
		READ_NUMERIC(config->max_clients);
	} else if (strcmp(name, "min-reauth-time") == 0) {
		READ_NUMERIC(config->min_reauth_time);
	} else if (strcmp(name, "ban-reset-time") == 0) {
		READ_NUMERIC(config->ban_reset_time);
	} else if (strcmp(name, "max-ban-score") == 0) {
		READ_NUMERIC( config->max_ban_score);
	} else if (strcmp(name, "ban-points-wrong-password") == 0) {
		READ_NUMERIC(config->ban_points_wrong_password);
	} else if (strcmp(name, "ban-points-connection") == 0) {
		READ_NUMERIC(config->ban_points_connect);
	} else if (strcmp(name, "ban-points-kkdcp") == 0) {
		READ_NUMERIC(config->ban_points_kkdcp);
	} else if (strcmp(name, "max-same-clients") == 0) {
		READ_NUMERIC(config->max_same_clients);
	} else if (strcmp(name, "device") == 0) {
		READ_STATIC_STRING(config->network.name);
	} else if (strcmp(name, "cgroup") == 0) {
		READ_STRING(config->cgroup);
	} else if (strcmp(name, "proxy-url") == 0) {
		READ_STRING(config->proxy_url);
	} else if (strcmp(name, "ipv4-network") == 0) {
		READ_STRING(config->network.ipv4);
		prefix4 = extract_prefix(config->network.ipv4);
		if (prefix4 != 0) {
			config->network.ipv4_netmask = ipv4_prefix_to_strmask(config, prefix4);
		}
	} else if (strcmp(name, "ipv4-netmask") == 0) {
		READ_STRING(config->network.ipv4_netmask);
	} else if (strcmp(name, "ipv6-network") == 0) {
		READ_STRING(config->network.ipv6);
		prefix = extract_prefix(config->network.ipv6);
		if (prefix)
			config->network.ipv6_prefix = prefix;
	} else if (strcmp(name, "ipv6-prefix") == 0) {
		READ_NUMERIC(config->network.ipv6_prefix);

		if (valid_ipv6_prefix(config->network.ipv6_prefix) == 0) {
			fprintf(stderr, ERRSTR"invalid IPv6 prefix: %u\n", prefix);
			exit(1);
		}
	} else if (strcmp(name, "ipv6-subnet-prefix") == 0) {
		/* read subnet prefix */
		READ_NUMERIC(prefix);
		if (prefix > 0) {
			config->network.ipv6_subnet_prefix = prefix;

			if (valid_ipv6_prefix(prefix) == 0) {
				fprintf(stderr, ERRSTR"invalid IPv6 subnet prefix: %u\n", prefix);
				exit(1);
			}
		}
	} else if (strcmp(name, "custom-header") == 0) {
		READ_MULTI_LINE(config->custom_header, config->custom_header_size);
	} else if (strcmp(name, "split-dns") == 0) {
		READ_MULTI_LINE(config->split_dns, config->split_dns_size);
	} else if (strcmp(name, "route") == 0) {
		READ_MULTI_LINE(config->network.routes, config->network.routes_size);
	} else if (strcmp(name, "no-route") == 0) {
		READ_MULTI_LINE(config->network.no_routes, config->network.no_routes_size);
	} else if (strcmp(name, "default-select-group") == 0) {
		READ_STRING(config->default_select_group);
	} else if (strcmp(name, "auto-select-group") == 0) {
		READ_TF(ctx->auto_select_group);
	} else if (strcmp(name, "select-group") == 0) {
		READ_MULTI_BRACKET_LINE(config->group_list,
					config->friendly_group_list,
					config->group_list_size);
	} else if (strcmp(name, "dns") == 0) {
		READ_MULTI_LINE(config->network.dns, config->network.dns_size);
	} else if (strcmp(name, "ipv4-dns") == 0) {
		READ_MULTI_LINE(config->network.dns, config->network.dns_size);
	} else if (strcmp(name, "ipv6-dns") == 0) {
		READ_MULTI_LINE(config->network.dns, config->network.dns_size);
	} else if (strcmp(name, "nbns") == 0) {
		READ_MULTI_LINE(config->network.nbns, config->network.nbns_size);
	} else if (strcmp(name, "ipv4-nbns") == 0) {
		READ_MULTI_LINE(config->network.nbns, config->network.nbns_size);
	} else if (strcmp(name, "ipv6-nbns") == 0) {
		READ_MULTI_LINE(config->network.nbns, config->network.nbns_size);
	} else if (strcmp(name, "route-add-cmd") == 0) {
		READ_STRING(config->route_add_cmd);
	} else if (strcmp(name, "route-del-cmd") == 0) {
		READ_STRING(config->route_del_cmd);
	} else if (strcmp(name, "config-per-user") == 0) {
		READ_STRING(config->per_user_dir);
	} else if (strcmp(name, "config-per-group") == 0) {
		READ_STRING(config->per_group_dir);
	} else if (strcmp(name, "expose-iroutes") == 0) {
		READ_TF(ctx->expose_iroutes);
	} else if (strcmp(name, "default-user-config") == 0) {
		READ_STRING(config->default_user_conf);
	} else if (strcmp(name, "default-group-config") == 0) {
		READ_STRING(config->default_group_conf);
	} else {
		if (reload == 0)
			fprintf(stderr, WARNSTR"skipping unknown option '%s'\n", name);
	}

 exit:
	talloc_free(value);
	return 0;
}

static void parse_cfg_file(void *pool, const char *file, struct perm_cfg_st *perm_config, unsigned reload)
{
	int ret;
	struct cfg_st *config;
	struct ini_ctx_st ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.file = file;
	ctx.reload = reload;
	ctx.perm_config = perm_config;

	perm_config->config = talloc_zero(perm_config, struct cfg_st);
	if (perm_config->config == NULL)
		exit(1);

	config = perm_config->config;
	config->usage_count = talloc_zero(config, int);
	if (config->usage_count == NULL) {
		fprintf(stderr, ERRSTR"memory\n");
		exit(1);
	}

	/* set config (no-zero) default vals
	 */
	if (reload == 0) {
		perm_config->sup_config_type = SUP_CONFIG_FILE;
		list_head_init(&perm_config->attic);
	}
	config->mobile_idle_timeout = (unsigned)-1;
	config->no_compress_limit = DEFAULT_NO_COMPRESS_LIMIT;
	config->rekey_time = 24*60*60;
	config->cookie_timeout = DEFAULT_COOKIE_RECON_TIMEOUT;
	config->auth_timeout = DEFAULT_AUTH_TIMEOUT_SECS;
	config->ban_reset_time = DEFAULT_BAN_RESET_TIME;
	config->max_ban_score = DEFAULT_MAX_BAN_SCORE;
	config->ban_points_wrong_password = DEFAULT_PASSWORD_POINTS;
	config->ban_points_connect = DEFAULT_CONNECT_POINTS;
	config->ban_points_kkdcp = DEFAULT_KKDCP_POINTS;
	config->dpd = DEFAULT_DPD_TIME;
	config->network.ipv6_subnet_prefix = 128;
	config->dtls_legacy = 1;
	config->dtls_psk = 1;
	config->predictable_ips = 1;
	config->use_utmp = 1;

	/* parse configuration
	 */
	ret = ini_parse(file, cfg_ini_handler, &ctx);
	if (ret < 0 && file != NULL && strcmp(file, DEFAULT_CFG_FILE) == 0)
		ret = ini_parse(OLD_DEFAULT_CFG_FILE, cfg_ini_handler, &ctx);

	if (ret < 0) {
		fprintf(stderr, ERRSTR"cannot load config file %s\n", file);
		exit(1);
	}

	if (reload == 0) {
		if (ctx.auth_size == 0) {
			fprintf(stderr, ERRSTR"the 'auth' configuration option was not specified!\n");
			exit(1);
		}

		figure_auth_funcs(perm_config, ctx.auth, ctx.auth_size, 1);
		figure_auth_funcs(perm_config, ctx.eauth, ctx.eauth_size, 0);

		figure_acct_funcs(perm_config, ctx.acct);
	}

	if (ctx.auto_select_group != 0 && perm_config->auth[0].amod != NULL && perm_config->auth[0].amod->group_list != NULL) {
		perm_config->auth[0].amod->group_list(config, perm_config->auth[0].additional, &config->group_list, &config->group_list_size);
	}

	if (ctx.expose_iroutes != 0) {
		load_iroutes(config);
	}

#ifdef HAVE_GSSAPI
	if (ctx.urlfw_size > 0) {
		parse_kkdcp(config, ctx.urlfw, ctx.urlfw_size);
		talloc_free(ctx.urlfw);
	}
#endif

	fprintf(stderr, NOTESTR"setting '%s' as supplemental config option\n", sup_config_name(perm_config->sup_config_type));
}


/* sanity checks on config */
static void check_cfg(struct perm_cfg_st *perm_config, unsigned silent)
{
	unsigned j, i;
	struct cfg_st *config = perm_config->config;

	if (perm_config->auth[0].enabled == 0) {
		fprintf(stderr, ERRSTR"no authentication method was specified!\n");
		exit(1);
	}

	if (perm_config->socket_file_prefix == NULL) {
		fprintf(stderr, ERRSTR"the 'socket-file' configuration option must be specified!\n");
		exit(1);
	}

	if (perm_config->cert_size == 0 || perm_config->key_size == 0) {
		fprintf(stderr, ERRSTR"the 'server-cert' and 'server-key' configuration options must be specified!\n");
		exit(1);
	}

	if (config->network.ipv4 == NULL && config->network.ipv6 == NULL) {
		fprintf(stderr, ERRSTR"no ipv4-network or ipv6-network options set.\n");
		exit(1);
	}

	if (config->network.ipv4 != NULL && config->network.ipv4_netmask == NULL) {
		fprintf(stderr, ERRSTR"no mask found for IPv4 network.\n");
		exit(1);
	}

	if (config->network.ipv6 != NULL && config->network.ipv6_prefix == 0) {
		fprintf(stderr, ERRSTR"no prefix found for IPv6 network.\n");
		exit(1);
	}

	if (config->banner && strlen(config->banner) > MAX_BANNER_SIZE) {
		fprintf(stderr, ERRSTR"banner size is too long\n");
		exit(1);
	}

	if (perm_config->cert_size != perm_config->key_size) {
		fprintf(stderr, ERRSTR"the specified number of keys doesn't match the certificates\n");
		exit(1);
	}

	if (perm_config->auth[0].type & AUTH_TYPE_CERTIFICATE && perm_config->auth_methods == 1) {
		if (config->cisco_client_compat == 0)
			config->cert_req = GNUTLS_CERT_REQUIRE;
		else
			config->cert_req = GNUTLS_CERT_REQUEST;
	} else {
		unsigned i;
		for (i=0;i<perm_config->auth_methods;i++) {
			if (perm_config->auth[i].type & AUTH_TYPE_CERTIFICATE) {
				config->cert_req = GNUTLS_CERT_REQUEST;
				break;
			}
		}
	}

	if (config->cert_req != 0 && config->cert_user_oid == NULL) {
		fprintf(stderr, ERRSTR"a certificate is requested by the option 'cert-user-oid' is not set\n");
		exit(1);
	}

	if (config->cert_req != 0 && config->cert_user_oid != NULL) {
		if (!c_isdigit(config->cert_user_oid[0]) && strcmp(config->cert_user_oid, "SAN(rfc822name)") != 0) {
			fprintf(stderr, ERRSTR"the option 'cert-user-oid' has a unsupported value\n");
			exit(1);
		}
	}

	if (perm_config->unix_conn_file != NULL && (config->cert_req != 0)) {
		if (config->listen_proxy_proto == 0) {
			fprintf(stderr, ERRSTR"the option 'listen-clear-file' cannot be combined with 'auth=certificate'\n");
			exit(1);
		}
	}

	if (perm_config->cert && perm_config->cert_hash == NULL) {
		perm_config->cert_hash = calc_sha1_hash(perm_config, perm_config->cert[0], 1);
	}

	if (config->xml_config_file) {
		config->xml_config_hash = calc_sha1_hash(config, config->xml_config_file, 0);
		if (config->xml_config_hash == NULL && perm_config->chroot_dir != NULL) {
			char path[_POSIX_PATH_MAX];

			snprintf(path, sizeof(path), "%s/%s", perm_config->chroot_dir, config->xml_config_file);
			config->xml_config_hash = calc_sha1_hash(config, path, 0);

			if (config->xml_config_hash == NULL) {
				fprintf(stderr, ERRSTR"cannot open file '%s'\n", path);
				exit(1);
			}
		}
		if (config->xml_config_hash == NULL) {
			fprintf(stderr, ERRSTR"cannot open file '%s'\n", config->xml_config_file);
			exit(1);
		}
	}

	if (config->keepalive == 0)
		config->keepalive = 3600;

	if (config->dpd == 0)
		config->dpd = 60;

	if (config->priorities == NULL)
		config->priorities = talloc_strdup(config, "NORMAL:%SERVER_PRECEDENCE:%COMPAT");

	if (perm_config->occtl_socket_file == NULL)
		perm_config->occtl_socket_file = talloc_strdup(perm_config, OCCTL_UNIX_SOCKET);

	if (perm_config->stats_reset_time <= 0)
		perm_config->stats_reset_time = 24*60*60*7; /* weekly */

	if (config->network.ipv6_prefix && config->network.ipv6_prefix >= config->network.ipv6_subnet_prefix) {
		fprintf(stderr, ERRSTR"the subnet prefix (%u) cannot be smaller or equal to network's (%u)\n", 
				config->network.ipv6_subnet_prefix, config->network.ipv6_prefix);
		exit(1);
	}

	if (config->network.name == NULL) {
		fprintf(stderr, ERRSTR"the 'device' configuration option must be specified!\n");
		exit(1);
	}

	if (config->mobile_dpd == 0)
		config->mobile_dpd = config->dpd;

	if (config->cisco_client_compat) {
		if (!config->dtls_legacy && !silent) {
			fprintf(stderr, NOTESTR"the cisco-client-compat option implies dtls-legacy = true; enabling\n");
		}
		config->dtls_legacy = 1;
	}

	if (perm_config->unix_conn_file) {
		if (config->dtls_psk && !silent) {
			fprintf(stderr, NOTESTR"'dtls-psk' cannot be combined with unix socket file\n");
		}
		config->dtls_psk = 0;
	}

	if (config->match_dtls_and_tls) {
		if (config->dtls_legacy) {
			fprintf(stderr, ERRSTR"'match-tls-dtls-ciphers' cannot be applied when 'dtls-legacy' or 'cisco-client-compat' is on\n");
			exit(1);
		}
	}

	if (config->mobile_idle_timeout == (unsigned)-1)
		config->mobile_idle_timeout = config->idle_timeout;

	if (config->no_compress_limit < MIN_NO_COMPRESS_LIMIT)
		config->no_compress_limit = MIN_NO_COMPRESS_LIMIT;

#if !defined(HAVE_LIBSECCOMP)
	if (config->isolate != 0 && !silent) {
		fprintf(stderr, ERRSTR"'isolate-workers' is set to true, but not compiled with seccomp or Linux namespaces support\n");
	}
#endif

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

	for (j=0;j<config->network.no_routes_size;j++) {
		if (ip_route_sanity_check(config->network.no_routes, &config->network.no_routes[j]) != 0)
			exit(1);
	}

	for (j=0;j<config->network.dns_size;j++) {
		if (strcmp(config->network.dns[j], "local") == 0) {
			fprintf(stderr, ERRSTR"the 'local' DNS keyword is no longer supported.\n");
			exit(1);
		}
	}

	if (config->per_user_dir || config->per_group_dir) {
		if (perm_config->sup_config_type != SUP_CONFIG_FILE) {
			fprintf(stderr, ERRSTR"specified config-per-user or config-per-group but supplemental config is '%s'\n",
				sup_config_name(perm_config->sup_config_type));
			exit(1);
		}
	}

}

static const struct option long_options[] = {
	{"debug", 1, 0, 'd'},
	{"config", 1, 0, 'c'},
	{"pid-file", 0, 0, 'p'},
	{"test-config", 0, 0, 't'},
	{"foreground", 0, 0, 'f'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{NULL, 0, 0, 0}
};

static
void usage(void)
{
	fprintf(stderr, "ocserv - OpenConnect VPN server\n");
	fprintf(stderr, "Usage:  ocserv [ -<flag> [<val>] | --<name>[{=| }<val>] ]...\n\n");

	fprintf(stderr, "   -f, --foreground           Do not fork into background\n");
	fprintf(stderr, "   -d, --debug=num            Enable verbose network debugging information\n");
	fprintf(stderr, "				- it must be in the range:\n");
	fprintf(stderr, "				  0 to 9999\n");
	fprintf(stderr, "   -c, --config=file          Configuration file for the server\n");
	fprintf(stderr, "				- file must exist\n");
	fprintf(stderr, "   -t, --test-config          Test the provided configuration file\n");
	fprintf(stderr, "   -p, --pid-file=file        Specify pid file for the server\n");
	fprintf(stderr, "   -v, --version              output version information and exit\n");
	fprintf(stderr, "   -h, --help                 display extended usage information and exit\n\n");

	fprintf(stderr, "Openconnect VPN server (ocserv) is a VPN server compatible with the\n");
	fprintf(stderr, "openconnect VPN client.  It follows the TLS and DTLS-based AnyConnect VPN\n");
	fprintf(stderr, "protocol which is used by several CISCO routers.\n\n");

	fprintf(stderr, "Please send bug reports to:  "PACKAGE_BUGREPORT"\n");
}

int cmd_parser (void *pool, int argc, char **argv, struct perm_cfg_st** config)
{
	unsigned test_only = 0;
	int c;

	*config = talloc_zero(pool, struct perm_cfg_st);
	if (*config == NULL)
		exit(1);

	while (1) {
		c = getopt_long(argc, argv, "d:c:p:ftvh", long_options, NULL);
		if (c == -1)
			break;

		switch(c) {
			case 'f':
				(*config)->foreground = 1;
				break;
			case 'p':
				strlcpy(pid_file, optarg, sizeof(pid_file));
				break;
			case 'c':
				strlcpy(cfg_file, optarg, sizeof(cfg_file));
				break;
			case 'd':
				(*config)->debug = atoi(optarg);
				break;
			case 't':
				test_only = 1;
				break;
			case 'h':
				usage();
				exit(0);
			case 'v':
				print_version();
				exit(0);
		}
	}

	if (optind != argc) {
		fprintf(stderr, ERRSTR"no additional command line options are allowed\n\n");
		exit(1);
	}

	if (access(cfg_file, R_OK) != 0) {
		fprintf(stderr, ERRSTR"cannot access config file: %s\n", cfg_file);
		fprintf(stderr, "Usage: %s -c [config]\nUse %s --help for more information.\n", argv[0], argv[0]);
		exit(1);
	}

	parse_cfg_file(pool, cfg_file, *config, 0);

	check_cfg(*config, 0);

	if (test_only)
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

static void print_version(void)
{
	const char *p;

	fputs(PACKAGE_STRING, stderr);
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
	append("PKCS#11");
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
}


void reload_cfg_file(void *pool, struct perm_cfg_st* perm_config, unsigned archive)
{
	if (archive)
		archive_cfg(perm_config);
	else
		clear_cfg(perm_config);

	parse_cfg_file(pool, cfg_file, perm_config, 1);

	check_cfg(perm_config, 1);

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

int _add_multi_line_val(void *pool, char ***varname, size_t *num,
		        const char *value)
{
	unsigned _max = DEFAULT_CONFIG_ENTRIES;
	void *tmp;

	if (*varname == NULL) {
		*num = 0;
		*varname = talloc_array(pool, char*, _max);
		if (*varname == NULL)
			return -1;
	}

	if (*num >= _max-1) {
		_max += 128;
		tmp = talloc_realloc(pool, *varname, char*, _max);
		if (tmp == NULL)
			return -1;
		*varname = tmp;
	}

	(*varname)[*num] = talloc_strdup(*varname, value);
	(*num)++;

	(*varname)[*num] = NULL;
	return 0;
}

void clear_old_configs(struct perm_cfg_st* config)
{
	attic_entry_st *e = NULL, *pos;

	/* go through the attic and clear old configurations if unused */
	list_for_each_safe(&config->attic, e, pos, list) {
		if (*e->usage_count == 0) {
			list_del(&e->list);
			talloc_free(e);
		}
	}
}
