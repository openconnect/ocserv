/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
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
#include <auth/openidconnect.h>
#include <auth/common.h>
#include <sec-mod-sup-config.h>
#include <sec-mod-acct.h>
#include "inih/ini.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>
#include <netdb.h>
#include <assert.h>

#include <vpn.h>
#include <main.h>
#include <tlslib.h>
#include <occtl/ctl.h>
#include <gnutls/crypto.h>
#include "common-config.h"

#include <getopt.h>
#include <snapshot.h>

#define OLD_DEFAULT_CFG_FILE "/etc/ocserv.conf"
#define DEFAULT_CFG_FILE "/etc/ocserv/ocserv.conf"

static void print_version(void);

static char pid_file[_POSIX_PATH_MAX] = "";
static char cfg_file[_POSIX_PATH_MAX] = DEFAULT_CFG_FILE;

static void archive_cfg(struct list_head *head);
static void clear_cfg(struct list_head *head);
static void check_cfg(vhost_cfg_st *vhost, vhost_cfg_st *defvhost, unsigned silent);

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
	while(len > 0 && c_isspace(value[len-1])) \
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

struct snapshot_t * config_snapshot = NULL;

char ** pam_auth_group_list = NULL;
char ** gssapi_auth_group_list = NULL;
char ** plain_auth_group_list = NULL;
unsigned pam_auth_group_list_size = 0;
unsigned gssapi_auth_group_list_size = 0;
unsigned plain_auth_group_list_size = 0;


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
	void *(*get_brackets_string)(void *pool, struct perm_cfg_st *config, const char *);
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
#ifdef 	SUPPORT_OIDC_AUTH
	{NAME("oidc"), &oidc_auth_funcs, AUTH_TYPE_OIDC, oidc_get_brackets_string},
#endif
};


static void figure_auth_funcs(void *pool, const char *vhostname,
			      struct perm_cfg_st *config, char **auth, unsigned auth_size,
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
						config->auth[0].additional = avail_auth_types[i].get_brackets_string(pool, config, auth[j]+avail_auth_types[i].name_size);

					if (config->auth[0].amod != NULL && avail_auth_types[i].mod != NULL) {
						fprintf(stderr, ERRSTR"%s: you cannot mix multiple authentication methods of %s type\n", vhostname, auth[j]);
						exit(1);
					}

					if (config->auth[0].amod == NULL)
						config->auth[0].amod = avail_auth_types[i].mod;
					config->auth[0].type |= avail_auth_types[i].type;
					if (config->auth[0].name == NULL) {
						config->auth[0].name = talloc_strdup(pool, avail_auth_types[i].name);
					} else {
						char *tmp;
						tmp = talloc_asprintf(pool, "%s+%s", config->auth[0].name, avail_auth_types[i].name);
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
				fprintf(stderr, ERRSTR"%s: unknown or unsupported auth method: %s\n", vhostname, auth[j]);
				exit(1);
			}
			talloc_free(auth[j]);
		}
		fprintf(stderr, NOTESTR"%ssetting '%s' as primary authentication method\n", vhostname, config->auth[0].name);
	} else {
		unsigned x = config->auth_methods;
		/* Append authentication methods (alternative options) */
		for (j=0;j<auth_size;j++) {
			found = 0;
			for (i=0;i<sizeof(avail_auth_types)/sizeof(avail_auth_types[0]);i++) {
				if (c_strncasecmp(auth[j], avail_auth_types[i].name, avail_auth_types[i].name_size) == 0) {
					if (avail_auth_types[i].get_brackets_string)
						config->auth[x].additional = avail_auth_types[i].get_brackets_string(pool, config, auth[j]+avail_auth_types[i].name_size);

					config->auth[x].name = talloc_strdup(pool, avail_auth_types[i].name);
					fprintf(stderr, NOTESTR"%s: enabling '%s' as authentication method\n", vhostname, avail_auth_types[i].name);

					config->auth[x].amod = avail_auth_types[i].mod;
					config->auth[x].type |= avail_auth_types[i].type;
					config->auth[x].enabled = 1;
					found = 1;
					x++;
					if (x >= MAX_AUTH_METHODS) {
						fprintf(stderr, ERRSTR"%s: you cannot enable more than %d authentication methods\n", vhostname, x);
						exit(1);
					}
					break;
				}
			}

			if (found == 0) {
				fprintf(stderr, ERRSTR"%s: unknown or unsupported auth method: %s\n", vhostname, auth[j]);
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
	void *(*get_brackets_string)(void *pool, struct perm_cfg_st *config, const char *);
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

static void figure_acct_funcs(void *pool, const char *vhostname, struct perm_cfg_st *config, const char *acct)
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
				config->acct.additional = avail_acct_types[i].get_brackets_string(pool, config, acct+avail_acct_types[i].name_size);

			if ((avail_acct_types[i].mod->auth_types & config->auth[0].type) == 0) {
				fprintf(stderr, ERRSTR"%s: you cannot mix the '%s' accounting method with the '%s' authentication method\n", vhostname, acct, config->auth[0].name);
				exit(1);
			}

			config->acct.amod = avail_acct_types[i].mod;
			config->acct.name = avail_acct_types[i].name;
			found = 1;
			break;
		}
	}

	if (found == 0) {
		fprintf(stderr, ERRSTR"%s: unknown or unsupported accounting method: %s\n", vhostname, acct);
		exit(1);
	}
	fprintf(stderr, NOTESTR"%ssetting '%s' as accounting method\n", vhostname, config->acct.name);
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

static void apply_default_conf(vhost_cfg_st *vhost, unsigned reload)
{
	/* set config (no-zero) default vals
	 */
	if (!reload) { /* perm config defaults */
		tls_vhost_init(vhost);
		vhost->perm_config.stats_reset_time = 24*60*60*7; /* weekly */
	}

	vhost->perm_config.config->mobile_idle_timeout = (unsigned)-1;
#ifdef ENABLE_COMPRESSION
	vhost->perm_config.config->no_compress_limit = DEFAULT_NO_COMPRESS_LIMIT;
#endif
	vhost->perm_config.config->rekey_time = 24*60*60;
	vhost->perm_config.config->cookie_timeout = DEFAULT_COOKIE_RECON_TIMEOUT;
	vhost->perm_config.config->auth_timeout = DEFAULT_AUTH_TIMEOUT_SECS;
	vhost->perm_config.config->ban_reset_time = DEFAULT_BAN_RESET_TIME;
	vhost->perm_config.config->max_ban_score = DEFAULT_MAX_BAN_SCORE;
	vhost->perm_config.config->ban_points_wrong_password = DEFAULT_PASSWORD_POINTS;
	vhost->perm_config.config->ban_points_connect = DEFAULT_CONNECT_POINTS;
	vhost->perm_config.config->ban_points_kkdcp = DEFAULT_KKDCP_POINTS;
	vhost->perm_config.config->dpd = DEFAULT_DPD_TIME;
	vhost->perm_config.config->network.ipv6_subnet_prefix = 128;
	vhost->perm_config.config->dtls_legacy = 1;
	vhost->perm_config.config->dtls_psk = 1;
	vhost->perm_config.config->predictable_ips = 1;
	vhost->perm_config.config->use_utmp = 1;
	vhost->perm_config.config->keepalive = 3600;
	vhost->perm_config.config->dpd = 60;

}

static void cfg_new(struct vhost_cfg_st *vhost, unsigned reload)
{
	vhost->perm_config.config = talloc_zero(vhost->pool, struct cfg_st);
	if (vhost->perm_config.config == NULL)
		exit(1);

	vhost->perm_config.config->usage_count = talloc_zero(vhost->perm_config.config, int);
	if (vhost->perm_config.config->usage_count == NULL) {
		fprintf(stderr, ERRSTR"memory\n");
		exit(1);
	}

	apply_default_conf(vhost, reload);
}

static vhost_cfg_st *vhost_add(void *pool, struct list_head *head, const char *name, unsigned reload)
{
	vhost_cfg_st *vhost;

	vhost = talloc_zero(pool, struct vhost_cfg_st);
	if (vhost == NULL)
		exit(1);
	vhost->pool = vhost;

	cfg_new(vhost, reload);

	if (name) {
		vhost->name = talloc_strdup(vhost, name);
		if (vhost->name == NULL) {
			fprintf(stderr, ERRSTR"memory\n");
			exit(1);
		}
	}

	vhost->perm_config.sup_config_type = SUP_CONFIG_FILE;
	list_head_init(&vhost->perm_config.attic);


	list_add(head, &vhost->list);

	return vhost;
}

struct ini_ctx_st {
	struct list_head *head;
	unsigned reload;
	const char *file;
	void *pool;
};

#define WARN_ON_VHOST_ONLY(vname, oname) \
	({int rval; \
		if (vname) { \
			fprintf(stderr, WARNSTR"%s is ignored on %s virtual host\n", oname, vname); \
			rval = 1; \
		} else { \
			rval = 0; \
		} \
	rval; \
	})

#define WARN_ON_VHOST(vname, oname, member) \
	({int rval; \
		if (vname) { \
			fprintf(stderr, WARNSTR"%s is ignored on %s virtual host\n", oname, vname); \
			memcpy(&config->member, &defvhost->perm_config.config->member, sizeof(config->member)); \
			rval = 1; \
		} else { \
			rval = 0; \
		} \
	rval; \
	})

#define PWARN_ON_VHOST(vname, oname, member) \
	({int rval; \
		if (vname) { \
			fprintf(stderr, WARNSTR"%s is ignored on %s virtual host\n", oname, vname); \
			vhost->perm_config.member = defvhost->perm_config.member; \
			rval = 1; \
		} else { \
			rval = 0; \
		} \
	rval; \
	})

#define PWARN_ON_VHOST_STRDUP(vname, oname, member) \
	({int rval; \
		if (vname) { \
			fprintf(stderr, WARNSTR"%s is ignored on %s virtual host\n", oname, vname); \
			vhost->perm_config.member = talloc_strdup(pool, defvhost->perm_config.member); \
			rval = 1; \
		} else { \
			rval = 0; \
		} \
	rval; \
	})

static char *idna_map(void *pool, const char *name, unsigned size)
{
#if GNUTLS_VERSION_NUMBER > 0x030508
	int ret;
	gnutls_datum_t out;

	ret = gnutls_idna_map(name, size, &out, 0);
	if (ret < 0) {
		goto fallback;
	}

	return talloc_strdup(pool, (char*)out.data);

 fallback:
#endif
	return talloc_strndup(pool, name, size);
}

static
char *sanitize_name(void *pool, const char *p)
{
	size_t len;
	/* cleanup spaces before and after */
	while (c_isspace(*p))
		p++;

	len = strlen(p);
	if (len > 0) {
		while (c_isspace(p[len-1]))
			len--;
	}

	return idna_map(pool, p, len);
}

static int cfg_ini_handler(void *_ctx, const char *section, const char *name, const char *_value)
{
	struct ini_ctx_st *ctx = _ctx;
	vhost_cfg_st *vhost, *vtmp = NULL, *defvhost;
	unsigned use_dbus;
	struct cfg_st *config;
	void *pool;
	unsigned reload = ctx->reload;
	int ret;
	unsigned stage1_found = 1;
	unsigned force_cert_auth;
	unsigned prefix = 0;
	unsigned prefix4 = 0;
	unsigned found_vhost;
	char *value;

	defvhost = vhost = default_vhost(ctx->head);

	assert(defvhost != NULL);

	if (section != NULL && section[0] != 0) {
		char *vname;

		if (strncmp(section, "vhost:", 6) != 0) {
			if (reload == 0)
				fprintf(stderr, WARNSTR"skipping unknown section '%s'\n", section);
			return 0;
		}

		vname = sanitize_name(ctx->pool, section+6);
		if (vname == NULL || vname[0] == 0) {
			fprintf(stderr, ERRSTR"virtual host name is illegal '%s'\n", section+6);
			exit(1);
		}

		/* virtual host */
		found_vhost = 0;
		list_for_each(ctx->head, vtmp, list) {
			if (vtmp->name && strcmp(vtmp->name, vname) == 0) {
				vhost = vtmp;
				found_vhost = 1;
				break;
			}
		}

		if (c_strcasecmp(section+6, vname) != 0) {
			fprintf(stderr, NOTESTR"virtual host name '%s' was canonicalized to '%s'\n",
				section+6, vname);
		}

		if (!found_vhost) {
			/* add */
			fprintf(stderr, NOTESTR"adding virtual host: %s\n", vname);
			vhost = vhost_add(ctx->pool, ctx->head, vname, reload);
		}
		talloc_free(vname);
	}

	value = sanitize_config_value(vhost->pool, _value);
	if (value == NULL)
		return 0;

	/* read persistent configuration */
	if (vhost->auth_init == 0) {
		pool = vhost;

		if (strcmp(name, "auth") == 0) {
			READ_MULTI_LINE(vhost->auth, vhost->auth_size);
		} else if (strcmp(name, "enable-auth") == 0) {
			READ_MULTI_LINE(vhost->eauth, vhost->eauth_size);
		} else if (strcmp(name, "acct") == 0) {
			vhost->acct = talloc_strdup(pool, value);
		} else if (strcmp(name, "listen-host") == 0) {
			PREAD_STRING(pool, vhost->perm_config.listen_host);
		} else if (strcmp(name, "udp-listen-host") == 0) {
			PREAD_STRING(pool, vhost->perm_config.udp_listen_host);
		} else if (strcmp(name, "listen-clear-file") == 0) {
			if (!PWARN_ON_VHOST_STRDUP(vhost->name, "listen-clear-file", unix_conn_file))
				PREAD_STRING(pool, vhost->perm_config.unix_conn_file);
		} else if (strcmp(name, "tcp-port") == 0) {
			if (!PWARN_ON_VHOST(vhost->name, "tcp-port", port))
				READ_NUMERIC(vhost->perm_config.port);
		} else if (strcmp(name, "udp-port") == 0) {
			if (!PWARN_ON_VHOST(vhost->name, "udp-port", udp_port))
				READ_NUMERIC(vhost->perm_config.udp_port);
		} else if (strcmp(name, "run-as-user") == 0) {
			if (!PWARN_ON_VHOST(vhost->name, "run-as-user", uid)) {
				const struct passwd* pwd = getpwnam(value);
				if (pwd == NULL) {
					fprintf(stderr, ERRSTR"unknown user: %s\n", value);
					exit(1);
				}
				vhost->perm_config.uid = pwd->pw_uid;
			}
		} else if (strcmp(name, "run-as-group") == 0) {
			if (!PWARN_ON_VHOST(vhost->name, "run-as-group", gid)) {
				const struct group* grp = getgrnam(value);
				if (grp == NULL) {
					fprintf(stderr, ERRSTR"unknown group: %s\n", value);
					exit(1);
				}
				vhost->perm_config.gid = grp->gr_gid;
			}
		} else if (strcmp(name, "server-cert") == 0) {
			READ_MULTI_LINE(vhost->perm_config.cert, vhost->perm_config.cert_size);
		} else if (strcmp(name, "server-key") == 0) {
			READ_MULTI_LINE(vhost->perm_config.key, vhost->perm_config.key_size);
		} else if (strcmp(name, "dh-params") == 0) {
			READ_STRING(vhost->perm_config.dh_params_file);
		} else if (strcmp(name, "pin-file") == 0) {
			READ_STRING(vhost->perm_config.pin_file);
		} else if (strcmp(name, "srk-pin-file") == 0) {
			READ_STRING(vhost->perm_config.srk_pin_file);
		} else if (strcmp(name, "ca-cert") == 0) {
			READ_STRING(vhost->perm_config.ca);
#if !defined(OCSERV_WORKER_PROCESS)
		} else if (strcmp(name, "key-pin") == 0) {
			READ_STRING(vhost->perm_config.key_pin);
		} else if (strcmp(name, "srk-pin") == 0) {
			READ_STRING(vhost->perm_config.srk_pin);
#endif
		} else if (strcmp(name, "socket-file") == 0) {
			if (!PWARN_ON_VHOST_STRDUP(vhost->name, "socket-file", socket_file_prefix))
				PREAD_STRING(pool, vhost->perm_config.socket_file_prefix);
		} else if (strcmp(name, "occtl-socket-file") == 0) {
			if (!PWARN_ON_VHOST_STRDUP(vhost->name, "occtl-socket-file", occtl_socket_file))
				PREAD_STRING(pool, vhost->perm_config.occtl_socket_file);
		} else if (strcmp(name, "chroot-dir") == 0) {
			if (!PWARN_ON_VHOST_STRDUP(vhost->name, "chroot-dir", chroot_dir))
				PREAD_STRING(pool, vhost->perm_config.chroot_dir);
		} else if (strcmp(name, "server-stats-reset-time") == 0) {
			/* cannot be modified as it would require sec-mod to
			 * re-read configuration too */
			if (!PWARN_ON_VHOST(vhost->name, "server-stats-reset-time", stats_reset_time))
				READ_NUMERIC(vhost->perm_config.stats_reset_time);
		} else if (strcmp(name, "pid-file") == 0) {
			if (pid_file[0] == 0) {
				READ_STATIC_STRING(pid_file);
			} else if (reload == 0)
				fprintf(stderr, NOTESTR"skipping 'pid-file' config option\n");
		} else {
			stage1_found = 0;
		}
		if (stage1_found)
			goto exit;
	}


	/* read the rest of the (non-permanent) configuration */
	pool = vhost->perm_config.config;
	config = vhost->perm_config.config;

	/* When adding allocated data, remember to modify
	 * reload_cfg_file();
	 */
	if (strcmp(name, "listen-host-is-dyndns") == 0) {
		READ_TF(config->is_dyndns);
	} else if (strcmp(name, "listen-proxy-proto") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "listen-proxy-proto", listen_proxy_proto))
			READ_TF(config->listen_proxy_proto);
	} else if (strcmp(name, "append-routes") == 0) {
		READ_TF(config->append_routes);
#ifdef HAVE_GSSAPI
	} else if (strcmp(name, "kkdcp") == 0) {
		READ_MULTI_LINE(vhost->urlfw, vhost->urlfw_size);
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
		if (!WARN_ON_VHOST(vhost->name, "rate-limit-ms", rate_limit_ms))
			READ_NUMERIC(config->rate_limit_ms);
	} else if (strcmp(name, "ocsp-response") == 0) {
		READ_STRING(config->ocsp_response);
#ifdef ANYCONNECT_CLIENT_COMPAT
	} else if (strcmp(name, "user-profile") == 0) {
		READ_STRING(config->xml_config_file);
#endif 
	} else if (strcmp(name, "default-domain") == 0) {
		READ_STRING(config->default_domain);
	} else if (strcmp(name, "crl") == 0) {
		READ_STRING(config->crl);
	} else if (strcmp(name, "cert-user-oid") == 0) {
		READ_STRING(config->cert_user_oid);
	} else if (strcmp(name, "cert-group-oid") == 0) {
		READ_STRING(config->cert_group_oid);
	} else if (strcmp(name, "connect-script") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "connect-script", connect_script))
			READ_STRING(config->connect_script);
	} else if (strcmp(name, "host-update-script") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "host-update-script", host_update_script))
			READ_STRING(config->host_update_script);
	} else if (strcmp(name, "disconnect-script") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "disconnect-script", disconnect_script))
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
		if (!WARN_ON_VHOST(vhost->name, "dtls-psk", dtls_psk))
			READ_TF(config->dtls_psk);
	} else if (strcmp(name, "match-tls-dtls-ciphers") == 0) {
		READ_TF(config->match_dtls_and_tls);
#ifdef ENABLE_COMPRESSION
	} else if (strcmp(name, "compression") == 0) {
		READ_TF(config->enable_compression);
	} else if (strcmp(name, "compression-algo-priority") == 0) {
		if (!WARN_ON_VHOST_ONLY(vhost->name, "compression-algo-priority")) {
#if defined(OCSERV_WORKER_PROCESS)
			if (switch_comp_priority(pool, value) == 0) {
				fprintf(stderr, WARNSTR"invalid compression modstring %s\n", value);
			}
#endif
		}
	} else if (strcmp(name, "no-compress-limit") == 0) {
		READ_NUMERIC(config->no_compress_limit);
#endif
	} else if (strcmp(name, "use-seccomp") == 0) {
		READ_TF(config->isolate);
		if (config->isolate)
			fprintf(stderr, NOTESTR"'use-seccomp' was replaced by 'isolate-workers'\n");
	} else if (strcmp(name, "isolate-workers") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "isolate-workers", isolate))
			READ_TF(config->isolate);
	} else if (strcmp(name, "predictable-ips") == 0) {
		READ_TF(config->predictable_ips);
	} else if (strcmp(name, "use-utmp") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "use-utmp", use_utmp))
			READ_TF(config->use_utmp);
	} else if (strcmp(name, "use-dbus") == 0) {
		READ_TF(use_dbus);
		if (use_dbus != 0) {
			fprintf(stderr, NOTESTR"'use-dbus' was replaced by 'use-occtl'\n");
			config->use_occtl = use_dbus;
		}
	} else if (strcmp(name, "use-occtl") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "use-occtl", use_occtl))
			READ_TF(config->use_occtl);
	} else if (strcmp(name, "try-mtu-discovery") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "try-mtu-discovery", try_mtu))
			READ_TF(config->try_mtu);
	} else if (strcmp(name, "ping-leases") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "ping_leases", ping_leases))
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
		if (!WARN_ON_VHOST(vhost->name, "auth-timeout", auth_timeout))
			READ_NUMERIC(config->auth_timeout);
	} else if (strcmp(name, "idle-timeout") == 0) {
		READ_NUMERIC(config->idle_timeout);
	} else if (strcmp(name, "mobile-idle-timeout") == 0) {
		READ_NUMERIC(config->mobile_idle_timeout);
	} else if (strcmp(name, "max-clients") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "max-clients", max_clients))
			READ_NUMERIC(config->max_clients);
	} else if (strcmp(name, "min-reauth-time") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "min-reauth-time", min_reauth_time))
			READ_NUMERIC(config->min_reauth_time);
	} else if (strcmp(name, "ban-reset-time") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "ban-reset-time", ban_reset_time))
			READ_NUMERIC(config->ban_reset_time);
	} else if (strcmp(name, "max-ban-score") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "max-ban-score", max_ban_score))
			READ_NUMERIC( config->max_ban_score);
	} else if (strcmp(name, "ban-points-wrong-password") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "ban-points-wrong-password", ban_points_wrong_password))
			READ_NUMERIC(config->ban_points_wrong_password);
	} else if (strcmp(name, "ban-points-connection") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "ban-points-connection", ban_points_connect))
			READ_NUMERIC(config->ban_points_connect);
	} else if (strcmp(name, "ban-points-kkdcp") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "ban-points-kkdcp", ban_points_kkdcp))
			READ_NUMERIC(config->ban_points_kkdcp);
	} else if (strcmp(name, "max-same-clients") == 0) {
		READ_NUMERIC(config->max_same_clients);
	} else if (strcmp(name, "device") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "device", network.name))
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
		READ_TF(vhost->auto_select_group);
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
		if (!WARN_ON_VHOST(vhost->name, "route-add-cmd", route_add_cmd))
			READ_STRING(config->route_add_cmd);
	} else if (strcmp(name, "route-del-cmd") == 0) {
		if (!WARN_ON_VHOST(vhost->name, "route-del-cmd", route_del_cmd))
			READ_STRING(config->route_del_cmd);
	} else if (strcmp(name, "config-per-user") == 0) {
		READ_STRING(config->per_user_dir);
	} else if (strcmp(name, "config-per-group") == 0) {
		READ_STRING(config->per_group_dir);
	} else if (strcmp(name, "expose-iroutes") == 0) {
		READ_TF(vhost->expose_iroutes);
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

enum {
	CFG_FLAG_RELOAD = (1<<0),
	CFG_FLAG_SECMOD = (1<<1),
	CFG_FLAG_WORKER = (1<<2)
};

static void replace_file_with_snapshot(char ** file_name)
{
	char * snapshot_file_name;
	if (*file_name == NULL) {
		return;
	}

	if (snapshot_lookup_filename(
			config_snapshot, 
			*file_name, 
			&snapshot_file_name) < 0) {
		fprintf(stderr, ERRSTR"cannot find snapshot for file %s\n", *file_name);
		exit(1);
	}

	talloc_free(*file_name);
	*file_name = snapshot_file_name;
}

static void parse_cfg_file(void *pool, const char *file, struct list_head *head,
			   unsigned flags)
{
	int ret;
	struct cfg_st *config;
	struct ini_ctx_st ctx;
	vhost_cfg_st *vhost = NULL;
	vhost_cfg_st *defvhost;

	memset(&ctx, 0, sizeof(ctx));
	ctx.file = file;
	ctx.reload = (flags&CFG_FLAG_RELOAD)?1:0;
	ctx.head = head;

	// Worker always reads from snapshot
	if ((flags & CFG_FLAG_WORKER) == CFG_FLAG_WORKER) {
		char * snapshot_file = NULL;

		if ((snapshot_lookup_filename(config_snapshot, file, &snapshot_file) < 0) && 
			(snapshot_lookup_filename(config_snapshot, OLD_DEFAULT_CFG_FILE, &snapshot_file) < 0)) {
			fprintf(stderr, ERRSTR"snapshot_lookup failed for file %s\n", file);
			exit(1);
		}

		ret = ini_parse(snapshot_file, cfg_ini_handler, &ctx);
		if (ret < 0) {
			fprintf(stderr, ERRSTR"cannot load config file %s\n", file);
			exit(1);
		}
		talloc_free(snapshot_file);

		// Walk the config, replacing filename with the snapshot equivalent
		list_for_each(head, vhost, list) {
			size_t index;
			replace_file_with_snapshot(&vhost->perm_config.dh_params_file);
			replace_file_with_snapshot(&vhost->perm_config.config->ocsp_response);
			for (index = 0; index < vhost->perm_config.cert_size; index ++) {
				replace_file_with_snapshot(&vhost->perm_config.cert[index]);
			}
		}
	} else {
		const char * cfg_file = file;

		if (cfg_file == NULL) {
			fprintf(stderr, ERRSTR"no config file!\n");
			exit(1);
		}

		/* parse configuration
		*/
		ret = ini_parse(cfg_file, cfg_ini_handler, &ctx);
		if (ret < 0 && file != NULL && strcmp(file, DEFAULT_CFG_FILE) == 0) {
			cfg_file = OLD_DEFAULT_CFG_FILE;
			ret = ini_parse(cfg_file, cfg_ini_handler, &ctx);
		}

		if (ret < 0) {
			fprintf(stderr, ERRSTR"cannot load config file %s\n", cfg_file);
			exit(1);
		}
		
		ret = snapshot_create(config_snapshot, cfg_file);
		if (ret < 0){
			fprintf(stderr, ERRSTR"cannot snapshot config file %s\n", cfg_file);
			exit(1);
		}
		list_for_each(head, vhost, list) {
			size_t index;
			snapshot_create(config_snapshot, vhost->perm_config.dh_params_file);
			snapshot_create(config_snapshot, vhost->perm_config.config->ocsp_response);
			for (index = 0; index < vhost->perm_config.cert_size; index ++) {
				snapshot_create(config_snapshot, vhost->perm_config.cert[index]);
			}
		}

	}

	/* apply configuration not yet applied.
	 * We start from the last, which is the default server (firstly
	 * added).
	 */
	list_for_each_rev(head, vhost, list) {
		config = vhost->perm_config.config;

		if (vhost->auth_init == 0) {
			if (vhost->auth_size == 0) {
				fprintf(stderr, ERRSTR"%sthe 'auth' configuration option was not specified!\n", PREFIX_VHOST(vhost));
				exit(1);
			}

			figure_auth_funcs(vhost, PREFIX_VHOST(vhost), &vhost->perm_config, vhost->auth, vhost->auth_size, 1);
			figure_auth_funcs(vhost, PREFIX_VHOST(vhost), &vhost->perm_config, vhost->eauth, vhost->eauth_size, 0);

			figure_acct_funcs(vhost, PREFIX_VHOST(vhost), &vhost->perm_config, vhost->acct);

			vhost->auth_init = 1;
		}

		if (vhost->auto_select_group != 0 && vhost->perm_config.auth[0].amod != NULL && vhost->perm_config.auth[0].amod->group_list != NULL) {
			vhost->perm_config.auth[0].amod->group_list(config, vhost->perm_config.auth[0].additional, &config->group_list, &config->group_list_size);
			switch (vhost->perm_config.auth[0].amod->type) {
			case AUTH_TYPE_PAM|AUTH_TYPE_USERNAME_PASS:
				pam_auth_group_list = config->group_list;
				pam_auth_group_list_size = config->group_list_size;
				break;
			case AUTH_TYPE_GSSAPI:
				gssapi_auth_group_list = config->group_list;
				gssapi_auth_group_list_size = config->group_list_size;
				break;
			case AUTH_TYPE_PLAIN|AUTH_TYPE_USERNAME_PASS:
				plain_auth_group_list = config->group_list;
				plain_auth_group_list_size = config->group_list_size;
				break;
			}
		}

		if (vhost->expose_iroutes != 0) {
			load_iroutes(config);
		}

		if (vhost->name)
			defvhost = default_vhost(head);
		else
			defvhost = NULL;

		/* this check copies mandatory fields from default vhost if needed */
		check_cfg(vhost, defvhost, ctx.reload);

		/* the following are only useful in main process */
		if (!(flags & CFG_FLAG_SECMOD)) {
			tls_load_files(NULL, vhost);
			tls_load_prio(NULL, vhost);
			tls_reload_crl(NULL, vhost, 1);
		}

#ifdef HAVE_GSSAPI
		if (vhost->urlfw_size > 0) {
			parse_kkdcp(config, vhost->urlfw, vhost->urlfw_size);
			talloc_free(vhost->urlfw);
			vhost->urlfw = NULL;
		}
#endif
		fprintf(stderr, NOTESTR"%ssetting '%s' as supplemental config option\n",
			PREFIX_VHOST(vhost),
			sup_config_name(vhost->perm_config.sup_config_type));
	}
}


/* sanity checks on config */
static void check_cfg(vhost_cfg_st *vhost, vhost_cfg_st *defvhost, unsigned silent)
{
	unsigned j, i;
	struct cfg_st *config;

	config = vhost->perm_config.config;

	if (vhost->perm_config.auth[0].enabled == 0) {
		fprintf(stderr, ERRSTR"%sno authentication method was specified!\n", PREFIX_VHOST(vhost));
		exit(1);
	}

	if (vhost->perm_config.socket_file_prefix == NULL) {
		if (vhost->name) {
			vhost->perm_config.socket_file_prefix = talloc_strdup(vhost, defvhost->perm_config.socket_file_prefix);
		} else {
			/* The 'socket-file' is not mandatory on main server */
			fprintf(stderr, ERRSTR"%sthe 'socket-file' configuration option must be specified!\n", PREFIX_VHOST(vhost));
			exit(1);
		}
	}

	if (vhost->perm_config.port == 0 && vhost->perm_config.unix_conn_file == NULL) {
		if (defvhost) {
			if (vhost->perm_config.port)
				vhost->perm_config.port = vhost->perm_config.port;
			else if (vhost->perm_config.unix_conn_file)
				vhost->perm_config.unix_conn_file = talloc_strdup(vhost, vhost->perm_config.unix_conn_file);
		} else {
			fprintf(stderr, ERRSTR"%sthe tcp-port option is mandatory!\n", PREFIX_VHOST(vhost));
			exit(1);
		}
	}

	if (vhost->perm_config.cert_size == 0 || vhost->perm_config.key_size == 0) {
		fprintf(stderr, ERRSTR"%sthe 'server-cert' and 'server-key' configuration options must be specified!\n", PREFIX_VHOST(vhost));
		exit(1);
	}

	if (config->network.ipv4 == NULL && config->network.ipv6 == NULL) {
		fprintf(stderr, ERRSTR"%sno ipv4-network or ipv6-network options set.\n", PREFIX_VHOST(vhost));
		exit(1);
	}

	if (config->network.ipv4 != NULL && config->network.ipv4_netmask == NULL) {
		fprintf(stderr, ERRSTR"%sno mask found for IPv4 network.\n", PREFIX_VHOST(vhost));
		exit(1);
	}

	if (config->network.ipv6 != NULL && config->network.ipv6_prefix == 0) {
		fprintf(stderr, ERRSTR"%sno prefix found for IPv6 network.\n", PREFIX_VHOST(vhost));
		exit(1);
	}

	if (config->banner && strlen(config->banner) > MAX_BANNER_SIZE) {
		fprintf(stderr, ERRSTR"%sbanner size is too long\n", PREFIX_VHOST(vhost));
		exit(1);
	}

	if (vhost->perm_config.cert_size != vhost->perm_config.key_size) {
		fprintf(stderr, ERRSTR"%sthe specified number of keys doesn't match the certificates\n", PREFIX_VHOST(vhost));
		exit(1);
	}

	if ((vhost->perm_config.auth[0].type & AUTH_TYPE_CERTIFICATE) && vhost->perm_config.auth_methods == 1) {
		if (config->cisco_client_compat == 0)
			config->cert_req = GNUTLS_CERT_REQUIRE;
		else
			config->cert_req = GNUTLS_CERT_REQUEST;
	} else {
		unsigned i;
		for (i=0;i<vhost->perm_config.auth_methods;i++) {
			if (vhost->perm_config.auth[i].type & AUTH_TYPE_CERTIFICATE) {
				config->cert_req = GNUTLS_CERT_REQUEST;
				break;
			}
		}
	}

	if (config->cert_req != 0 && config->cert_user_oid == NULL) {
		fprintf(stderr, ERRSTR"%sa certificate is requested by the option 'cert-user-oid' is not set\n", PREFIX_VHOST(vhost));
		exit(1);
	}

	if (config->cert_req != 0 && config->cert_user_oid != NULL) {
		if (!c_isdigit(config->cert_user_oid[0]) && strcmp(config->cert_user_oid, "SAN(rfc822name)") != 0) {
			fprintf(stderr, ERRSTR"%sthe option 'cert-user-oid' has a unsupported value\n", PREFIX_VHOST(vhost));
			exit(1);
		}
	}

	if (vhost->perm_config.unix_conn_file != NULL && (config->cert_req != 0)) {
		if (config->listen_proxy_proto == 0) {
			fprintf(stderr, ERRSTR"%sthe option 'listen-clear-file' cannot be combined with 'auth=certificate'\n", PREFIX_VHOST(vhost));
			exit(1);
		}
	}

#ifdef ANYCONNECT_CLIENT_COMPAT
	if (vhost->perm_config.cert && vhost->perm_config.cert_hash == NULL) {
		vhost->perm_config.cert_hash = calc_sha1_hash(vhost->pool, vhost->perm_config.cert[0], 1);
	}

	if (config->xml_config_file) {
		config->xml_config_hash = calc_sha1_hash(vhost->pool, config->xml_config_file, 0);
		if (config->xml_config_hash == NULL && vhost->perm_config.chroot_dir != NULL) {
			char path[_POSIX_PATH_MAX];

			snprintf(path, sizeof(path), "%s/%s", vhost->perm_config.chroot_dir, config->xml_config_file);
			config->xml_config_hash = calc_sha1_hash(vhost->pool, path, 0);

			if (config->xml_config_hash == NULL) {
				fprintf(stderr, ERRSTR"%scannot open file '%s'\n", PREFIX_VHOST(vhost), path);
				exit(1);
			}
		}
		if (config->xml_config_hash == NULL) {
			fprintf(stderr, ERRSTR"%scannot open file '%s'\n", PREFIX_VHOST(vhost), config->xml_config_file);
			exit(1);
		}
	}
#endif

	if (config->priorities == NULL) {
		/* on vhosts assign the main host priorities */
		if (defvhost) {
			config->priorities = talloc_strdup(config, defvhost->perm_config.config->priorities);
		} else {
			config->priorities = talloc_strdup(config, "NORMAL:%SERVER_PRECEDENCE:%COMPAT");
		}
	}

	if (vhost->perm_config.occtl_socket_file == NULL)
		vhost->perm_config.occtl_socket_file = talloc_strdup(vhost, OCCTL_UNIX_SOCKET);


	if (config->network.ipv6_prefix && config->network.ipv6_prefix >= config->network.ipv6_subnet_prefix) {
		fprintf(stderr, ERRSTR"%sthe subnet prefix (%u) cannot be smaller or equal to network's (%u)\n",
				PREFIX_VHOST(vhost), config->network.ipv6_subnet_prefix, config->network.ipv6_prefix);
		exit(1);
	}

	if (!vhost->name && config->network.name[0] == 0) {
		fprintf(stderr, ERRSTR"%sthe 'device' configuration option must be specified!\n", PREFIX_VHOST(vhost));
		exit(1);
	}

	if (config->mobile_dpd == 0)
		config->mobile_dpd = config->dpd;

	if (config->cisco_client_compat) {
		if (!config->dtls_legacy && !silent) {
			fprintf(stderr, NOTESTR"%sthe cisco-client-compat option implies dtls-legacy = true; enabling\n", PREFIX_VHOST(vhost));
		}
		config->dtls_legacy = 1;
	}

	if (vhost->perm_config.unix_conn_file) {
		if (config->dtls_psk && !silent) {
			fprintf(stderr, NOTESTR"%s'dtls-psk' cannot be combined with unix socket file\n", PREFIX_VHOST(vhost));
		}
		config->dtls_psk = 0;
	}

	if (config->match_dtls_and_tls) {
		if (config->dtls_legacy) {
			fprintf(stderr, ERRSTR"%s'match-tls-dtls-ciphers' cannot be applied when 'dtls-legacy' or 'cisco-client-compat' is on\n", PREFIX_VHOST(vhost));
			exit(1);
		}
	}

	if (config->mobile_idle_timeout == (unsigned)-1)
		config->mobile_idle_timeout = config->idle_timeout;

#ifdef ENABLE_COMPRESSION
	if (config->no_compress_limit < MIN_NO_COMPRESS_LIMIT)
		config->no_compress_limit = MIN_NO_COMPRESS_LIMIT;
#endif

	/* use tcp listen host by default */
	if (vhost->perm_config.udp_listen_host ==  NULL) {
		vhost->perm_config.udp_listen_host = vhost->perm_config.listen_host;
	}

#if !defined(HAVE_LIBSECCOMP)
	if (config->isolate != 0 && !silent) {
		fprintf(stderr, ERRSTR"%s'isolate-workers' is set to true, but not compiled with seccomp or Linux namespaces support\n", PREFIX_VHOST(vhost));
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
			fprintf(stderr, ERRSTR"%sthe 'local' DNS keyword is no longer supported.\n", PREFIX_VHOST(vhost));
			exit(1);
		}
	}

	if (config->per_user_dir || config->per_group_dir) {
		if (vhost->perm_config.sup_config_type != SUP_CONFIG_FILE) {
			fprintf(stderr, ERRSTR"%sspecified config-per-user or config-per-group but supplemental config is '%s'\n",
				PREFIX_VHOST(vhost), sup_config_name(vhost->perm_config.sup_config_type));
			exit(1);
		}
	}

}

#define OPT_NO_CHDIR 1
static const struct option long_options[] = {
	{"debug", 1, 0, 'd'},
	{"config", 1, 0, 'c'},
	{"pid-file", 1, 0, 'p'},
	{"test-config", 0, 0, 't'},
	{"foreground", 0, 0, 'f'},
	{"no-chdir", 0, 0, OPT_NO_CHDIR},
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
	fprintf(stderr, "       --no-chdir             Do not perform a chdir on daemonize\n");
	fprintf(stderr, "   -p, --pid-file=file        Specify pid file for the server\n");
	fprintf(stderr, "   -v, --version              output version information and exit\n");
	fprintf(stderr, "   -h, --help                 display extended usage information and exit\n\n");

	fprintf(stderr, "Openconnect VPN server (ocserv) is a VPN server compatible with the\n");
	fprintf(stderr, "openconnect VPN client.  It follows the TLS and DTLS-based AnyConnect VPN\n");
	fprintf(stderr, "protocol which is used by several CISCO routers.\n\n");

	fprintf(stderr, "Please send bug reports to:  "PACKAGE_BUGREPORT"\n");
}

int cmd_parser (void *pool, int argc, char **argv, struct list_head *head, bool worker)
{
	unsigned test_only = 0;
	int c;
	vhost_cfg_st *vhost;

	vhost = vhost_add(pool, head, NULL, 0);
	assert(vhost != NULL);

	while (1) {
		c = getopt_long(argc, argv, "d:c:p:ftvh", long_options, NULL);
		if (c == -1)
			break;

		switch(c) {
			case 'f':
				vhost->perm_config.foreground = 1;
				break;
			case 'p':
				strlcpy(pid_file, optarg, sizeof(pid_file));
				break;
			case 'c':
				strlcpy(cfg_file, optarg, sizeof(cfg_file));
				break;
			case 'd':
				vhost->perm_config.debug = atoi(optarg);
				break;
			case 't':
				test_only = 1;
				break;
			case OPT_NO_CHDIR:
				vhost->perm_config.no_chdir = 1;
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

	parse_cfg_file(pool, cfg_file, head, worker ? CFG_FLAG_WORKER : 0);

	if (test_only)
		exit(0);

	return 0;

}

static void archive_cfg(struct list_head *head)
{
	attic_entry_st *e;
	struct vhost_cfg_st* vhost = NULL;

	list_for_each(head, vhost, list) {
		/* we don't clear anything as it may be referenced by some
		 * client (proc_st). We move everything to attic and
		 * once nothing is in use we clear that */

		e = talloc(vhost, attic_entry_st);
		if (e == NULL) {
			/* we leak, but better than crashing */
			return;
		}

		e->usage_count = vhost->perm_config.config->usage_count;

		/* we rely on talloc doing that recursively */
		talloc_steal(e, vhost->perm_config.config);
		vhost->perm_config.config = NULL;

		if (e->usage_count == NULL || *e->usage_count == 0) {
			talloc_free(e);
		} else {
			list_add(&vhost->perm_config.attic, &e->list);
		}
	}

	return;
}

static void clear_cfg(struct list_head *head)
{
	vhost_cfg_st *cpos = NULL, *ctmp;

	list_for_each_safe(head, cpos, ctmp, list) {
		/* we rely on talloc freeing recursively */
		talloc_free(cpos->perm_config.config);
		cpos->perm_config.config = NULL;
	}

	return;
}

void clear_vhosts(struct list_head *head)
{
	vhost_cfg_st *vhost = NULL, *ctmp;

	list_for_each_safe(head, vhost, ctmp, list) {
		tls_vhost_deinit(vhost);
		/* we rely on talloc freeing recursively */
		talloc_free(vhost->perm_config.config);
		vhost->perm_config.config = NULL;
	}

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
#ifdef SUPPORT_OIDC_AUTH
	append("oidc_auth");
#endif
	fprintf(stderr, "\n");

	p = gnutls_check_version(NULL);
	if (strcmp(p, GNUTLS_VERSION) != 0) {
		fprintf(stderr, "GnuTLS version: %s (compiled with %s)\n", p, GNUTLS_VERSION);
	} else {
		fprintf(stderr, "GnuTLS version: %s\n", p);
	}
}


void reload_cfg_file(void *pool, struct list_head *configs, unsigned sec_mod)
{
	struct vhost_cfg_st* vhost = NULL;
	unsigned flags = CFG_FLAG_RELOAD;

	if (sec_mod)
		flags |= CFG_FLAG_SECMOD;

	/* Archive or clear any non-permanent configs */
	if (!sec_mod)
		archive_cfg(configs);
	else
		clear_cfg(configs);

	/* Create new config structures and apply defaults */
	list_for_each(configs, vhost, list) {
		if (vhost->perm_config.config == NULL)
			cfg_new(vhost, 1);
	}

	/* parse the config again */
	parse_cfg_file(pool, cfg_file, configs, flags);

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
		tmp = talloc_realloc(pool, *varname, char*, (*num)+2);
		if (tmp == NULL)
			return -1;
		*varname = tmp;
	}

	(*varname)[*num] = talloc_strdup(*varname, value);
	(*num)++;

	(*varname)[*num] = NULL;
	return 0;
}

void clear_old_configs(struct list_head *head)
{
	attic_entry_st *e = NULL, *pos;
	vhost_cfg_st *cpos = NULL;

	list_for_each(head, cpos, list) {
		/* go through the attic and clear old configurations if unused */
		list_for_each_safe(&cpos->perm_config.attic, e, pos, list) {
			if (*e->usage_count == 0) {
				list_del(&e->list);
				talloc_free(e);
			}
		}
	}
}

// ocserv and ocserv-worker both load and parse the configuration files.
// As part of the process of loading the config files, auth / acct methods 
// are enabled based on the content of the acct_mod_st and auth_mod_st tables.
// These auth tables are present in the auth sub-subsystem. Linking against
// the auth subsystem pulls in a very large set of dependent binaries which
// increases the overall memory footprint. To avoid this, we provide stub 
// versions of acct_mod_st and auth_mod_st tables that the ocserv-worker
// process can link against.
#if defined(OCSERV_WORKER_PROCESS)

// Group information is populated by the auth subsystem. 
// When compiles as part of ocserv-worker, the auth subsystem is not present.
// To work around this, the group information is passed from ocserv-main to
// ocserv-worker, which then caches it and returns it when queried.
static void pam_group_list(void *pool, void *_additional, char ***groupname, unsigned *groupname_size)
{
	*groupname = pam_auth_group_list;
	*groupname_size = pam_auth_group_list_size;
}

static void gssapi_group_list(void *pool, void *_additional, char ***groupname, unsigned *groupname_size)
{
	*groupname = gssapi_auth_group_list;
	*groupname_size = gssapi_auth_group_list_size;
}

static void plain_group_list(void *pool, void *_additional, char ***groupname, unsigned *groupname_size)
{
	*groupname = plain_auth_group_list;
	*groupname_size = plain_auth_group_list_size;
}

const struct acct_mod_st radius_acct_funcs = {
	.type = ACCT_TYPE_RADIUS,
	.auth_types = ALL_AUTH_TYPES,
	.vhost_init = NULL,
	.vhost_deinit = NULL,
	.open_session = NULL,
	.close_session = NULL,
	.session_stats = NULL
};

const struct acct_mod_st pam_acct_funcs = {
  .type = ACCT_TYPE_PAM,
  .auth_types = ALL_AUTH_TYPES,
  .open_session = NULL,
  .close_session = NULL,
};

const struct auth_mod_st pam_auth_funcs = {
  .type = AUTH_TYPE_PAM | AUTH_TYPE_USERNAME_PASS,
  .auth_init = NULL,
  .auth_deinit = NULL,
  .auth_msg = NULL,
  .auth_pass = NULL,
  .auth_group = NULL,
  .auth_user = NULL,
  .group_list = pam_group_list
};

const struct auth_mod_st gssapi_auth_funcs = {
	.type = AUTH_TYPE_GSSAPI,
	.auth_init = NULL,
	.auth_deinit = NULL,
	.auth_msg = NULL,
	.auth_pass = NULL,
	.auth_user = NULL,
	.auth_group = NULL,
	.vhost_init = NULL,
	.vhost_deinit = NULL,
	.group_list = gssapi_group_list
};

const struct auth_mod_st plain_auth_funcs = {
	.type = AUTH_TYPE_PLAIN | AUTH_TYPE_USERNAME_PASS,
	.allows_retries = 1,
	.vhost_init = NULL,
	.auth_init = NULL,
	.auth_deinit = NULL,
	.auth_msg = NULL,
	.auth_pass = NULL,
	.auth_user = NULL,
	.auth_group = NULL,
	.group_list = plain_group_list
};


const struct auth_mod_st radius_auth_funcs = {
	.type = AUTH_TYPE_RADIUS | AUTH_TYPE_USERNAME_PASS,
	.allows_retries = 1,
	.vhost_init = NULL,
	.vhost_deinit = NULL,
	.auth_init = NULL,
	.auth_deinit = NULL,
	.auth_msg = NULL,
	.auth_pass = NULL,
	.auth_user = NULL,
	.auth_group = NULL,
	.group_list = NULL
};

const struct auth_mod_st oidc_auth_funcs = {
	.type = AUTH_TYPE_OIDC,
	.allows_retries = 1,
	.vhost_init = NULL,
	.vhost_deinit = NULL,
	.auth_init = NULL,
	.auth_deinit = NULL,
	.auth_msg = NULL,
	.auth_pass = NULL,
	.auth_user = NULL,
	.auth_group = NULL,
	.group_list = NULL
};


#else
int get_cert_names(struct worker_st * ws, const gnutls_datum_t * raw)
{
	return -1;
}
#endif

char secmod_socket_file_name_socket_file[_POSIX_PATH_MAX] = {0};

void restore_secmod_socket_file_name(const char * save_path)
{
	strlcpy(secmod_socket_file_name_socket_file, save_path, sizeof(secmod_socket_file_name_socket_file));
}

/* Creates a permanent filename to use for secmod to main communication
 */
const char *secmod_socket_file_name(struct perm_cfg_st *perm_config)
{
	unsigned int rnd;
	int ret;

	if (secmod_socket_file_name_socket_file[0] != 0)
		return secmod_socket_file_name_socket_file;

	ret = gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(rnd));
	if (ret < 0)
		exit(1);

	/* make socket name */
	snprintf(secmod_socket_file_name_socket_file, sizeof(secmod_socket_file_name_socket_file), "%s.%x",
		 perm_config->socket_file_prefix, rnd);

	return secmod_socket_file_name_socket_file;
}
