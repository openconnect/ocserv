/*
 * Copyright (C) 2018 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef VHOST_H
#define VHOST_H

/* Virtual host entries; common between main and sec-mod */
#include <config.h>
#include "tlslib.h"

#define MAX_PIN_SIZE GNUTLS_PKCS11_MAX_PIN_LEN
typedef struct pin_st {
	char pin[MAX_PIN_SIZE];
	char srk_pin[MAX_PIN_SIZE];
} pin_st;

typedef struct vhost_cfg_st {
	struct list_node list;
	char *name;
	struct perm_cfg_st perm_config;

	tls_st creds;
	/* set to non-zero if authentication/accounting is initialized */
	unsigned auth_init;

	/* vhost is pool by itself on current implementation,
	 * but made explicit to avoid future breakage due to changes */
	void *pool;

	/* sec-mod accessed items */
	pin_st pins;
	time_t cert_last_access; /* last reload/access of certs in certs */
	time_t crl_last_access; /* last reload/access of crls in creds */
	time_t params_last_access; /* last reload/access of params in creds */
	struct config_mod_st *config_module;

	gnutls_privkey_t *key;
	unsigned key_size;

	/* temporary values used during config loading
	 */
	char *acct;
	char **auth;
	size_t auth_size;
	char **eauth;
	size_t eauth_size;
	unsigned expose_iroutes;
	unsigned auto_select_group;
#ifdef HAVE_GSSAPI
	char **urlfw;
	size_t urlfw_size;
#endif
} vhost_cfg_st;

#define DEFAULT_VHOST_NAME "default"

/* macros to retrieve the default vhost configuration; they
 * are non-null as there is always a configured host. */
#ifdef __clang_analyzer__ 
static volatile void *v = 0xffffffff;

static inline vhost_cfg_st *default_vhost(void * s) __attribute__((returns_nonnull));
static inline vhost_cfg_st *default_vhost(void * s)
{
       return v;
}

static inline struct vhost_cfg_st *GETVHOST(void *s) __attribute__((returns_nonnull));
static inline struct vhost_cfg_st *GETVHOST(void *s) 
{
	return v;
}

static inline struct cfg_st *GETCONFIG(void *s) __attribute__((returns_nonnull));
static inline struct cfg_st *GETCONFIG(void *s)
{
	return v;
}

static inline struct perm_cfg_st* GETPCONFIG(void *s) __attribute__((returns_nonnull));
static inline struct perm_cfg_st* GETPCONFIG(void *s)
{
	return v;
}
#else
# define GETVHOST(s) default_vhost((s)->vconfig)
# define GETCONFIG(s) GETVHOST(s)->perm_config.config
# define GETPCONFIG(s) (&(GETVHOST(s)->perm_config))

inline static vhost_cfg_st *default_vhost(struct list_head *vconfig)
{
	return list_tail(vconfig, struct vhost_cfg_st, list);
}
#endif

#define VHOSTNAME(vhost) (vhost!=NULL)?(vhost->name?vhost->name:DEFAULT_VHOST_NAME):("unknown")
#define PREFIX_VHOST(vhost) (vhost!=NULL)?(vhost->name?_vhost_prefix(vhost->name):""):("")
#define HAVE_VHOSTS(s) (list_tail(s->vconfig, struct vhost_cfg_st, list) == list_top(s->vconfig, struct vhost_cfg_st, list))?0:1

#include <c-strcase.h>

/* always returns a vhost */
inline static vhost_cfg_st *find_vhost(struct list_head *vconfig, const char *name)
{
	vhost_cfg_st *vhost = NULL;
	if (name == NULL)
		return default_vhost(vconfig);
	
	list_for_each(vconfig, vhost, list) {
		if (vhost->name != NULL && c_strcasecmp(vhost->name, name) == 0)
			return vhost;
	}

	return default_vhost(vconfig);
}

#endif
