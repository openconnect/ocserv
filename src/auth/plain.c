/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#ifndef _XOPEN_SOURCE
# define _XOPEN_SOURCE
#endif
#include <unistd.h>
#include <vpn.h>
#include <c-ctype.h>
#include "plain.h"
#include "cfg.h"
#include "auth/common.h"
#include <ccan/htable/htable.h>
#include <ccan/hash/hash.h>

#define MAX_CPASS_SIZE 128

struct plain_ctx_st {
	char username[MAX_USERNAME_SIZE];
	char cpass[MAX_CPASS_SIZE];	/* crypt() passwd */

	char *groupnames[MAX_GROUPS];
	unsigned groupnames_size;

	const char *pass_msg;
	unsigned retries;
};

static char *password_file = NULL;

static void plain_global_init(void *pool, void *additional)
{
	struct plain_cfg_st *config = additional;

	if (config == NULL) {
		fprintf(stderr, "plain: no configuration passed!\n");
		exit(1);
	}

	password_file = talloc_strdup(pool, config->passwd);
	if (password_file == NULL) {
		fprintf(stderr, "plain: memory error\n");
		exit(1);
	}

	return;
}

/* Breaks a list of "xxx", "yyy", to a character array, of
 * MAX_COMMA_SEP_ELEMENTS size; Note that the given string is modified.
  */
static void
break_group_list(void *pool, char *text,
		 char *broken_text[MAX_GROUPS], unsigned *elements)
{
	char *p = talloc_strdup(pool, text);
	char *p2;
	unsigned len;

	*elements = 0;

	if (p == NULL)
		return;

	do {
		broken_text[*elements] = p;
		(*elements)++;

		p = strchr(p, ',');
		if (p) {
			*p = 0;
			len = p - broken_text[*elements-1];

			/* remove any trailing space */
			p2 = p-1;
			while (c_isspace(*p2)) {
				*p2 = 0;
				p2--;
			}

			p++;	/* move to next entry and skip white
				 * space.
				 */
			while (c_isspace(*p))
				p++;

			if (len == 1) {
				/* skip the group */
				(*elements)--;
			}
		} else {
			p2 = strrchr(broken_text[(*elements)-1], ' ');
			if (p2 != NULL) {
				while (c_isspace(*p2)) {
					*p2 = 0;
					p2--;
				}
			}
		}
	}
	while (p != NULL && *elements < MAX_GROUPS);
}

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int read_auth_pass(struct plain_ctx_st *pctx)
{
	FILE *fp;
	char line[512];
	ssize_t ll;
	char *p, *sp;
	int ret;

	fp = fopen(password_file, "r");
	if (fp == NULL) {
		syslog(LOG_AUTH,
		       "error in plain authentication; cannot open: %s",
		       password_file);
		return -1;
	}

	line[sizeof(line)-1] = 0;
	while ((p=fgets(line, sizeof(line)-1, fp)) != NULL) {
		ll = strlen(p);

		if (ll <= 4)
			continue;

		if (line[ll - 1] == '\n') {
			ll--;
			line[ll] = 0;
		}
		if (line[ll - 1] == '\r') {
			ll--;
			line[ll] = 0;
		}

		p = strtok_r(line, ":", &sp);

		if (p != NULL && strcmp(pctx->username, p) == 0) {
			p = strtok_r(NULL, ":", &sp);
			if (p != NULL) {
				break_group_list(pctx, p, pctx->groupnames, &pctx->groupnames_size);

				p = strtok_r(NULL, ":", &sp);
				if (p != NULL) {
					strlcpy(pctx->cpass, p, sizeof(pctx->cpass));
					ret = 0;
					goto exit;
				}
			}
		}
	}

	/* always succeed */
	ret = 0;
 exit:
	safe_memset(line, 0, sizeof(line));
	fclose(fp);
	return ret;
}

static int plain_auth_init(void **ctx, void *pool, const char *username, const char *ip)
{
	struct plain_ctx_st *pctx;
	int ret;

	if (username == NULL || username[0] == 0) {
		syslog(LOG_AUTH,
		       "plain-auth: no username present");
		return ERR_AUTH_FAIL;
	}

	pctx = talloc_zero(pool, struct plain_ctx_st);
	if (pctx == NULL)
		return ERR_AUTH_FAIL;

	strlcpy(pctx->username, username, sizeof(pctx->username));
	pctx->pass_msg = pass_msg_first;

	ret = read_auth_pass(pctx);
	if (ret < 0) {
		talloc_free(pctx);
		return ERR_AUTH_FAIL;
	}

	*ctx = pctx;

	return ERR_AUTH_CONTINUE;
}

static int plain_auth_group(void *ctx, const char *suggested, char *groupname, int groupname_size)
{
	struct plain_ctx_st *pctx = ctx;
	unsigned i, found = 0;

	groupname[0] = 0;

	if (suggested != NULL) {
		for (i=0;i<pctx->groupnames_size;i++) {
			if (strcmp(suggested, pctx->groupnames[i]) == 0) {
				strlcpy(groupname, pctx->groupnames[i], groupname_size);
				found = 1;
				break;
			}
		}

		if (found == 0) {
			syslog(LOG_AUTH,
			       "user '%s' requested group '%s' but is not a member",
			       pctx->username, suggested);
			return -1;
		}
	}

	if (pctx->groupnames_size > 0 && groupname[0] == 0) {
		strlcpy(groupname, pctx->groupnames[0], groupname_size);
	}
	return 0;
}

static int plain_auth_user(void *ctx, char *username, int username_size)
{
	/* do not update username */
	return -1;
}

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int plain_auth_pass(void *ctx, const char *pass, unsigned pass_len)
{
	struct plain_ctx_st *pctx = ctx;

	if (pctx->cpass[0] != 0
	    && strcmp(crypt(pass, pctx->cpass), pctx->cpass) == 0)
		return 0;
	else {
		if (pctx->retries++ < MAX_PASSWORD_TRIES-1) {
			pctx->pass_msg = pass_msg_failed;
			return ERR_AUTH_CONTINUE;
		} else {
			syslog(LOG_AUTH,
			       "plain-auth: error authenticating user '%s'",
			       pctx->username);
			return ERR_AUTH_FAIL;
		}
	}
}

static int plain_auth_msg(void *ctx, void *pool, char **msg)
{
	struct plain_ctx_st *pctx = ctx;

	*msg = talloc_strdup(pool, pctx->pass_msg);
	return 0;
}

static void plain_auth_deinit(void *ctx)
{
	talloc_free(ctx);
}

static size_t rehash(const void *_e, void *unused)
{
	const char *e = _e;
	return hash_any(e, strlen(e), 0);
}

static bool str_cmp(const void* _c1, void* _c2)
{
	const char *c1 = _c1, *c2 = _c2;

	if (strcmp(c1, c2) == 0)
		return 1;
	return 0;
}

static void plain_group_list(void *pool, void *additional, char ***groupname, unsigned *groupname_size)
{
	FILE *fp;
	char line[512];
	ssize_t ll;
	char *p, *sp;
	unsigned i;
	size_t hval;
	struct htable_iter iter;
	char *tgroup[MAX_GROUPS];
	unsigned tgroup_size;
	struct htable hash;
	struct plain_cfg_st *config = additional;

	htable_init(&hash, rehash, NULL);

	pool = talloc_init("plain");
	fp = fopen(config->passwd, "r");
	if (fp == NULL) {
		syslog(LOG_AUTH,
		       "error in plain authentication; cannot open: %s",
		       (char*)config->passwd);
		return;
	}

	line[sizeof(line)-1] = 0;
	while ((p=fgets(line, sizeof(line)-1, fp)) != NULL) {
		ll = strlen(p);

		if (ll <= 4)
			continue;

		if (line[ll - 1] == '\n') {
			ll--;
			line[ll] = 0;
		}
		if (line[ll - 1] == '\r') {
			ll--;
			line[ll] = 0;
		}

		p = strtok_r(line, ":", &sp);

		if (p != NULL) {
			p = strtok_r(NULL, ":", &sp);
			if (p != NULL) {
				break_group_list(pool, p, tgroup, &tgroup_size);

				for (i=0;i<tgroup_size;i++) {
					hval = rehash(tgroup[i], NULL);

					if (htable_get(&hash, hval, str_cmp, tgroup[i]) == NULL) {
						if (strlen(tgroup[i]) > 1)
							htable_add(&hash, hval, tgroup[i]);
					}
				}
			}
		}
	}

	*groupname_size = 0;
	*groupname = talloc_size(pool, sizeof(char*)*MAX_GROUPS);
	if (*groupname == NULL) {
		goto exit;
	}

	p = htable_first(&hash, &iter);
	while (p != NULL && (*groupname_size) < MAX_GROUPS) {
		(*groupname)[(*groupname_size)] = talloc_strdup(*groupname, p);
		p = htable_next(&hash, &iter);
		(*groupname_size)++;
	}

	/* always succeed */
 exit:
 	htable_clear(&hash);
	safe_memset(line, 0, sizeof(line));
	fclose(fp);
	return;
}

const struct auth_mod_st plain_auth_funcs = {
	.type = AUTH_TYPE_PLAIN | AUTH_TYPE_USERNAME_PASS,
	.allows_retries = 1,
	.global_init = plain_global_init,
	.auth_init = plain_auth_init,
	.auth_deinit = plain_auth_deinit,
	.auth_msg = plain_auth_msg,
	.auth_pass = plain_auth_pass,
	.auth_user = plain_auth_user,
	.auth_group = plain_auth_group,
	.group_list = plain_group_list
};
