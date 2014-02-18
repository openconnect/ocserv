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
 * GnuTLS is distributed in the hope that it will be useful, but
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
#include <unistd.h>
#include <vpn.h>
#include <plain.h>

#define MAX_CPASS_SIZE 128
#define MAX_TRIES 3

const char* pass_msg_first = "Please enter your password.";
const char* pass_msg_failed = "Login failed.\nPlease enter your password.";

struct plain_ctx_st {
	char username[MAX_USERNAME_SIZE];
	char cpass[MAX_CPASS_SIZE];	/* crypt() passwd */
	char groupname[MAX_GROUPNAME_SIZE];
	const char *passwd;	/* password file */
	const char *pass_msg;
	unsigned retries;
};

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int read_auth_pass(struct plain_ctx_st *pctx)
{
	unsigned groupname_size;
	FILE *fp;
	char *line = NULL;
	size_t len;
	ssize_t ll;
	char *p, *sp;
	int ret;

	fp = fopen(pctx->passwd, "r");
	if (fp == NULL) {
		syslog(LOG_AUTH,
		       "error in plain authentication; cannot open: %s",
		       pctx->passwd);
		return -1;
	}

	while ((ll = getline(&line, &len, fp)) > 0) {
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
				groupname_size = sizeof(pctx->groupname);
				groupname_size =
				    snprintf(pctx->groupname, groupname_size,
					     "%s", p);
				if (groupname_size == 1)	/* values like '*' or 'x' indicate empty group */
					pctx->groupname[0] = 0;

				p = strtok_r(NULL, ":", &sp);
				if (p != NULL) {
					snprintf(pctx->cpass,
						 sizeof(pctx->cpass), "%s", p);
					ret = 0;
					goto exit;
				}
			}
		}
	}

	/* always succeed */
	ret = 0;
 exit:
	fclose(fp);
	free(line);
	return ret;
}

static int plain_auth_init(void **ctx, const char *username, const char *ip,
			   void *additional)
{
	struct plain_ctx_st *pctx;
	int ret;

	pctx = malloc(sizeof(*pctx));
	if (pctx == NULL)
		return ERR_AUTH_FAIL;

	snprintf(pctx->username, sizeof(pctx->username), "%s", username);
	pctx->groupname[0] = 0;
	pctx->cpass[0] = 0;
	pctx->passwd = additional;
	pctx->retries = 0;
	pctx->pass_msg = pass_msg_first;

	ret = read_auth_pass(pctx);
	if (ret < 0) {
		free(pctx);
		return ERR_AUTH_FAIL;
	}

	*ctx = pctx;

	return 0;
}

static int plain_auth_group(void *ctx, char *groupname, int groupname_size)
{
	struct plain_ctx_st *pctx = ctx;

	snprintf(groupname, groupname_size, "%s", pctx->groupname);

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
		if (pctx->retries++ < MAX_TRIES) {
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

static int plain_auth_msg(void *ctx, char *msg, size_t msg_size)
{
	struct plain_ctx_st *pctx = ctx;

	snprintf(msg, msg_size, "%s", pctx->pass_msg);
	return 0;
}

static void plain_auth_deinit(void *ctx)
{
	free(ctx);
}

const struct auth_mod_st plain_auth_funcs = {
	.type = AUTH_TYPE_PLAIN | AUTH_TYPE_USERNAME_PASS,
	.auth_init = plain_auth_init,
	.auth_deinit = plain_auth_deinit,
	.auth_msg = plain_auth_msg,
	.auth_pass = plain_auth_pass,
	.auth_user = plain_auth_user,
	.auth_group = plain_auth_group
};
