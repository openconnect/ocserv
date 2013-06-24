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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <vpn.h>
#include <plain.h>

struct plain_ctx_st {
	char username[MAX_USERNAME_SIZE];
	char groupname[MAX_GROUPNAME_SIZE];
	const char* passwd;
};

static int plain_auth_init(void** ctx, const char* username, const char* ip, void* additional)
{
struct plain_ctx_st* pctx;

	pctx = malloc(sizeof(*pctx));
	if (pctx == NULL)
		return ERR_AUTH_FAIL;
	
	snprintf(pctx->username, sizeof(pctx->username), "%s", username);
	pctx->passwd = additional;
	
	*ctx = pctx;
	
	return 0;
}

static int plain_auth_group(void* ctx, char *groupname, int groupname_size)
{
struct plain_ctx_st* pctx = ctx;

	snprintf(groupname, groupname_size, "%s", pctx->groupname);
	
	return 0;
}


/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
static int plain_auth_pass(void* ctx, const char* pass)
{
struct plain_ctx_st* pctx = ctx;
unsigned groupname_size;
FILE* fp;
char * line = NULL;
size_t len;
ssize_t ll;
char* p;
int ret;

	fp = fopen(pctx->passwd, "r");
	if (fp == NULL) {
		syslog(LOG_AUTH, "error in plain authentication; cannot open: %s", pctx->passwd);
		return -1;
	}
	
	while((ll=getline(&line, &len, fp)) > 0) {
		if (ll <= 2)
			continue;

		if (line[ll-1] == '\n')
			line[ll-1] = 0;
		if (line[ll-2] == '\n')
			line[ll-2] = 0;

		p = strtok(line, ":");

		if (p != NULL && strcmp(pctx->username, p) == 0) {
			p = strtok(NULL, ":");
			if (p != NULL) {
				groupname_size = sizeof(pctx->groupname);
				groupname_size = snprintf(pctx->groupname, groupname_size, "%s", p);
				if (groupname_size == 1) /* values like '*' or 'x' indicate empty group */
					pctx->groupname[0] = 0;

				p = strtok(NULL, ":");
				if (p != NULL && strcmp(crypt(pass, p), p) == 0) {
					ret = 0;
					goto exit;
				}
			}
		}
	}
	
	ret = -1;
	syslog(LOG_AUTH, "error in plain authentication; error in user '%s'", pctx->username);
exit:
	fclose(fp);
	free(line);
	return ret;
}

static int plain_auth_msg(void* ctx, char* msg, size_t msg_size)
{
	snprintf(msg, msg_size, "%s", "Please enter your password");
	return 0;
}

static void plain_auth_deinit(void* ctx)
{
	free(ctx);
}

const struct auth_mod_st plain_auth_funcs = {
  .type = AUTH_TYPE_PLAIN | AUTH_TYPE_USERNAME_PASS,
  .auth_init = plain_auth_init,
  .auth_deinit = plain_auth_deinit,
  .auth_msg = plain_auth_msg,
  .auth_pass = plain_auth_pass,
  .auth_group = plain_auth_group
};
