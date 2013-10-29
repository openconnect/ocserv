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
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <route-add.h>
#include <main.h>
#include <common.h>

static
int replace_cmd(struct main_server_st* s, char cmd[_POSIX_PATH_MAX], const char* pattern, 
	const char* route, const char* dev)
{
int len = strlen(pattern);
unsigned i, j;
unsigned rlen = strlen(route);
unsigned dlen = strlen(dev);

	if (len + rlen + dlen >= sizeof(cmd))
		return ERR_MEM;
	
	for (i=j=0;i<len;i++) {
		if (pattern[i] == '%') {
			if (pattern[i+1] == 'R') {
				memcpy(&cmd[j], route, rlen);
				j += rlen;
				i++;
			} else if (pattern[i+1] == 'D') {
				memcpy(&cmd[j], dev, dlen);
				j += dlen;
				i++;
			} else {
				mslog(s, NULL, LOG_WARNING, "unknown token %%%c in cmd: %s", pattern[i+1], pattern);
				return ERR_PARSING;
			}
		} else
			cmd[j++] = pattern[i];
	}
	
	return 0;
}

static
int route_adddel(struct main_server_st* s, const char* pattern, const char* route, const char* dev)
{
int ret;
char cmd[_POSIX_PATH_MAX];

	ret = replace_cmd(s, cmd, pattern, route, dev);
	if (ret < 0)
		return ret;
	
	ret = system(cmd);
	if (ret == -1) {
		int e = errno;
		mslog(s, NULL, LOG_WARNING, "failed to spawn cmd: %s: %s", cmd, strerror(e));
		return ERR_EXEC;
	}
	
	if (!WIFEXITED(ret)) {
		mslog(s, NULL, LOG_WARNING, "cmd: %s: exited abnormally", cmd);
		return ERR_EXEC;
	}

	if (WEXITSTATUS(ret)) {
		mslog(s, NULL, LOG_WARNING, "cmd: %s: exited with error %d", cmd, WEXITSTATUS(ret));
		return ERR_EXEC;
	}
	
	return 0;
}

int route_add(struct main_server_st* s, const char* route, const char* dev)
{
	return route_adddel(s, s->config->route_add_cmd, route, dev);
}

int route_del(struct main_server_st* s, const char* route, const char* dev)
{
	return route_adddel(s, s->config->route_del_cmd, route, dev);
}

