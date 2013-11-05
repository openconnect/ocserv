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

	if (len + rlen + dlen >= _POSIX_PATH_MAX) {
		mslog(s, NULL, LOG_WARNING, "not enough memory to hold expanded pattern: %s", pattern);
		return ERR_MEM;
	}
	
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
				mslog(s, NULL, LOG_WARNING, "unknown token '%%%c' in cmd: %s", pattern[i+1], pattern);
				return ERR_PARSING;
			}
		} else
			cmd[j++] = pattern[i];
	}
	cmd[j] = 0;
	
	return 0;
}

static
int route_adddel(struct main_server_st* s, const char* pattern, const char* route, const char* dev)
{
int ret;
char cmd[_POSIX_PATH_MAX];

	if (pattern == 0) {
		mslog(s, NULL, LOG_WARNING, "route-add-cmd or route-del-cmd are not set.");
		return 0;
	}

	ret = replace_cmd(s, cmd, pattern, route, dev);
	if (ret < 0)
		return ret;
	
	mslog(s, NULL, LOG_DEBUG, "spawning cmd: %s", cmd);
	ret = system(cmd);
	if (ret == -1) {
		int e = errno;
		mslog(s, NULL, LOG_INFO, "failed to spawn cmd: %s: %s", cmd, strerror(e));
		return ERR_EXEC;
	}
	
	if (!WIFEXITED(ret)) {
		mslog(s, NULL, LOG_INFO, "cmd: %s: exited abnormally", cmd);
		return ERR_EXEC;
	}

	if (WEXITSTATUS(ret)) {
		mslog(s, NULL, LOG_INFO, "cmd: %s: exited with error %d", cmd, WEXITSTATUS(ret));
		return ERR_EXEC;
	}
	
	return 0;
}

static
int route_add(struct main_server_st* s, const char* route, const char* dev)
{
	return route_adddel(s, s->config->route_add_cmd, route, dev);
}

static
int route_del(struct main_server_st* s, const char* route, const char* dev)
{
	return route_adddel(s, s->config->route_del_cmd, route, dev);
}

void apply_iroutes(struct main_server_st* s, struct proc_st *proc)
{
unsigned i, j;
int ret;

	if (proc->config.iroutes_size == 0)
		return;

	for (i=0;i<proc->config.iroutes_size;i++) {
		ret = route_add(s, proc->config.iroutes[i], proc->tun_lease.name);
		if (ret < 0)
			goto fail;
	}
	proc->applied_iroutes = 1;
	
	return;
fail:
	for (j=0;j<i;j++)
		route_del(s, proc->config.iroutes[j], proc->tun_lease.name);
	
	return;
}

void remove_iroutes(struct main_server_st* s, struct proc_st *proc)
{
unsigned i;

	if (proc->config.iroutes_size == 0 || proc->applied_iroutes == 0)
		return;

	for (i=0;i<proc->config.iroutes_size;i++) {
		route_del(s, proc->config.iroutes[i], proc->tun_lease.name);
	}
	proc->applied_iroutes = 0;
	
	return;
}

