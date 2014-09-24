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
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/wait.h>

#include <route-add.h>
#include <main.h>
#include <str.h>
#include <common.h>

static
int replace_cmd(struct main_server_st* s, proc_st *proc, 
		char **cmd, const char* pattern, 
		const char* route, const char* dev)
{
	str_st str;
	int ret;

	str_init(&str, proc);

	ret = str_append_str(&str, pattern);
	if (ret < 0)
		return ERR_MEM;

	ret = str_replace_str(&str, "%{R}", route);
	if (ret < 0)
		goto fail;

	ret = str_replace_str(&str, "%{D}", dev);
	if (ret < 0)
		goto fail;

	/* The old compatibility strings */
	ret = str_replace_str(&str, "%R", route);
	if (ret < 0)
		goto fail;

	ret = str_replace_str(&str, "%D", dev);
	if (ret < 0)
		goto fail;

	*cmd = (char*)str.data;

	return 0;
 fail:
	str_clear(&str);
	return ERR_MEM;
}

static
int route_adddel(struct main_server_st* s, proc_st *proc,
		 const char* pattern, const char* route, const char* dev)
{
int ret;
char *cmd = NULL;

	if (pattern == 0) {
		mslog(s, NULL, LOG_WARNING, "route-add-cmd or route-del-cmd are not set.");
		return 0;
	}

	ret = replace_cmd(s, proc, &cmd, pattern, route, dev);
	if (ret < 0)
		return ret;
	
	mslog(s, NULL, LOG_DEBUG, "spawning cmd: %s", cmd);
	ret = system(cmd);
	if (ret == -1) {
		int e = errno;
		mslog(s, NULL, LOG_INFO, "failed to spawn cmd: %s: %s", cmd, strerror(e));
		ret = ERR_EXEC;
		goto fail;
	}
	
	if (!WIFEXITED(ret)) {
		mslog(s, NULL, LOG_INFO, "cmd: %s: exited abnormally", cmd);
		ret = ERR_EXEC;
		goto fail;
	}

	if (WEXITSTATUS(ret)) {
		mslog(s, NULL, LOG_INFO, "cmd: %s: exited with error %d", cmd, WEXITSTATUS(ret));
		ret = ERR_EXEC;
		goto fail;
	}
	
	ret = 0;
 fail:
 	talloc_free(cmd);
	return ret;
}

static
int route_add(struct main_server_st* s, proc_st *proc, const char* route, const char* dev)
{
	return route_adddel(s, proc, s->config->route_add_cmd, route, dev);
}

static
int route_del(struct main_server_st* s, proc_st *proc, const char* route, const char* dev)
{
	return route_adddel(s, proc, s->config->route_del_cmd, route, dev);
}

/* Executes the commands required to apply all the configured routes 
 * for this client locally.
 */
void apply_iroutes(struct main_server_st* s, struct proc_st *proc)
{
unsigned i, j;
int ret;

	if (proc->config.iroutes_size == 0)
		return;

	for (i=0;i<proc->config.iroutes_size;i++) {
		ret = route_add(s, proc, proc->config.iroutes[i], proc->tun_lease.name);
		if (ret < 0)
			goto fail;
	}
	proc->applied_iroutes = 1;
	
	return;
fail:
	for (j=0;j<i;j++)
		route_del(s, proc, proc->config.iroutes[j], proc->tun_lease.name);
	
	return;
}

/* Executes the commands required to removed all the configured routes 
 * for this client.
 */
void remove_iroutes(struct main_server_st* s, struct proc_st *proc)
{
unsigned i;

	if (proc->config.iroutes_size == 0 || proc->applied_iroutes == 0)
		return;

	for (i=0;i<proc->config.iroutes_size;i++) {
		route_del(s, proc, proc->config.iroutes[i], proc->tun_lease.name);
	}
	proc->applied_iroutes = 0;
	
	return;
}

