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
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <route-add.h>
#include <main.h>
#include <str.h>
#include <common.h>

static
int call_script(main_server_st *s, proc_st *proc, const char *cmd)
{
pid_t pid;
int ret, status = 0;

	if (cmd == NULL)
		return 0;

	pid = fork();
	if (pid == 0) {
		sigprocmask(SIG_SETMASK, &sig_default_set, NULL);

		mslog(s, proc, LOG_DEBUG, "executing route script %s", cmd);
		ret = execl("/bin/sh", "sh", "-c", cmd, NULL);
		if (ret == -1) {
			mslog(s, proc, LOG_ERR, "Could not execute route script %s", cmd);
			exit(1);
		}

		exit(77);
	} else if (pid == -1) {
		mslog(s, proc, LOG_ERR, "Could not fork()");
		return ERR_EXEC;
	}

	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		mslog(s, proc, LOG_ERR, "Could not waitpid()");
		return ERR_EXEC;
	}

	if (!WIFEXITED(status)) {
		mslog(s, proc, LOG_INFO, "cmd: %s: exited abnormally", cmd);
		return ERR_EXEC;
	}

	if (WEXITSTATUS(status)) {
		mslog(s, proc, LOG_INFO, "cmd: %s: exited with error %d", cmd, WEXITSTATUS(ret));
		return ERR_EXEC;
	}

	return 0;
}

static
int replace_cmd(struct main_server_st* s, proc_st *proc, 
		char **cmd, const char* pattern, 
		const char* route, const char* dev)
{
	str_st str;
	int ret;
	str_rep_tab tab[6];

	STR_TAB_SET(0, "%{R}", route);
	STR_TAB_SET(1, "%R", route);
	STR_TAB_SET(2, "%{D}", dev);
	STR_TAB_SET(3, "%D", dev);
	STR_TAB_SET_FUNC(4, "%{RI}", ipv4_route_to_cidr, route);
	STR_TAB_TERM(5);

	str_init(&str, proc);

	ret = str_append_str(&str, pattern);
	if (ret < 0)
		return ERR_MEM;

	ret = str_replace_str(&str, tab);
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

	ret = call_script(s, proc, cmd);
	if (ret < 0) {
		int e = errno;
		mslog(s, NULL, LOG_INFO, "failed to spawn cmd: %s: %s", cmd, strerror(e));
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
	return route_adddel(s, proc, GETCONFIG(s)->route_add_cmd, route, dev);
}

static
int route_del(struct main_server_st* s, proc_st *proc, const char* route, const char* dev)
{
	return route_adddel(s, proc, GETCONFIG(s)->route_del_cmd, route, dev);
}

/* Executes the commands required to apply all the configured routes 
 * for this client locally.
 */
int apply_iroutes(struct main_server_st* s, struct proc_st *proc)
{
unsigned i, j;
int ret;

	if (proc->config->n_iroutes == 0)
		return 0;

	for (i=0;i<proc->config->n_iroutes;i++) {
		ret = route_add(s, proc, proc->config->iroutes[i], proc->tun_lease.name);
		if (ret < 0)
			goto fail;
	}
	proc->applied_iroutes = 1;

	return 0;
fail:
	for (j=0;j<i;j++)
		route_del(s, proc, proc->config->iroutes[j], proc->tun_lease.name);

	return -1;
}

/* Executes the commands required to removed all the configured routes 
 * for this client.
 */
void remove_iroutes(struct main_server_st* s, struct proc_st *proc)
{
unsigned i;

	if (proc->config == NULL || proc->config->n_iroutes == 0 || proc->applied_iroutes == 0)
		return;

	for (i=0;i<proc->config->n_iroutes;i++) {
		route_del(s, proc, proc->config->iroutes[i], proc->tun_lease.name);
	}
	proc->applied_iroutes = 0;

	return;
}

