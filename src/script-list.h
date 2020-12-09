/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or
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
#ifndef SCRIPT_LIST_H
# define SCRIPT_LIST_H

#include <main.h>
#include <sys/types.h>
#include <signal.h>
#include <ev.h>

void script_child_watcher_cb(struct ev_loop *loop, ev_child *w, int revents);

inline static
void add_to_script_list(main_server_st* s, pid_t pid, struct proc_st* proc)
{
struct script_wait_st *stmp;

	stmp = talloc(s, struct script_wait_st);
	if (stmp == NULL)
		return;
	
	stmp->proc = proc;
	stmp->pid = pid;

	ev_child_init(&stmp->ev_child, script_child_watcher_cb, pid, 0);
	ev_child_start(main_loop, &stmp->ev_child);

	list_add(&s->script_list.head, &(stmp->list));
}

/* Removes the tracked connect script, and kills it. It returns the pid
 * of the removed script or -1.
 */
inline static pid_t remove_from_script_list(main_server_st* s, struct proc_st* proc)
{
	struct script_wait_st *stmp = NULL, *spos;
	pid_t ret = -1;

	list_for_each_safe(&s->script_list.head, stmp, spos, list) {
		if (stmp->proc == proc) {
			list_del(&stmp->list);
			ev_child_stop(main_loop, &stmp->ev_child);
			if (stmp->pid > 0) {
				kill(stmp->pid, SIGTERM);
				ret = stmp->pid;
			}
			talloc_free(stmp);
			break;
		}
	}

	return ret;
}

#endif
