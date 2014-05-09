/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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
#ifndef SCRIPT_LIST_H
# define SCRIPT_LIST_H

#include <main.h>

inline static
void add_to_script_list(main_server_st* s, pid_t pid, unsigned up, struct proc_st* proc)
{
struct script_wait_st *stmp;

	stmp = talloc(s, struct script_wait_st);
	if (stmp == NULL)
		return;
	
	stmp->proc = proc;
	stmp->pid = pid;
	stmp->up = up;
	
	list_add(&s->script_list.head, &(stmp->list));
}

inline static void remove_from_script_list(main_server_st* s, struct proc_st* proc)
{
struct script_wait_st *stmp = NULL, *spos;

	list_for_each_safe(&s->script_list.head, stmp, spos, list) {
		if (stmp->proc == proc) {
			list_del(&stmp->list);
			talloc_free(stmp);
			break;
		}
	}
}

#endif
