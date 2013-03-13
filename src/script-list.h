#ifndef SCRIPT_LIST_H
# define SCRIPT_LIST_H

#include <main.h>

inline static
void add_to_script_list(main_server_st* s, pid_t pid, unsigned up, struct proc_st* proc)
{
struct script_wait_st *stmp;

	stmp = malloc(sizeof(*stmp));
	if (stmp == NULL)
		return;
	
	stmp->proc = proc;
	stmp->pid = pid;
	stmp->up = up;
	
	list_add(&s->script_list.head, &(stmp->list));
}

inline static void remove_from_script_list(main_server_st* s, struct proc_st* proc)
{
struct script_wait_st *stmp, *spos;

	list_for_each_safe(&s->script_list.head, stmp, spos, list) {
		if (stmp->proc == proc) {
			list_del(&stmp->list);
			free(stmp);
			break;
		}
	}
}

#endif
