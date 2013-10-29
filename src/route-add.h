#ifndef ROUTE_ADD_H
# define ROUTE_ADD_H

#include <vpn.h>
#include <main.h>

void apply_iroutes(struct main_server_st* s, struct proc_st *proc);
void remove_iroutes(struct main_server_st* s, struct proc_st *proc);

#endif
