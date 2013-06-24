#ifndef AUTH_H
# define AUTH_H

#include <main.h>

struct auth_mod_st {
	unsigned int type;
	int (*auth_init)(void** ctx, const char* username, const char* ip, void* additional);
	int (*auth_msg)(void* ctx, char* msg, size_t msg_size);
	int (*auth_pass)(void* ctx, const char* pass);
	int (*auth_group)(void* ctx, char *groupname, int groupname_size);
	void (*auth_deinit)(void* ctx);
};

void main_auth_init(main_server_st *s);
void proc_auth_deinit(main_server_st* s, struct proc_st* proc);

#endif
