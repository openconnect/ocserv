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

/* Authentication with the worker thread works as follows:
 *    main                 worker
 *             <----      auth_init (username)
 *    auth_msg ---->
 *             <----      auth_req (password)
 *
 *    [the last two messages may be repeated multiple times,
 *     e.g. when in two-factor authentication]
 *
 * The receipt of auth_init message results to auth_init()
 * being called, auth_msg to auth_msg() and auth_req to auth_pass().
 *
 * auth_group() is called sometime after auth_init() to retrieve
 * the group of the user.  
 */
#endif
