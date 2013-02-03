#ifndef WORKER_H
#define WORKER_H

#include <config.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <vpn.h>
#include <cookies.h>
#include <tlslib.h>

int auth_cookie(worker_st *ws, void* cookie, size_t cookie_size);

int get_auth_handler(worker_st *server);
int post_old_auth_handler(worker_st *server);
int post_new_auth_handler(worker_st *server);

void set_resume_db_funcs(gnutls_session_t);

#endif
