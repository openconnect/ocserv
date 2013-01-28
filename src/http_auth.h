#ifndef AUTH_H
#define AUTH_H

int get_auth_handler(server_st *server);
int post_old_auth_handler(server_st *server);
int post_new_auth_handler(server_st *server);

#endif
