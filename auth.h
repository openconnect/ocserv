#ifndef AUTH_H
#define AUTH_H

int get_auth_handler(server_st *server);
int post_auth_handler(server_st *server);
int get_login_handler(server_st *server);
int post_login_handler(server_st *server);
int connect_handler(server_st *server);

#endif
