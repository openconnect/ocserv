#ifndef ROUTE_ADD_H
# define ROUTE_ADD_H

#include <vpn.h>
#include <main.h>

int route_del(struct main_server_st* s, const char* route, const char* dev);
int route_add(struct main_server_st* s, const char* route, const char* dev);

#endif
