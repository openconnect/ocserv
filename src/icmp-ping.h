#ifndef ICMP_PING_H
# define ICMP_PING_H

#include <main.h>

/* returns the number of positive replies received or
 * 0 if no host with this IP exists. */
int icmp_ping4(main_server_st* s, struct sockaddr_in* addr1, struct sockaddr_in* addr2);
int icmp_ping6(main_server_st* s, struct sockaddr_in6* addr1, struct sockaddr_in6* addr2);

#endif
