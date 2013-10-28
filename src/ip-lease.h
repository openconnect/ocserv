#ifndef IP_LEASE_H
# define IP_LEASE_H

#include <vpn.h>
#include <string.h>
#include <sys/socket.h>
#include <ccan/hash/hash.h>
#include <main.h>

struct ip_lease_st {
        struct sockaddr_storage rip;
        socklen_t rip_len;

        struct sockaddr_storage lip;
        socklen_t lip_len;
};

void ip_lease_deinit(struct ip_lease_db_st* db);
void ip_lease_init(struct ip_lease_db_st* db);

int get_ip_leases(struct main_server_st* s, struct proc_st* proc);
void remove_ip_leases(struct main_server_st* s, struct proc_st* proc);

#endif
