#ifndef TUN_H
# define TUN_H

#include <vpn.h>
#include <string.h>
#include <ccan/list/list.h>

struct tun_lease_st {

	char name[IFNAMSIZ];

        /* this is used temporarily. */
	int fd;
};

#endif
