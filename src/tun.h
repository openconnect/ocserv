#ifndef TUN_H
# define TUN_H

#include <vpn.h>
#include <string.h>
#include <ccan/list/list.h>

struct lease_st {
	struct list_node list;

	char name[IFNAMSIZ];
	char username[MAX_USERNAME_SIZE]; /* owner */
	unsigned int tun_nr;
	unsigned int in_use;
	time_t available_at; /* when it will be available */

        struct sockaddr_storage rip4;
        socklen_t rip4_len;

        struct sockaddr_storage lip4;
        socklen_t lip4_len;

        struct sockaddr_storage rip6;
        socklen_t rip6_len;

        struct sockaddr_storage lip6;
        socklen_t lip6_len;
        
        /* this is used temporarily. */
	int fd;
};

struct tun_st {
	struct list_head head;
	unsigned total;
};

inline static void tun_st_init(struct tun_st* ts)
{
	memset(ts, 0, sizeof(*ts));
	list_head_init(&ts->head);
}

inline static void tun_st_deinit(struct tun_st* ts)
{
	struct lease_st *ltmp, *pos;

	list_for_each_safe(&ts->head, ltmp, pos, list) {
		list_del(&ltmp->list);
		ts->total--;
	}
}

#endif
