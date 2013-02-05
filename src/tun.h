#ifndef TUN_H
# define TUN_H

#include <vpn.h>
#include <list.h>

struct lease_st {
	struct list_head list;

	char name[IFNAMSIZ];
	unsigned int tun_nr;
	unsigned int in_use;

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
	struct lease_st lease_list;
};

inline static void tun_st_init(struct tun_st* ts)
{
	memset(ts, 0, sizeof(*ts));
	INIT_LIST_HEAD(&ts->lease_list.list);
}

inline static void tun_st_deinit(struct tun_st* ts)
{
	struct list_head *cq;
	struct list_head *pos;
	struct lease_st *ltmp;

	list_for_each_safe(pos, cq, &ts->lease_list.list) {
		ltmp = list_entry(pos, struct lease_st, list);
		list_del(&ltmp->list);
	}
}

int open_tun(const struct cfg_st *config, struct tun_st* tun, struct lease_st **lease);

#endif
