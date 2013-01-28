#ifndef TUN_H
# define TUN_H

#include <vpn.h>


int open_tun(const struct cfg_st *config, const struct tun_st* tun, struct tun_id_st *id);

#endif
