/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <config.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <cloexec.h>
#include <icmp-ping.h>

#ifdef __linux__
# include <linux/if_tun.h>
#else
# include <net/if_tun.h>
#endif

#include <netdb.h>

#include <vpn.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>

/* INCREMENT taken from nettle's macros */
/* Requires that size > 0 */
#define INCREMENT(size, ctr)			\
  do {						\
    unsigned increment_i = (size) - 1;		\
    if (++(ctr)[increment_i] == 0)		\
      while (increment_i > 0			\
	     && ++(ctr)[--increment_i] == 0 )	\
	;					\
  } while (0)

static void bignum_add (uint8_t * num, unsigned size, unsigned step)
{
  register int i;
  register unsigned tmp, y;

  for (i = size-1; i >= 0; i--)
    {
      tmp = num[i];
      
      num[i] += step;
      if (num[i] < tmp)
        y = 1;
      else
        y = 0;

      if (y == 0)
        break;
    }
}

static int get_avail_network_addresses(main_server_st* s, const struct lease_st *last4,
					const struct lease_st *last6, struct lease_st* lease)
{
	struct sockaddr_storage tmp, mask, network;
	unsigned i;
	int ret, step;

	lease->rip4_len = 0;
	lease->lip4_len = 0;
	lease->rip6_len = 0;
	lease->lip6_len = 0;
	
	memset(&tmp, 0, sizeof(tmp));

	if (s->config->network.ipv4 && s->config->network.ipv4_netmask) {
		ret =
		    inet_pton(AF_INET, s->config->network.ipv4, SA_IN_P(&network));

		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "Error reading IP: %s\n", s->config->network.ipv4);
			return -1;
		}

		ret =
		    inet_pton(AF_INET, s->config->network.ipv4_netmask, SA_IN_P(&mask));
	
		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "Error reading mask: %s\n", s->config->network.ipv4_netmask);
			return -1;
		}

		/* mask the network (just in case it is wrong) */
		for (i=0;i<sizeof(struct in_addr);i++)
			SA_IN_U8_P(&network)[i] &= (SA_IN_U8_P(&mask)[i]);
        	((struct sockaddr_in*)&network)->sin_family = AF_INET;

        	if (last4 != NULL) {
        	        memcpy(&tmp, &last4->rip4, last4->rip4_len);
                } else {
        		memcpy(&tmp, &network, sizeof(tmp));
        		((struct sockaddr_in*)&tmp)->sin_family = AF_INET;
                }

		lease->lip4_len = sizeof(struct sockaddr_in);
		memcpy(&lease->lip4, &tmp, sizeof(struct sockaddr_in));
		
		step = 1;
		do {
        		bignum_add(SA_IN_U8_P(&lease->lip4), sizeof(struct in_addr), step);
        		if (SA_IN_U8_P(&lease->lip4)[3] == 255) /* broadcast */
	        		bignum_add(SA_IN_U8_P(&lease->lip4), sizeof(struct in_addr), step);

        		lease->rip4_len = sizeof(struct sockaddr_in);
        		memcpy(&lease->rip4, &lease->lip4, sizeof(struct sockaddr_in));
        		bignum_add(SA_IN_U8_P(&lease->rip4), sizeof(struct in_addr), step);

        		/* mask the last IP with the netmask */
        		memcpy(&tmp, &lease->rip4, lease->rip4_len);
        		for (i=0;i<sizeof(struct in_addr);i++)
        			SA_IN_U8_P(&tmp)[i] &= (SA_IN_U8_P(&mask)[i]);
		
        		/* the result should match the network */
        		if (memcmp(SA_IN_U8_P(&network), SA_IN_U8_P(&tmp), sizeof(struct in_addr)) != 0) {
        			mslog(s, NULL, LOG_ERR, "Reached limit of maximum (v4) IPs.\n");
        			return -1;
        		}
                } while((step=icmp_ping4(s, (void*)&lease->lip4, (void*)&lease->rip4)) != 0);
	}

	if (s->config->network.ipv6 && s->config->network.ipv6_netmask) {
		ret =
		    inet_pton(AF_INET6, s->config->network.ipv6, SA_IN6_P(&network));

		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "Error reading IP: %s\n", s->config->network.ipv6);
			return -1;
		}

		ret =
		    inet_pton(AF_INET6, s->config->network.ipv6_netmask, SA_IN6_P(&mask));
	
		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "Error reading mask: %s\n", s->config->network.ipv6_netmask);
			return -1;
		}
	
		/* mask the network */
		for (i=0;i<sizeof(struct in6_addr);i++)
			SA_IN6_U8_P(&network)[i] &= (SA_IN6_U8_P(&mask)[i]);
		((struct sockaddr_in6*)&network)->sin6_family = AF_INET6;

        	if (last6 != NULL) {
        	        memcpy(&tmp, &last6->rip6, last6->rip6_len);
                } else {
        		memcpy(&tmp, &network, sizeof(tmp));
	        	((struct sockaddr_in6*)&tmp)->sin6_family = AF_INET6;
                }

		lease->lip6_len = sizeof(struct sockaddr_in6);
		memcpy(&lease->lip6, &tmp, sizeof(struct sockaddr_in6));

		step = 1;
		do {
        		bignum_add(SA_IN6_U8_P(&lease->lip6), sizeof(struct in6_addr), step);

	        	lease->rip6_len = last6->rip6_len;
        		memcpy(&lease->rip6, &lease->lip6, lease->rip6_len);
	        	bignum_add(SA_IN6_U8_P(&lease->rip6), sizeof(struct in6_addr), step);

        		/* mask the last IP with the netmask */
        		memcpy(&tmp, &lease->rip6, lease->rip6_len);
        		for (i=0;i<sizeof(struct in6_addr);i++)
	        		SA_IN6_U8_P(&tmp)[i] &= (SA_IN6_U8_P(&mask)[i]);

        		/* the result should match the network */
	        	if (memcmp(SA_IN6_U8_P(&network), SA_IN6_U8_P(&tmp), sizeof(struct in6_addr)) != 0) {
		        	mslog(s, NULL, LOG_ERR, "Reached limit of maximum (v6) IPs.\n");
        			return -1;
	        	}
                } while((step=icmp_ping6(s, (void*)&lease->lip6, (void*)&lease->rip6)) != 0);
	}

	if (lease->lip6_len == 0 && lease->lip4_len == 0) {
		mslog(s, NULL, LOG_ERR, "No IPv4 or IPv6 addresses are configured. Cannot obtain lease.\n");
		return -1;
	}

	lease->tun_nr = 0;
	if (last4)
		lease->tun_nr = MAX(lease->tun_nr, last4->tun_nr+1);
	if (last6)
		lease->tun_nr = MAX(lease->tun_nr, last6->tun_nr+1);

	return 0;
}

static int set_network_info( main_server_st* s, const struct lease_st *lease)
{
	struct ifreq ifr;
	int fd, ret;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;

	if (lease->lip4_len > 0 && lease->rip4_len > 0) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", lease->name);

		memcpy(&ifr.ifr_addr, &lease->lip4, lease->lip4_len);

		ret = ioctl(fd, SIOCSIFADDR, &ifr);
		if (ret != 0) {
			mslog(s, NULL, LOG_ERR, "%s: Error setting IPv4.\n", lease->name);
		}

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", lease->name);
		memcpy(&ifr.ifr_dstaddr, &lease->rip4, lease->rip4_len);

		ret = ioctl(fd, SIOCSIFDSTADDR, &ifr);
		if (ret != 0) {
			mslog(s, NULL, LOG_ERR, "%s: Error setting DST IPv4.\n", lease->name);
		}
	}

	if (lease->lip6_len > 0 && lease->rip6_len > 0) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET6;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", lease->name);

		memcpy(&ifr.ifr_addr, &lease->lip6, lease->lip6_len);

		ret = ioctl(fd, SIOCSIFADDR, &ifr);
		if (ret != 0) {
			mslog(s, NULL, LOG_ERR, "%s: Error setting IPv6.\n", lease->name);
		}

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET6;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", lease->name);
		memcpy(&ifr.ifr_dstaddr, &lease->rip6, lease->rip6_len);

		ret = ioctl(fd, SIOCSIFDSTADDR, &ifr);
		if (ret != 0) {
			mslog(s, NULL, LOG_ERR, "%s: Error setting DST IPv6.\n", lease->name);
		}
	}
	
	if (lease->lip6_len == 0 && lease->lip4_len == 0) {
		mslog(s, NULL, LOG_ERR, "%s: Could not set any IP.\n", lease->name);
		ret = -1;
	} else
		ret = 0;
		
	/* bring interface up */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	ifr.ifr_flags |= IFF_UP;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", lease->name);

	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (ret != 0) {
		mslog(s, NULL, LOG_ERR, "%s: Could not bring up interface.\n", lease->name);
	}

	close(fd);
	return ret;
}


int open_tun(main_server_st* s, struct proc_st* proc)
{
	int tunfd, ret, e;
	struct ifreq ifr;
	unsigned int t;
	struct lease_st *lease = NULL;
	struct lease_st *last4, *tmp;
	struct lease_st *last6;
	unsigned current = s->tun->total;
	time_t now = time(0);
	
	last4 = last6 = NULL;
		
	/* try to re-use an address */
        list_for_each(&s->tun->head, tmp, list) {
		/* if the device isn't in use by the server and the IPs
		 *  are free. */
		if (tmp->in_use == 0 && (tmp->available_at < now || (proc->username[0] != 0 && strcmp(proc->username, tmp->username) == 0))) {
                        if ((tmp->lip6_len != 0 && icmp_ping6(s, (void*)&tmp->lip6, (void*)&tmp->rip6) == 0) ||
                          (tmp->lip4_len != 0 && icmp_ping4(s, (void*)&tmp->lip4, (void*)&tmp->rip4) == 0)) {
        			lease = tmp;
	        		mslog(s, NULL, LOG_INFO, "reusing tun device %s\n", lease->name);
		        	break;
                        }
		}
	}
		
	/* nothing to re-use */
	if (lease == NULL) {
		lease = calloc(1, sizeof(*lease));
		if (lease == NULL)
		        return -1;

                list_for_each_rev(&s->tun->head, tmp, list) {
			if (last4 == NULL && tmp->rip4_len > 0)
				last4 = tmp;

			if (last6 == NULL && tmp->rip6_len > 0)
				last6 = tmp;
			
			if (last4 && last6)
				break;
		}

		ret = get_avail_network_addresses(s, last4, last6, lease);
		if (ret < 0) {
			free(lease);
			return -1;
		}

		/* Add into the list */
		list_add_tail( &s->tun->head, &lease->list);
		snprintf(lease->name, sizeof(lease->name), "%s%u", s->config->network.name, current);
		snprintf(lease->username, sizeof(lease->username), "%s", proc->username);
		s->tun->total++;
	}

	/* No need to free the lease after this point.
	 */
	 
	/* Obtain a free tun device */
#ifdef __linux__
	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd < 0) {
		int e = errno;
		mslog(s, NULL, LOG_ERR, "Can't open /dev/net/tun: %s\n",
		       strerror(e));
		return -1;
	}
	
	set_cloexec_flag (tunfd, 1);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        memcpy(ifr.ifr_name, lease->name, IFNAMSIZ);

	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: TUNSETIFF: %s\n", lease->name, strerror(e));
		goto fail;
	}
	memcpy(lease->name, ifr.ifr_name, IFNAMSIZ);
	mslog(s, NULL, LOG_INFO, "assigning tun device %s\n", lease->name);

	if (ioctl(tunfd, TUNSETPERSIST, (void *)0) < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: TUNSETPERSIST: %s\n", lease->name, strerror(e));
		goto fail;
	}

	if (s->config->uid != -1) {
		t = s->config->uid;
		ret = ioctl(tunfd, TUNSETOWNER, t);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_INFO, "%s: TUNSETOWNER: %s\n",
			       lease->name, strerror(e));
			goto fail;
		}
	}

# ifdef TUNSETGROUP
	if (s->config->gid != -1) {
		t = s->config->uid;
		ret = ioctl(tunfd, TUNSETGROUP, t);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "%s: TUNSETGROUP: %s\n",
			       lease->name, strerror(e));
			goto fail;
		}
	}
# endif
#else /* freebsd */
	tunfd = open("/dev/tun", O_RDWR);
	if (tunfd < 0) {
		int e = errno;
		mslog(s, NULL, LOG_ERR, "Can't open /dev/tun: %s\n",
		       strerror(e));
		return -1;
	}
	
	/* find device name */
	{
		struct stat st;
		
		ret = fstat(tunfd, &st);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "%s: stat: %s\n", strerror(e));
			goto fail;
		}
		
		snprintf(lease->name, sizeof(lease->name), "%s", devname(st.st_rdev, S_IFCHR));
	}
	
	set_cloexec_flag (tunfd, 1);
#endif

	/* set IP/mask */
	ret = set_network_info(s, lease);
	if (ret < 0) {
		goto fail;
	}
	
	lease->in_use = 1;
	lease->available_at = now + s->config->cookie_validity;
	lease->fd = tunfd;
	proc->lease = lease;

	return 0;
fail:
	close(tunfd);
	return -1;
}
