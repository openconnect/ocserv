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

static int bignum_add1 (uint8_t * num, unsigned size)
{
  register int i, y = 0;

  for (i = size-1; i >= 0; i--)
    {
      y = 0;
      if (num[i] == 0xff)
        {
          num[i] = 0;
          y = 1;
        }
      else
        num[i]++;

      if (y == 0)
        break;
    }

  return 0;
}

static int get_avail_network_addresses(const struct cfg_st *config, const struct lease_st *last4,
					const struct lease_st *last6, struct lease_st* lease)
{
	struct sockaddr_storage tmp, mask, network;
	unsigned i;
	int ret;

	lease->rip4_len = 0;
	lease->lip4_len = 0;
	lease->rip6_len = 0;
	lease->lip6_len = 0;
	
	memset(&tmp, 0, sizeof(tmp));

	if (config->network.ipv4 && config->network.ipv4_netmask) {
		ret =
		    inet_pton(AF_INET, config->network.ipv4, SA_IN_P(&network));

		if (ret != 1) {
			syslog(LOG_ERR, "Error reading IP: %s\n", config->network.ipv4);
			return -1;
		}

		ret =
		    inet_pton(AF_INET, config->network.ipv4_netmask, SA_IN_P(&mask));
	
		if (ret != 1) {
			syslog(LOG_ERR, "Error reading mask: %s\n", config->network.ipv4_netmask);
			return -1;
		}

		/* mask the network (just in case it is wrong) */
		for (i=0;i<sizeof(struct in_addr);i++)
			SA_IN_U8_P(&network)[i] &= (SA_IN_U8_P(&mask)[i]);

		memcpy(&tmp, &network, sizeof(tmp));
		((struct sockaddr_in*)&tmp)->sin_family = AF_INET;
		((struct sockaddr_in*)&network)->sin_family = AF_INET;
	}
	

	/* read the network */
	if (last4 == NULL && (config->network.ipv4 && config->network.ipv4_netmask)) {
	
		/* add one to get local IP */
		i = sizeof(struct in_addr)-1;
		SA_IN_U8_P(&tmp)[i]++;
	
		lease->lip4_len = sizeof(struct sockaddr_in);
		memcpy(&lease->lip4, &tmp, lease->lip4_len);

		/* add one to get remote IP */
		i = sizeof(struct in_addr)-1;
		SA_IN_U8_P(&tmp)[i]++;

		lease->rip4_len = sizeof(struct sockaddr_in);
		memcpy(&lease->rip4, &tmp, lease->rip4_len);
	} else if (last4 != NULL) {

		lease->lip4_len = last4->rip4_len;
		memcpy(&lease->lip4, &last4->rip4, last4->rip4_len);

		bignum_add1(SA_IN_U8_P(&lease->lip4), sizeof(struct in_addr));
		if (SA_IN_U8_P(&lease->lip4)[3] == 255) /* broadcast */
			bignum_add1(SA_IN_U8_P(&lease->lip4), sizeof(struct in_addr));

		lease->rip4_len = last4->rip4_len;
		memcpy(&lease->rip4, &lease->lip4, lease->rip4_len);
		bignum_add1(SA_IN_U8_P(&lease->rip4), sizeof(struct in_addr));

		/* mask the last IP with the netmask */
		memcpy(&tmp, &lease->rip4, lease->rip4_len);
		for (i=0;i<sizeof(struct in_addr);i++)
			SA_IN_U8_P(&tmp)[i] &= (SA_IN_U8_P(&mask)[i]);
		
		/* the result should match the network */
		if (memcmp(SA_IN_U8_P(&network), SA_IN_U8_P(&tmp), sizeof(struct in_addr)) != 0) {
			syslog(LOG_ERR, "Reached limit of maximum (v4) IPs.\n");
			return -1;
		}
	}

	if (config->network.ipv6 && config->network.ipv6_netmask) {
		ret =
		    inet_pton(AF_INET6, config->network.ipv6, SA_IN6_P(&network));

		if (ret != 1) {
			syslog(LOG_ERR, "Error reading IP: %s\n", config->network.ipv6);
			return -1;
		}

		ret =
		    inet_pton(AF_INET6, config->network.ipv6_netmask, SA_IN6_P(&mask));
	
		if (ret != 1) {
			syslog(LOG_ERR, "Error reading mask: %s\n", config->network.ipv6_netmask);
			return -1;
		}
	
		/* mask the network */
		for (i=0;i<sizeof(struct in6_addr);i++)
			SA_IN6_U8_P(&network)[i] &= (SA_IN6_U8_P(&mask)[i]);
	
		memcpy(&tmp, &network, sizeof(tmp));
		((struct sockaddr_in6*)&tmp)->sin6_family = AF_INET6;
		((struct sockaddr_in6*)&network)->sin6_family = AF_INET6;
	}

	if (last6 == NULL && (config->network.ipv6 && config->network.ipv6_netmask)) {
		/* add one to get local IP */
		i = sizeof(struct in6_addr)-1;
		SA_IN6_U8_P(&tmp)[i]++;
	
		lease->lip6_len = sizeof(struct sockaddr_in6);
		memcpy(&lease->lip6, &tmp, lease->lip6_len);

		/* add one to get remote IP */
		i = sizeof(struct in6_addr)-1;
		SA_IN6_U8_P(&tmp)[i]++;
	
		lease->rip6_len = sizeof(struct sockaddr_in6);
		memcpy(&lease->rip6, &tmp, lease->rip6_len);
	} else if (last6 != NULL) {

		lease->lip6_len = last6->rip6_len;
		memcpy(&lease->lip6, &last6->rip6, last6->rip6_len);
		bignum_add1(SA_IN6_U8_P(&lease->lip6), sizeof(struct in6_addr));

		lease->rip6_len = last6->rip6_len;
		memcpy(&lease->rip6, &lease->lip6, lease->rip6_len);
		bignum_add1(SA_IN6_U8_P(&lease->rip6), sizeof(struct in6_addr));

		/* mask the last IP with the netmask */
		memcpy(&tmp, &lease->rip6, lease->rip6_len);
		for (i=0;i<sizeof(struct in6_addr);i++)
			SA_IN6_U8_P(&tmp)[i] &= (SA_IN6_U8_P(&mask)[i]);

		/* the result should match the network */
		if (memcmp(SA_IN6_U8_P(&network), SA_IN6_U8_P(&tmp), sizeof(struct in6_addr)) != 0) {
			syslog(LOG_ERR, "Reached limit of maximum (v6) IPs.\n");
			return -1;
		}
	}

	if (lease->lip6_len == 0 && lease->lip4_len == 0) {
		syslog(LOG_ERR, "No IPv4 or IPv6 addresses are configured. Cannot obtain lease.\n");
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


int open_tun(main_server_st* s, struct lease_st** l)
{
	int tunfd, ret, e;
	struct ifreq ifr;
	unsigned int t;
	struct lease_st *lease = NULL;
	struct lease_st *last4, *tmp;
	struct lease_st *last6;
	unsigned current = s->tun->total;
	
	last4 = last6 = NULL;
		
	/* try to re-use an address */
        list_for_each(&s->tun->head, tmp, list) {
		if (tmp->in_use == 0) {
			lease = tmp;
			mslog(s, NULL, LOG_INFO, "reusing tun device %s\n", lease->name);
			break;
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

		ret = get_avail_network_addresses(s->config, last4, last6, lease);
		if (ret < 0) {
			free(lease);
			return -1;
		}

		/* Add into the list */
		list_add_tail( &s->tun->head, &lease->list);
		snprintf(lease->name, sizeof(lease->name), "%s%u", s->config->network.name, current);
		s->tun->total++;
	}

	/* No need to free the lease after this point.
	 */
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
	lease->fd = tunfd;
	*l = lease;

	return 0;
fail:
	close(tunfd);
	return -1;
}
