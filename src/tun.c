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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <vpn.h>
#include <tun.h>
#include <list.h>

static int set_network_info(const struct vpn_st *vinfo)
{
	struct ifreq ifr;
	int fd, ret;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;

	/* set netmask */
	if (vinfo->ipv4_netmask && vinfo->ipv4) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);

		ret =
		    inet_pton(AF_INET, vinfo->ipv4_netmask,
			      &((struct sockaddr_in *) &ifr.ifr_addr)->
			      sin_addr);
		if (ret != 1) {
			syslog(LOG_ERR, "%s: Error reading mask: %s\n",
			       vinfo->name, vinfo->ipv4_netmask);
			goto fail;
		}

		ret = ioctl(fd, SIOCSIFNETMASK, &ifr);
		if (ret != 0) {
			syslog(LOG_ERR, "%s: Error setting mask: %s\n",
			       vinfo->name, vinfo->ipv4_netmask);
		}

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);

		ret =
		    inet_pton(AF_INET, vinfo->ipv4,
			      &((struct sockaddr_in *) &ifr.ifr_addr)->
			      sin_addr);
		if (ret != 1) {
			syslog(LOG_ERR, "%s: Error reading IP: %s\n",
			       vinfo->name, vinfo->ipv4_netmask);
			goto fail;

		}

		ret = ioctl(fd, SIOCSIFADDR, &ifr);
		if (ret != 0) {
			syslog(LOG_ERR, "%s: Error setting IP: %s\n",
			       vinfo->name, vinfo->ipv4);
		}
	}

	if (vinfo->ipv6_netmask && vinfo->ipv6) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET6;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);

		ret =
		    inet_pton(AF_INET6, vinfo->ipv6_netmask,
			      &((struct sockaddr_in6 *) &ifr.ifr_addr)->
			      sin6_addr);
		if (ret != 1) {
			syslog(LOG_ERR, "%s: Error reading mask: %s\n",
			       vinfo->name, vinfo->ipv6_netmask);
			goto fail;

		}

		ret = ioctl(fd, SIOCSIFNETMASK, &ifr);
		if (ret != 0) {
			syslog(LOG_ERR, "%s: Error setting mask: %s\n",
			       vinfo->name, vinfo->ipv6_netmask);
		}

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET6;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);

		ret =
		    inet_pton(AF_INET6, vinfo->ipv6,
			      &((struct sockaddr_in6 *) &ifr.ifr_addr)->
			      sin6_addr);
		if (ret != 1) {
			syslog(LOG_ERR, "%s: Error reading IP: %s\n",
			       vinfo->name, vinfo->ipv6_netmask);
			goto fail;

		}

		ret = ioctl(fd, SIOCSIFADDR, &ifr);
		if (ret != 0) {
			syslog(LOG_ERR, "%s: Error setting IP: %s\n",
			       vinfo->name, vinfo->ipv6);
		}
	}


	ret = 0;
      fail:
	close(fd);
	return ret;
}

int open_tun(struct cfg_st *config, struct tun_st* tun)
{
	int tunfd, ret, e;
	struct ifreq ifr;
	unsigned int t;

	/* XXX obtain random IPs + tun nr */

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd < 0) {
		int e = errno;
		syslog(LOG_ERR, "Can't open /dev/net/tun: %s\n",
		       strerror(e));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),
		 config->network.name, 0);
	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0) {
		e = errno;
		syslog(LOG_ERR, "TUNSETIFF: %s\n", strerror(e));
		goto fail;
	}

	if (config->uid != -1) {
		t = config->uid;
		ret = ioctl(tunfd, TUNSETOWNER, t);
		if (ret < 0) {
			e = errno;
			syslog(LOG_INFO, "TUNSETOWNER: %s\n",
			       strerror(e));
			goto fail;
		}
	}

	if (config->gid != -1) {
		t = config->uid;
		ret = ioctl(tunfd, TUNSETGROUP, t);
		if (ret < 0) {
			e = errno;
			syslog(LOG_ERR, "TUNSETGROUP: %s\n",
			       strerror(e));
			goto fail;
		}
	}

	/* set IP/mask */
	ret = set_network_info(&config->network);
	if (ret < 0) {
		goto fail;
	}

	return tunfd;
fail:
	close(tunfd);
	return -1;
}
