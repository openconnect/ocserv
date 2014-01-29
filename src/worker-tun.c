/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <gnutls/crypto.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#include <vpn.h>
#include <worker.h>
#include <tlslib.h>

#include <ifaddrs.h>

static
int get_ips(struct worker_st *ws, struct vpn_st *vinfo, char **buffer,
	    size_t * buffer_size)
{
	struct ifaddrs *ifaddr, *ifa;
	int ret, e;
	void *p;

	/* getifaddrs looks like a waste, especially when the number of devices/clients
	 * is large. We should instead get that info from the main process
	 */

	ret = getifaddrs(&ifaddr);
	if (ret != 0) {
		e = errno;
		oclog(ws, LOG_ERR, "getifaddrs error: %s", strerror(e));
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (strcmp(vinfo->name, ifa->ifa_name) == 0) {
			p = (char *)inet_ntop(ifa->ifa_addr->sa_family,
					      ifa->ifa_addr, *buffer,
					      *buffer_size);
			if (p == NULL) {
				e = errno;
				oclog(ws, LOG_ERR, "inet_ntop error: %s",
				      strerror(e));
				continue;
			}

			ret = strlen(p) + 1;
			*buffer += ret;
			*buffer_size -= ret;

			if (ifa->ifa_addr->sa_family == AF_INET) {
				if (strcmp(p, "0.0.0.0") == 0)
					p = NULL;
				vinfo->ipv4 = p;
			} else {
				if (strcmp(p, "::") == 0)
					p = NULL;
				vinfo->ipv6 = p;
			}

			/* DST */
			if (ifa->ifa_dstaddr == NULL)
				continue;

			p = (char *)inet_ntop(ifa->ifa_dstaddr->sa_family,
					      ifa->ifa_dstaddr, *buffer,
					      *buffer_size);
			if (p == NULL) {
				e = errno;
				oclog(ws, LOG_ERR, "inet_ntop error: %s",
				      strerror(e));
				continue;
			}

			ret = strlen(p) + 1;
			*buffer += ret;
			*buffer_size -= ret;

			if (ifa->ifa_dstaddr->sa_family == AF_INET) {
				if (strcmp(p, "0.0.0.0") == 0)
					p = NULL;
				vinfo->ipv4_local = p;
			} else {
				if (strcmp(p, "::") == 0)
					p = NULL;
				vinfo->ipv6_local = p;
			}
		}
	}

	freeifaddrs(ifaddr);

	return 0;
}

/* Returns information based on an VPN network stored in worker_st but
 * using real time information for many fields. Nothing is allocated,
 * the provided buffer is used.
 * 
 * Returns 0 on success.
 */
int get_rt_vpn_info(worker_st * ws,
		    struct vpn_st *vinfo, char *buffer, size_t buffer_size)
{
	int ret, fd;
	struct ifreq ifr;

	memset(vinfo, 0, sizeof(*vinfo));
	vinfo->name = ws->tun_name;

	/* get the remote IPs */
	ret = get_ips(ws, vinfo, &buffer, &buffer_size);
	if (ret < 0) {
		oclog(ws, LOG_DEBUG, "cannot obtain IPs for %s", vinfo->name);
	}

	if (vinfo->ipv4 == NULL && vinfo->ipv6 == NULL) {
		return -1;
	}
#define LOCAL "local"
	if (ws->config->network.ipv4_dns
	    && strcmp(ws->config->network.ipv4_dns, LOCAL) == 0)
		vinfo->ipv4_dns = vinfo->ipv4_local;
	else
		vinfo->ipv4_dns = ws->config->network.ipv4_dns;

	if (ws->config->network.ipv6_dns
	    && strcmp(ws->config->network.ipv6_dns, LOCAL) == 0)
		vinfo->ipv6_dns = vinfo->ipv6_local;
	else
		vinfo->ipv6_dns = ws->config->network.ipv6_dns;

	if (ws->config->network.ipv4_nbns
	    && strcmp(ws->config->network.ipv4_nbns, LOCAL) == 0)
		vinfo->ipv4_nbns = vinfo->ipv4_local;
	else
		vinfo->ipv4_nbns = ws->config->network.ipv4_nbns;

	if (ws->config->network.ipv6_nbns
	    && strcmp(ws->config->network.ipv6_nbns, LOCAL) == 0)
		vinfo->ipv6_nbns = vinfo->ipv6_local;
	else
		vinfo->ipv6_nbns = ws->config->network.ipv6_nbns;

	vinfo->routes_size = ws->config->network.routes_size;
	if (ws->config->network.routes_size > 0)
		vinfo->routes = ws->config->network.routes;

	vinfo->ipv4_netmask = ws->config->network.ipv4_netmask;
	vinfo->ipv6_netmask = ws->config->network.ipv6_netmask;

	if (ws->config->network.mtu != 0) {
		vinfo->mtu = ws->config->network.mtu;
	} else {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1)
			return -1;

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);
		ret = ioctl(fd, SIOCGIFMTU, (caddr_t) & ifr);
		if (ret < 0) {
			oclog(ws, LOG_ERR, "cannot obtain MTU for %s. Assuming 1500",
			      vinfo->name);
			vinfo->mtu = 1500;
		} else {
			vinfo->mtu = ifr.ifr_mtu;
		}
		close(fd);
	}

	return 0;
}
