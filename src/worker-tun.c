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
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#include <vpn.h>
#include <worker.h>
#include <tlslib.h>

/* if local is non zero it returns the local, otherwise the remote */
static
int get_ip(struct worker_st* ws, int fd, int family, unsigned int local,
           struct vpn_st* vinfo, char** buffer, size_t* buffer_size)
{
void* ptr;
void* p;
struct ifreq ifr;
unsigned int flags;
int ret, e;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = family;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);

	if (local != 0)
		flags = SIOCGIFADDR;
	else
		flags = SIOCGIFDSTADDR;

	ret = ioctl(fd, flags, &ifr);
	if (ret != 0) {
		e = errno;
		oclog(ws, LOG_DEBUG, "ioctl error: %s", strerror(e));
		goto fail;
	}

	if (family == AF_INET) {
		ptr = SA_IN_P(&ifr.ifr_addr);
	} else if (family == AF_INET6) {
		ptr = SA_IN6_P(&ifr.ifr_addr);
	} else {
		oclog(ws, LOG_DEBUG, "Unknown family!");
		return -1;
	}

	p = (char*)inet_ntop(family, ptr, *buffer, *buffer_size);
	if (p == NULL) {
		e = errno;
		oclog(ws, LOG_DEBUG, "inet_ntop error: %s", strerror(e));
		goto fail;
	}

	ret = strlen(p) + 1;
	*buffer += ret;
	*buffer_size -= ret;

	if (family == AF_INET) {
		if (strcmp(p, "0.0.0.0")==0)
			p = NULL;
		if (local != 0)
			vinfo->ipv4_local = p;
		else
			vinfo->ipv4 = p;
	} else {
		if (strcmp(p, "::")==0)
			p = NULL;
		if (local != 0)
			vinfo->ipv6_local = p;
		else
			vinfo->ipv6 = p;
	}

	return 0;
fail:
	return -1;
}

/* Returns information based on an VPN network stored in worker_st but
 * using real time information for many fields. Nothing is allocated,
 * the provided buffer is used.
 * 
 * Returns 0 on success.
 */
int get_rt_vpn_info(worker_st * ws,
                    struct vpn_st* vinfo, char* buffer, size_t buffer_size)
{
int fd, ret;
struct ifreq ifr;

	memset(vinfo, 0, sizeof(*vinfo));
	vinfo->name = ws->tun_name;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
        
	/* get the remote IPs */
        ret = get_ip(ws, fd, AF_INET6, 0, vinfo, &buffer, &buffer_size);
        if (ret < 0)
                oclog(ws, LOG_DEBUG, "cannot obtain IPv6 remote IP for %s", vinfo->name);

        ret = get_ip(ws, fd, AF_INET, 0, vinfo, &buffer, &buffer_size);
        if (ret < 0)
                oclog(ws, LOG_DEBUG, "cannot obtain IPv4 remote IP for %s", vinfo->name);

        if (vinfo->ipv4 == NULL && vinfo->ipv6 == NULL) {
                ret = -1;
                goto fail;
        }

	/* get the local IPs */
        ret = get_ip(ws, fd, AF_INET6, 1, vinfo, &buffer, &buffer_size);
        if (ret < 0)
                oclog(ws, LOG_DEBUG, "cannot obtain IPv6 local IP for %s", vinfo->name);

        ret = get_ip(ws, fd, AF_INET, 1, vinfo, &buffer, &buffer_size);
        if (ret < 0)
                oclog(ws, LOG_DEBUG, "cannot obtain IPv4 local IP for %s", vinfo->name);

#define LOCAL "local"
	if (ws->ipv4_dns != NULL)
		vinfo->ipv4_dns = ws->ipv4_dns;
	else if (ws->config->network.ipv4_dns && strcmp(ws->config->network.ipv4_dns, LOCAL) == 0)
		vinfo->ipv4_dns = vinfo->ipv4_local;
	else
		vinfo->ipv4_dns = ws->config->network.ipv4_dns;

	if (ws->ipv6_dns != NULL)
		vinfo->ipv6_dns = ws->ipv6_dns;
	else if (ws->config->network.ipv6_dns && strcmp(ws->config->network.ipv6_dns, LOCAL) == 0)
		vinfo->ipv6_dns = vinfo->ipv6_local;
	else
		vinfo->ipv6_dns = ws->config->network.ipv6_dns;

	if (ws->ipv4_nbns != NULL)
		vinfo->ipv4_nbns = ws->ipv4_nbns;
	else if (ws->config->network.ipv4_nbns && strcmp(ws->config->network.ipv4_nbns, LOCAL) == 0)
		vinfo->ipv4_nbns = vinfo->ipv4_local;
	else
		vinfo->ipv4_nbns = ws->config->network.ipv4_nbns;

	if (ws->ipv6_nbns != NULL)
		vinfo->ipv6_nbns = ws->ipv6_nbns;
	else if (ws->config->network.ipv6_nbns && strcmp(ws->config->network.ipv6_nbns, LOCAL) == 0)
		vinfo->ipv6_nbns = vinfo->ipv6_local;
	else
		vinfo->ipv6_nbns = ws->config->network.ipv6_nbns;

	vinfo->routes_size = ws->config->network.routes_size;
	if (ws->config->network.routes_size > 0)
		vinfo->routes = ws->config->network.routes;

	if (ws->ipv4_netmask != NULL)
		vinfo->ipv4_netmask = ws->ipv4_netmask;
	else
		vinfo->ipv4_netmask = ws->config->network.ipv4_netmask;

	if (ws->ipv6_netmask != NULL)
		vinfo->ipv6_netmask = ws->ipv6_netmask;
	else
		vinfo->ipv6_netmask = ws->config->network.ipv6_netmask;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);
	ret = ioctl(fd, SIOCGIFMTU, (caddr_t)&ifr);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "Cannot obtain MTU for %s. Assuming 1500", vinfo->name);
		vinfo->mtu = 1500;
	} else {
		vinfo->mtu = ifr.ifr_mtu;
	}

	ret = 0;
fail:
	close(fd);
	return ret;
}


