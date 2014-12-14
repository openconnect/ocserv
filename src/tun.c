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
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#include <ip-lease.h>

#if defined(HAVE_LINUX_IF_TUN_H)
# include <linux/if_tun.h>
#elif defined(HAVE_NET_IF_TUN_H)
# include <net/if_tun.h>
#endif

#include <netdb.h>
#include <vpn.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>

#ifdef __FreeBSD__
# include <net/if_var.h>
# include <netinet/in_var.h>
#endif

#ifdef __linux__

#include <linux/types.h>

struct in6_ifreq {
	struct in6_addr ifr6_addr;
	__u32 ifr6_prefixlen;
	unsigned int ifr6_ifindex;
};

static
int set_ipv6_addr(main_server_st * s, struct proc_st *proc)
{
	int fd, e, ret;
	struct in6_ifreq ifr6;
	struct ifreq ifr;
	unsigned idx;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: Error socket(AF_INET6): %s\n",
		      proc->tun_lease.name, strerror(e));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, proc->tun_lease.name, IFNAMSIZ);

	ret = ioctl(fd, SIOGIFINDEX, &ifr);
	if (ret != 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: Error in SIOGIFINDEX: %s\n",
		      proc->tun_lease.name, strerror(e));
		ret = -1;
		goto cleanup;
	}

	idx = ifr.ifr_ifindex;

	memset(&ifr6, 0, sizeof(ifr6));
	memcpy(&ifr6.ifr6_addr, SA_IN6_P(&proc->ipv6->lip),
	       SA_IN_SIZE(proc->ipv6->lip_len));
	ifr6.ifr6_ifindex = idx;
	ifr6.ifr6_prefixlen = 127;

	ret = ioctl(fd, SIOCSIFADDR, &ifr6);
	if (ret != 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: Error setting IPv6: %s\n",
		      proc->tun_lease.name, strerror(e));
		ret = -1;
		goto cleanup;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET6;
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	strlcpy(ifr.ifr_name, proc->tun_lease.name, IFNAMSIZ);

	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (ret != 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "%s: Could not bring up IPv6 interface: %s\n",
		      proc->tun_lease.name, strerror(e));
		ret = -1;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	close(fd);

	return ret;
}
#elif defined(SIOCAIFADDR_IN6)

#include <netinet6/nd6.h>

static
int set_ipv6_addr(main_server_st * s, struct proc_st *proc)
{
	int fd, e, ret;
	struct in6_aliasreq ifr6;
	struct ifreq ifr;

	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: Error socket(AF_INET6): %s\n",
		      proc->tun_lease.name, strerror(e));
		return -1;
	}

	memset(&ifr6, 0, sizeof(ifr6));
	strlcpy(ifr6.ifra_name, proc->tun_lease.name, IFNAMSIZ);

	memcpy(&ifr6.ifra_addr.sin6_addr, SA_IN6_P(&proc->ipv6->lip),
	       SA_IN_SIZE(proc->ipv6->lip_len));
	ifr6.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	ifr6.ifra_addr.sin6_family = AF_INET6;

	memcpy(&ifr6.ifra_dstaddr.sin6_addr, SA_IN6_P(&proc->ipv6->rip),
	       SA_IN_SIZE(proc->ipv6->rip_len));
	ifr6.ifra_dstaddr.sin6_len = sizeof(struct sockaddr_in6);
	ifr6.ifra_dstaddr.sin6_family = AF_INET6;

	memset(&ifr6.ifra_prefixmask.sin6_addr, 0xff, sizeof(struct in6_addr));
	ifr6.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifr6.ifra_prefixmask.sin6_family = AF_INET6;

	ifr6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	ifr6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	ret = ioctl(fd, SIOCAIFADDR_IN6, &ifr6);
	if (ret != 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: Error setting IPv6: %s\n",
		      proc->tun_lease.name, strerror(e));
		ret = -1;
		goto cleanup;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET6;
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	strlcpy(ifr.ifr_name, oroc->tun_lease.name, IFNAMSIZ);

	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (ret != 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "%s: Could not bring up IPv6 interface: %s\n",
		      proc->tun_lease.name, strerror(e));
		ret = -1;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	close(fd);

	return ret;
}
#else
#warning "No IPv6 support on this platform"
static int set_ipv6_addr(main_server_st * s, struct proc_st *proc)
{
	return -1;
}

#endif

static int set_network_info(main_server_st * s, struct proc_st *proc)
{
	int fd = -1, ret, e;
#ifdef SIOCAIFADDR
	struct in_aliasreq ifr;
#else
	struct ifreq ifr;
#endif

	if (proc->ipv4 && proc->ipv4->lip_len > 0 && proc->ipv4->rip_len > 0) {
		memset(&ifr, 0, sizeof(ifr));

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1)
			return -1;

#ifdef SIOCAIFADDR
		strlcpy(ifr.ifra_name, proc->tun_lease.name, IFNAMSIZ);

		memcpy(&ifr.ifra_addr, &proc->ipv4->lip, proc->ipv4->lip_len);
		ifr.ifra_addr.sin_len = sizeof(struct sockaddr_in);
		ifr.ifra_addr.sin_family = AF_INET;

		memcpy(&ifr.ifra_dstaddr, &proc->ipv4->rip, proc->ipv4->rip_len);
		ifr.ifra_dstaddr.sin_len = sizeof(struct sockaddr_in);
		ifr.ifra_dstaddr.sin_family = AF_INET;

		ifr.ifra_mask.sin_len = sizeof(struct sockaddr_in);
		ifr.ifra_mask.sin_family = AF_INET;
		ifr.ifra_mask.sin_addr.s_addr = 0xffffffff;

		ret = ioctl(fd, SIOCAIFADDR, &ifr);
		if (ret != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "%s: Error setting IPv4: %s\n",
			      proc->tun_lease.name, strerror(e));
			ret = -1;
			goto cleanup;
		}
#else
		strlcpy(ifr.ifr_name, proc->tun_lease.name, IFNAMSIZ);
		memcpy(&ifr.ifr_addr, &proc->ipv4->lip, proc->ipv4->lip_len);
		ifr.ifr_addr.sa_family = AF_INET;

		ret = ioctl(fd, SIOCSIFADDR, &ifr);
		if (ret != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "%s: Error setting IPv4: %s\n",
			      proc->tun_lease.name, strerror(e));
			ret = -1;
			goto cleanup;
		}

		memset(&ifr, 0, sizeof(ifr));

		strlcpy(ifr.ifr_name, proc->tun_lease.name, IFNAMSIZ);
		memcpy(&ifr.ifr_dstaddr, &proc->ipv4->rip, proc->ipv4->rip_len);
		ifr.ifr_dstaddr.sa_family = AF_INET;

		ret = ioctl(fd, SIOCSIFDSTADDR, &ifr);
		if (ret != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR,
			      "%s: Error setting DST IPv4: %s\n",
			      proc->tun_lease.name, strerror(e));
			ret = -1;
			goto cleanup;
		}

		/* bring interface up */
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET;
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		strlcpy(ifr.ifr_name, proc->tun_lease.name, IFNAMSIZ);

		ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
		if (ret != 0) {
			mslog(s, NULL, LOG_ERR,
			      "%s: Could not bring up IPv4 interface.\n",
			      proc->tun_lease.name);
			ret = -1;
			goto cleanup;
		}
#endif

		close(fd);
		fd = -1;
	}

	if (proc->ipv6 && proc->ipv6->lip_len > 0 && proc->ipv6->rip_len > 0) {
		ret = set_ipv6_addr(s, proc);
		if (ret < 0) {
			remove_ip_lease(s, proc->ipv6);
			proc->ipv6 = NULL;
		}
	}

	if (proc->ipv6 == 0 && proc->ipv4 == 0) {
		mslog(s, NULL, LOG_ERR, "%s: Could not set any IP.\n",
		      proc->tun_lease.name);
		ret = -1;
		goto cleanup;
	}

	ret = 0;

 cleanup:
	if (fd != -1)
		close(fd);
	return ret;
}

#include <ccan/hash/hash.h>

int open_tun(main_server_st * s, struct proc_st *proc)
{
	int tunfd, ret, e;
	struct ifreq ifr;
	unsigned int t;

	ret = get_ip_leases(s, proc);
	if (ret < 0)
		return ret;
	snprintf(proc->tun_lease.name, sizeof(proc->tun_lease.name), "%s%%d",
		 s->config->network.name);

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

	set_cloexec_flag(tunfd, 1);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	memcpy(ifr.ifr_name, proc->tun_lease.name, IFNAMSIZ);

	if (ioctl(tunfd, TUNSETIFF, (void *)&ifr) < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: TUNSETIFF: %s\n",
		      proc->tun_lease.name, strerror(e));
		goto fail;
	}
	memcpy(proc->tun_lease.name, ifr.ifr_name, IFNAMSIZ);
	mslog(s, proc, LOG_INFO, "assigning tun device %s\n",
	      proc->tun_lease.name);

	/* we no longer use persistent tun */
	if (ioctl(tunfd, TUNSETPERSIST, (void *)0) < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: TUNSETPERSIST: %s\n",
		      proc->tun_lease.name, strerror(e));
		goto fail;
	}

	if (s->config->uid != -1) {
		t = s->config->uid;
		ret = ioctl(tunfd, TUNSETOWNER, t);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_INFO, "%s: TUNSETOWNER: %s\n",
			      proc->tun_lease.name, strerror(e));
			goto fail;
		}
	}
#ifdef TUNSETGROUP
	if (s->config->gid != -1) {
		t = s->config->uid;
		ret = ioctl(tunfd, TUNSETGROUP, t);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "%s: TUNSETGROUP: %s\n",
			      proc->tun_lease.name, strerror(e));
			goto fail;
		}
	}
#endif
#else				/* freebsd */
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
			mslog(s, NULL, LOG_ERR, "tun fd %d: stat: %s\n", tunfd, strerror(e));
			goto fail;
		}

		strlcpy(proc->tun_lease.name, devname(st.st_rdev, S_IFCHR), sizeof(proc->tun_lease.name));
	}

	set_cloexec_flag(tunfd, 1);
#endif

	if (proc->tun_lease.name[0] == 0) {
		mslog(s, NULL, LOG_ERR, "tun device with no name!");
		goto fail;
	}

	/* set IP/mask */
	ret = set_network_info(s, proc);
	if (ret < 0) {
		goto fail;
	}

	proc->tun_lease.fd = tunfd;

	return 0;
 fail:
	close(tunfd);
	return -1;
}

void close_tun(main_server_st * s, struct proc_st *proc)
{
	int fd = -1;

	if (proc->tun_lease.fd >= 0) {
		close(proc->tun_lease.fd);
		proc->tun_lease.fd = -1;
	}

#ifdef SIOCIFDESTROY
	int e;
	struct ifreq ifr;

	if (proc->tun_lease.name[0] != 0) {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd == -1)
			return -1;

		memset(&ifr, 0, sizeof(struct ifreq));
		strlcpy(ifr.ifr_name, proc->tun_lease.name, IFNAMSIZ);

		ret = ioctl(fd, SIOCIFDESTROY, &ifr);
		if (ret != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "%s: Error destroying interface: %s\n",
				proc->tun_lease.name, strerror(e));
		}
	}
#endif

	if (fd != -1)
		close(fd);

	return;
}
