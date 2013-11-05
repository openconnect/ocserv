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

static int set_network_info( main_server_st* s, struct proc_st* proc)
{
	struct ifreq ifr;
	int fd, ret;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;

	if (proc->ipv4 && proc->ipv4->lip_len > 0 && proc->ipv4->rip_len > 0) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", proc->tun_lease.name);

		memcpy(&ifr.ifr_addr, &proc->ipv4->lip, proc->ipv4->lip_len);

		ret = ioctl(fd, SIOCSIFADDR, &ifr);
		if (ret != 0) {
			mslog(s, NULL, LOG_ERR, "%s: Error setting IPv4.\n", proc->tun_lease.name);
		}

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", proc->tun_lease.name);
		memcpy(&ifr.ifr_dstaddr, &proc->ipv4->rip, proc->ipv4->rip_len);

		ret = ioctl(fd, SIOCSIFDSTADDR, &ifr);
		if (ret != 0) {
			mslog(s, NULL, LOG_ERR, "%s: Error setting DST IPv4.\n", proc->tun_lease.name);
		}
	}

	if (proc->ipv6 && proc->ipv6->lip_len > 0 && proc->ipv6->rip_len > 0) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET6;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", proc->tun_lease.name);

		memcpy(&ifr.ifr_addr, &proc->ipv6->lip, proc->ipv6->lip_len);

		ret = ioctl(fd, SIOCSIFADDR, &ifr);
		if (ret != 0) {
			mslog(s, NULL, LOG_ERR, "%s: Error setting IPv6.\n", proc->tun_lease.name);
		}

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = AF_INET6;
		snprintf(ifr.ifr_name, IFNAMSIZ, "%s", proc->tun_lease.name);
		memcpy(&ifr.ifr_dstaddr, &proc->ipv6->rip, proc->ipv6->rip_len);

		ret = ioctl(fd, SIOCSIFDSTADDR, &ifr);
		if (ret != 0) {
			mslog(s, NULL, LOG_ERR, "%s: Error setting DST IPv6.\n", proc->tun_lease.name);
		}
	}
	
	if (proc->ipv6 == 0 && proc->ipv4 == 0) {
		mslog(s, NULL, LOG_ERR, "%s: Could not set any IP.\n", proc->tun_lease.name);
		ret = -1;
		goto cleanup;
	}
		
	/* bring interface up */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	ifr.ifr_flags |= IFF_UP;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", proc->tun_lease.name);

	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (ret != 0) {
		mslog(s, NULL, LOG_ERR, "%s: Could not bring up interface.\n", proc->tun_lease.name);
		ret = -1;
	}

cleanup:
	close(fd);
	return ret;
}

#include <ccan/hash/hash.h>

int open_tun(main_server_st* s, struct proc_st* proc)
{
	int tunfd, ret, e;
	struct ifreq ifr;
	unsigned int t;
	
	ret = get_ip_leases(s, proc);
	if (ret < 0)
		return ret;
	snprintf(proc->tun_lease.name, sizeof(proc->tun_lease.name), "%s%%d", s->config->network.name);

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

        memcpy(ifr.ifr_name, proc->tun_lease.name, IFNAMSIZ);

	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: TUNSETIFF: %s\n", proc->tun_lease.name, strerror(e));
		goto fail;
	}
	memcpy(proc->tun_lease.name, ifr.ifr_name, IFNAMSIZ);
	mslog(s, proc, LOG_INFO, "assigning tun device %s\n", proc->tun_lease.name);

# if 0
	/* we no longer use persistent tun */
	if (ioctl(tunfd, TUNSETPERSIST, (void *)0) < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "%s: TUNSETPERSIST: %s\n", proc->tun_lease.name, strerror(e));
		goto fail;
	}
# endif

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

# ifdef TUNSETGROUP
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
		
		snprintf(proc->tun_lease.name, sizeof(proc->tun_lease.name), "%s", devname(st.st_rdev, S_IFCHR));
	}

	set_cloexec_flag (tunfd, 1);
#endif

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
