/* vi: set sw=4 ts=4: */
/*
 * Mini ping implementation for busybox
 *
 * Copyright (C) 1999 by Randolph Chung <tausq@debian.org>
 *
 * Adapted from the ping in netkit-base 0.10:
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/* from ping6.c:
 * Copyright (C) 1999 by Randolph Chung <tausq@debian.org>
 *
 * This version of ping is adapted from the ping in netkit-base 0.10,
 * which is:
 *
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. <BSD Advertising Clause omitted per the July 22, 1999 licensing change
 *		ftp://ftp.cs.berkeley.edu/pub/4bsd/README.Impt.License.Change>
 *
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This version is an adaptation of ping.c from busybox.
 * The code was modified by Bart Visscher <magick@linux-fan.com>
 */

/* Ported to ocserv by Nikos Mavrogiannopoulos */

#include <config.h>
#include <main.h>
#include <net/if.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <gnutls/crypto.h>
#include <icmp-ping.h>

#ifndef ICMP_DEST_UNREACH
# ifdef ICMP_UNREACH
#  define ICMP_DEST_UNREACH ICMP_UNREACH
# else
#  define ICMP_DEST_UNREACH 3
# endif
#endif

/* I see RENUMBERED constants in bits/in.h - !!?
 * What a fuck is going on with libc? Is it a glibc joke? */
#ifdef IPV6_2292HOPLIMIT
#undef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT IPV6_2292HOPLIMIT
#endif

enum {
	DEFDATALEN = 56,
	MAXIPLEN = 60,
	MAXICMPLEN = 76,
	MAXPACKET = 65468,
	MAX_DUP_CHK = (8 * 128),
	MAXWAIT = 10,
	PINGINTERVAL = 1,	/* 1 second */
};

/* common routines */

static int in_cksum(unsigned short *buf, int sz)
{
	int nleft = sz;
	int sum = 0;
	unsigned short *w = buf;
	unsigned short ans = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&ans) = *(unsigned char *) w;
		sum += ans;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ans = ~sum;
	return ans;
}

inline static int retry(e)
{
	if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR)
		return 1;
	else
		return 0;
}

#define PING_TIMEOUT 3

static
ssize_t recvfrom_timeout(int sockfd, void *buf, size_t len, int flags,
			 struct sockaddr *src_addr, socklen_t * addrlen)
{
	fd_set rfds;
	struct timeval tv;
	int ret;

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = 250000;

	ret = select(sockfd + 1, &rfds, NULL, NULL, &tv);
	if (ret == -1)
		return -1;
	else if (ret > 0)
		return recvfrom(sockfd, buf, len, 0, src_addr, addrlen);
	else
		return -1;


}

int icmp_ping4(main_server_st * s, struct sockaddr_in *addr1)
{
	struct icmp *pkt;
	int pingsock, c, e;
	char packet1[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
	char buf1[64];
	time_t now;
	uint16_t id1, id2;
	unsigned gotreply = 0, unreachable = 0;

	if (s->config->ping_leases == 0)
		return 0;

	gnutls_rnd(GNUTLS_RND_NONCE, &id1, sizeof(id1));
	gnutls_rnd(GNUTLS_RND_NONCE, &id2, sizeof(id2));

	pingsock = socket(AF_INET, SOCK_RAW, 1);
	if (pingsock == -1) {
		e = errno;
		mslog(s, NULL, LOG_INFO,
		      "could not open raw socket for ping: %s", strerror(e));
		return 0;
	}

	pkt = (struct icmp *) packet1;
	memset(pkt, 0, sizeof(packet1));
	pkt->icmp_type = ICMP_ECHO;
	pkt->icmp_id = id1;
	pkt->icmp_cksum =
	    in_cksum((unsigned short *) pkt, sizeof(packet1));

	while ((c = sendto(pingsock, packet1, DEFDATALEN + ICMP_MINLEN, 0,
			   (struct sockaddr *) addr1,
			   sizeof(*addr1)) == -1) && retry(errno));
	/* listen for replies */

	now = time(0);
	while (time(0) - now < PING_TIMEOUT
	       && (unreachable + gotreply) < 2) {
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);

		c = recvfrom_timeout(pingsock, packet1, sizeof(packet1), 0,
				     (struct sockaddr *) &from, &fromlen);

		if (c < 0) {
			continue;
		} else if (c >= 76 && fromlen == sizeof(struct sockaddr_in)) {	/* icmp6_hdr */
			if (memcmp
			    (SA_IN_P(&from), SA_IN_P(addr1),
			     SA_IN_SIZE(sizeof(*addr1))) == 0) {

#ifdef HAVE_STRUCT_IPHDR_IHL
				struct iphdr *iphdr =
				    (struct iphdr *) packet1;
				pkt = (struct icmp *) (packet1 + (iphdr->ihl << 2));	/* skip ip hdr */
#else
				pkt = (struct icmp *) (packet1 + ((packet1[0] & 0x0f) << 2));	/* skip ip hdr */
#endif
				if (pkt->icmp_id == id1 || pkt->icmp_id == id2) {
					if (pkt->icmp_type == ICMP_ECHOREPLY)
						gotreply++;
					else if (pkt->icmp_type == ICMP_DEST_UNREACH)
						unreachable++;
                                }
			}
		}
	}

	close(pingsock);

	if (gotreply > 0) {
		mslog(s, NULL, LOG_INFO,
		      "pinged %s and is in use",
		      human_addr((void *) addr1,
				 sizeof(struct sockaddr_in), buf1,
				 sizeof(buf1)));
		return gotreply;
	} else {
		mslog(s, NULL, LOG_INFO,
		      "pinged %s and is not in use",
		      human_addr((void *) addr1,
				 sizeof(struct sockaddr_in), buf1,
				 sizeof(buf1)));
		return 0;
	}
}

int icmp_ping6(main_server_st * s,
	       struct sockaddr_in6 *addr1)
{
	struct icmp6_hdr *pkt;
	char buf1[64];
	int pingsock, c, e;
	int sockopt;
	char packet1[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
	uint16_t id1, id2;
	unsigned gotreply = 0, unreachable = 0;
	time_t now;

	if (s->config->ping_leases == 0)
		return 0;

	gnutls_rnd(GNUTLS_RND_NONCE, &id1, sizeof(id1));
	gnutls_rnd(GNUTLS_RND_NONCE, &id2, sizeof(id2));

	pingsock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (pingsock == -1) {
		e = errno;
		mslog(s, NULL, LOG_INFO,
		      "could not open raw socket for ping: %s", strerror(e));
		return 0;
	}

	pkt = (struct icmp6_hdr *) packet1;
	memset(pkt, 0, sizeof(packet1));
	pkt->icmp6_type = ICMP6_ECHO_REQUEST;
	pkt->icmp6_id = id1;

#if defined(SOL_RAW) && defined(IPV6_CHECKSUM)
	sockopt = offsetof(struct icmp6_hdr, icmp6_cksum);
	setsockopt(pingsock, SOL_RAW, IPV6_CHECKSUM,
		   &sockopt, sizeof(sockopt));
#endif
	while ((c =
		sendto(pingsock, packet1,
		       DEFDATALEN + sizeof(struct icmp6_hdr), 0,
		       (struct sockaddr *) addr1,
		       sizeof(*addr1)) == -1) && retry(errno));

	/* listen for replies */
	now = time(0);
	while (time(0) - now < PING_TIMEOUT
	       && (unreachable + gotreply) < 2) {
		struct sockaddr_in6 from;
		socklen_t fromlen = sizeof(from);
		c = recvfrom_timeout(pingsock, packet1,
				     sizeof(packet1), 0,
				     (struct sockaddr *)
				     &from, &fromlen);
		if (c < 0) {
			continue;
		} else if (c >= 8 && fromlen == sizeof(struct sockaddr_in6)) {	/* icmp6_hdr */
			if (memcmp
			    (SA_IN6_P(&from), SA_IN6_P(addr1),
			     SA_IN_SIZE(sizeof(*addr1))) == 0) {

				pkt = (struct icmp6_hdr *) packet1;
				if (pkt->icmp6_id == id1 || pkt->icmp6_id == id2) {
					if (pkt->icmp6_type == ICMP6_ECHO_REPLY)
						gotreply++;
					else if (pkt->icmp6_type == ICMP_DEST_UNREACH)
						unreachable++;
				}
			}
		}
	}

	close(pingsock);

	if (gotreply > 0) {
		mslog(s, NULL, LOG_INFO,
		      "pinged %s and is in use",
		      human_addr((void *) addr1,
				 sizeof(struct sockaddr_in6), buf1,
				 sizeof(buf1)));
		return gotreply;
	} else {
		mslog(s, NULL, LOG_INFO,
		      "pinged %s and is not in use",
		      human_addr((void *) addr1,
				 sizeof(struct sockaddr_in6), buf1,
				 sizeof(buf1)));
		return 0;
	}
}
