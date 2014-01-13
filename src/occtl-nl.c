/*
 * Copyright (C) 2014 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <occtl.h>

#if defined(HAVE_LIBNL) && defined(__linux__)

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <inttypes.h>

static struct nl_sock *sock = NULL;
static struct nl_cache *cache = NULL;
static struct rtnl_link *rlink = NULL;
static int nl_failed = 0;

static int open_netlink(const char* iface)
{
int err;
int if_idx;

	if (sock != NULL)
		return 0;
	
	if (nl_failed != 0) /* don't bother re-opening */
		return -1;

	sock = nl_socket_alloc();
	if (sock == NULL) {
		fprintf(stderr, "nl: cannot open netlink\n");
		goto error;
	}

	if ((err = nl_connect(sock, NETLINK_ROUTE)) < 0) {
		fprintf(stderr, "nl: error in nl_connect");
		goto error;
	}

	if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) < 0) {
		fprintf(stderr, "nl: failed to alloc cache");
		goto error;
	}

	if (!(if_idx = rtnl_link_name2i(cache, iface))) {
		fprintf(stderr, "nl: cannot find %s\n", iface);
		goto error;
	}

	rlink = rtnl_link_get (cache, if_idx);
	if (rlink == NULL) {
		fprintf(stderr, "nl: cannot get rlink\n");
		goto error;
	}

	return 0;
error:
	if (sock != NULL) {
		nl_socket_free(sock);
		sock = NULL;
	}
	if (cache != NULL)
		nl_cache_free(cache);
	nl_failed = 1;
	
	return -1;
}

static void
bytes2human(unsigned long bytes, char* output, unsigned output_size, const char* suffix)
{
double data;

	if (suffix == NULL)
		suffix = "";

	if (bytes > 1000 && bytes < 1000 * 1000) {
		data = ((double) bytes) / 1000;
		snprintf(output, output_size, "%.1f KB%s", data, suffix);
		return;
	} else if (bytes >= 1000 * 1000 && bytes < 1000 * 1000 * 1000) {
		data = ((double) bytes) / (1000 * 1000);
		snprintf(output, output_size, "%.1f MB%s", data, suffix);
		return;
	} else if (bytes >= 1000 * 1000 * 1000) {
		data = ((double) bytes) / (1000 * 1000 * 1000);
		snprintf(output, output_size, "%.1f GB%s", data, suffix);
		return;
	} else {
		snprintf(output, output_size, "%lu bytes%s", bytes, suffix);
		return;
	}
}

static void
value2speed(unsigned long bytes, time_t time, char* output, unsigned output_size)
{
unsigned long speed;

	speed = bytes / time;
	bytes2human(speed, output, output_size, "/sec");
}

void print_iface_stats(const char *iface, time_t since, FILE * out)
{
	uint64_t tx, rx;
	char buf1[32], buf2[32];
	time_t diff = time(0) - since;

	if (open_netlink(iface) < 0)
		return;

	rx = rtnl_link_get_stat(rlink, RTNL_LINK_RX_BYTES);
	tx = rtnl_link_get_stat(rlink, RTNL_LINK_TX_BYTES);

	bytes2human(rx, buf1, sizeof(buf1), NULL);
	bytes2human(tx, buf2, sizeof(buf2), NULL);
	fprintf(out, "\tRX: %"PRIu64" (%s) TX: %"PRIu64" (%s)\n", rx, buf1, tx, buf2);
	
	value2speed(rx, diff, buf1, sizeof(buf1));
	value2speed(tx, diff, buf2, sizeof(buf2));
	fprintf(out, "\tAverage bandwidth RX: %s  TX: %s\n", buf1, buf2);

	return;
}

#else
void print_iface_stats(const char *iface, FILE * out)
{
	return;
}
#endif
