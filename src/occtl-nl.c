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
 * ocserv is distributed in the hope that it will be useful, but
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
static int nl_failed = 0;

static int open_netlink(void)
{
int err;

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

	return 0;
error:
	if (sock != NULL) {
		nl_socket_free(sock);
		sock = NULL;
	}
	nl_failed = 1;

	return -1;
}

static void
value2speed(unsigned long bytes, time_t time, char* output, unsigned output_size)
{
unsigned long speed;

	speed = bytes / time;
	bytes2human(speed, output, output_size, "/sec");
}

void print_iface_stats(const char *iface, time_t since, FILE * out, cmd_params_st *params, unsigned have_more)
{
	uint64_t tx, rx;
	char buf1[32], buf2[32];
	time_t diff = time(0) - since;
	int ret;
	struct rtnl_link *rlink = NULL;

	if (iface == NULL || iface[0] == 0)
		return;

	if (open_netlink() < 0)
		return;

	ret = rtnl_link_get_kernel(sock, 0, iface, &rlink);
	if (ret < 0) {
		fprintf(stderr, "nl: cannot find %s\n", iface);
		return;
	}

	rx = rtnl_link_get_stat(rlink, RTNL_LINK_RX_BYTES);
	tx = rtnl_link_get_stat(rlink, RTNL_LINK_TX_BYTES);

	bytes2human(rx, buf1, sizeof(buf1), NULL);
	bytes2human(tx, buf2, sizeof(buf2), NULL);
	if (HAVE_JSON(params)) {
		fprintf(out, "    \"RX\":  \"%"PRIu64"\",\n    \"TX\":  \"%"PRIu64"\",\n", rx, tx);
		fprintf(out, "    \"_RX\":  \"%s\",\n    \"_TX\":  \"%s\",\n", buf1, buf2);
	} else
		fprintf(out, "\tRX: %"PRIu64" (%s)   TX: %"PRIu64" (%s)\n", rx, buf1, tx, buf2);

	value2speed(rx, diff, buf1, sizeof(buf1));
	value2speed(tx, diff, buf2, sizeof(buf2));
	if (HAVE_JSON(params))
		fprintf(out, "    \"Average RX\":  \"%s\",\n    \"Average TX\":  \"%s\"%s\n", buf1, buf2, have_more?",":"");
	else
		fprintf(out, "\tAverage bandwidth RX: %s  TX: %s\n", buf1, buf2);

	return;
}

#else
void print_iface_stats(const char *iface, time_t since, FILE * out, cmd_params_st *params, unsigned have_more)
{
	return;
}
#endif
