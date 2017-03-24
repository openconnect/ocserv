/*
 * Copyright (C) 2017 Nikos Mavrogiannopoulos
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <gnutls/gnutls.h>

/* Unit test for _cstp_recv_packet(). I checks whether
 * CSTP packets are received and decoded as expected.
 */
static unsigned verbose = 0;
#define UNDER_TEST
#define force_write write

#include "../src/tlslib.c"

int get_cert_names(worker_st * ws, const gnutls_datum_t * raw)
{
	return 0;
}

#define MAX_SIZE 256
#define ITERATIONS 1024

void writer(int fd)
{
	unsigned size, i, j;
	unsigned char buf[MAX_SIZE+8];

	memset(buf, 0, sizeof(buf));

	for (i=0;i<ITERATIONS;i++) {
		assert(gnutls_rnd(GNUTLS_RND_NONCE, &size, sizeof(unsigned)) >= 0);

		size %= MAX_SIZE;
		size++; /* non-zero */

		buf[4] = (size >> 8) & 0xff;
		buf[5] = size & 0xff;

		size += 8;

		if (verbose)
			fprintf(stderr, "sending %d\n", size);
		for (j=0;j<size;j++) { /* use multiple writes */
			assert(write(fd, buf+j, 1) == 1);
		}
	}
	return;
}

void receiver(int fd)
{
	worker_st ws;
	unsigned char buf[MAX_SIZE*3];
	int ret;
	unsigned i;

	memset(&ws, 0, sizeof(ws));
	ws.conn_fd = fd;

	for (i=0;i<ITERATIONS;i++) {
		ret = _cstp_recv_packet(&ws, buf, sizeof(buf));
		if (verbose)
			fprintf(stderr, "received %d\n", ret);
		assert(ret > 0);
	}

	return;
}

int main(int argc, char **argv)
{
	int sockets[2];
	pid_t child;
	int status = 0;

	if (argc > 1)
		verbose = 1;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) >= 0);

	child = fork();
	assert(child >= 0);
	
	if (child) {
		close(sockets[1]);
		receiver(sockets[0]);
		wait(&status);
		if (WEXITSTATUS(status) != 0) {
			fprintf(stderr, "child failed %d!\n", (int)WEXITSTATUS(status));
			exit(1);
		}
	} else {
		close(sockets[0]);
		writer(sockets[1]);
		return 0;
	}

	return 0;
}
