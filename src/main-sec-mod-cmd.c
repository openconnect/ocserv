/*
 * Copyright (C) 2015 Red Hat, Inc.
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <system.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#include <sys/un.h>
#include <cloexec.h>
#include "common.h"
#include "str.h"
#include "setproctitle.h"
#include <sec-mod.h>
#include <route-add.h>
#include <ipc.pb-c.h>
#include <script-list.h>

#include <vpn.h>
#include <main.h>
#include <ccan/list/list.h>

int handle_sec_mod_commands(main_server_st * s)
{
	struct iovec iov[3];
	uint8_t cmd;
	struct msghdr hdr;
	uint16_t length;
	uint8_t *raw;
	int ret, raw_len, e;
	void *pool = talloc_new(s);
	//PROTOBUF_ALLOCATOR(pa, pool);

	if (pool == NULL)
		return -1;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = &length;
	iov[1].iov_len = 2;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	ret = recvmsg(s->sec_mod_fd, &hdr, 0);
	if (ret == -1) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "cannot obtain metadata from command socket: %s",
		      strerror(e));
		return ERR_BAD_COMMAND;
	}

	if (ret == 0) {
		mslog(s, NULL, LOG_DEBUG, "command socket closed");
		return ERR_WORKER_TERMINATED;
	}

	if (ret < 3) {
		mslog(s, NULL, LOG_ERR, "command error");
		return ERR_BAD_COMMAND;
	}

	mslog(s, NULL, LOG_DEBUG, "main received message '%s' from sec-mod of %u bytes\n",
	      cmd_request_to_str(cmd), (unsigned)length);

	raw = talloc_size(pool, length);
	if (raw == NULL) {
		mslog(s, NULL, LOG_ERR, "memory error");
		return ERR_MEM;
	}

	raw_len = force_read_timeout(s->sec_mod_fd, raw, length, 2);
	if (raw_len != length) {
		e = errno;
		mslog(s, NULL, LOG_ERR,
		      "cannot obtain data from command socket: %s",
		      strerror(e));
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	switch (cmd) {
	default:
		mslog(s, NULL, LOG_ERR, "unknown CMD from sec-mod 0x%x.", (unsigned)cmd);
		ret = ERR_BAD_COMMAND;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	talloc_free(raw);
	talloc_free(pool);

	return ret;
}

