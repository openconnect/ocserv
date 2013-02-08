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

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
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

#include <vpn.h>
#include "ipc.h"
#include <worker.h>
#include <cookies.h>
#include <tlslib.h>

int send_tun_mtu(worker_st *ws, unsigned int mtu)
{
	struct iovec iov[2];
	uint8_t cmd;
	struct msghdr hdr;
	struct cmd_tun_mtu_st data;

	memset(&hdr, 0, sizeof(hdr));
	
	cmd = CMD_TUN_MTU;
	data.mtu = mtu;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = (void*)&data;
	iov[1].iov_len = sizeof(data);
	
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	return(sendmsg(ws->cmd_fd, &hdr, 0));
}
