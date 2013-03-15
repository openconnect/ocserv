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
#include <worker.h>

#ifdef HAVE_LIBSECCOMP

#include <seccomp.h>
#include <errno.h>

int disable_system_calls(struct worker_st *ws)
{
	int ret, e;
	scmp_filter_ctx ctx;
	
	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		oclog(ws, LOG_WARNING, "could not initialize seccomp");
		return -1;
	}

#define ADD_SYSCALL(name) \
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name), 0); \
	if (ret < 0) { \
		e = errno; \
		oclog(ws, LOG_WARNING, "could not add " #name " to seccomp filter: %s", strerror(e)); \
		ret = -1; \
		goto fail; \
	}
	
	ADD_SYSCALL(time);
	ADD_SYSCALL(recvmsg);
	ADD_SYSCALL(sendmsg);
	ADD_SYSCALL(read);
	ADD_SYSCALL(write);
	ADD_SYSCALL(writev);
	ADD_SYSCALL(select);
	ADD_SYSCALL(alarm);
	ADD_SYSCALL(close);
	ADD_SYSCALL(exit);
	ADD_SYSCALL(exit_group);
	ADD_SYSCALL(send);
	ADD_SYSCALL(recv);
	ADD_SYSCALL(socket);
	ADD_SYSCALL(connect);

	/* this we need to get the MTU from
	 * the TUN device */
	ADD_SYSCALL(ioctl);

	ret = seccomp_load(ctx);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not load seccomp filter");
		ret = -1;
		goto fail;
	}
	
	seccomp_release(ctx);
	ret = 0;
fail:
	seccomp_release(ctx);
	return ret;
}
#else
int disable_system_calls(struct worker_st *ws)
{
	return 0;
}
#endif
