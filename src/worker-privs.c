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
#include <worker.h>
#include <sys/ioctl.h>

#ifdef HAVE_LIBSECCOMP

#include <seccomp.h>
#include <errno.h>

int disable_system_calls(struct worker_st *ws)
{
	int ret;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
	if (ctx == NULL) {
		oclog(ws, LOG_DEBUG, "could not initialize seccomp");
		return -1;
	}

#define ADD_SYSCALL(name, ...) \
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name), __VA_ARGS__); \
	/* libseccomp returns EDOM for pseudo-syscalls due to a bug */ \
	if (ret < 0 && ret != -EDOM) { \
		oclog(ws, LOG_DEBUG, "could not add " #name " to seccomp filter: %s", strerror(-ret)); \
		ret = -1; \
		goto fail; \
	}

	/* we use quite some system calls here, and in the end
	 * we don't even know whether a newer libc will change the
	 * underlying calls to something else. seccomp seems to be useful
	 * in very restricted designs.
	 */
	ADD_SYSCALL(time, 0);
	ADD_SYSCALL(gettimeofday, 0);
#if defined(HAVE_CLOCK_GETTIME)
	ADD_SYSCALL(clock_gettime, 0);
#endif
	ADD_SYSCALL(nanosleep, 0);
	ADD_SYSCALL(getrusage, 0);
	ADD_SYSCALL(alarm, 0);
	ADD_SYSCALL(brk, 0);

	ADD_SYSCALL(recvmsg, 0);
	ADD_SYSCALL(sendmsg, 0);

	ADD_SYSCALL(read, 0);

	ADD_SYSCALL(write, 0);
	ADD_SYSCALL(writev, 0);

	ADD_SYSCALL(send, 0);
	ADD_SYSCALL(recv, 0);

	/* it seems we need to add sendto and recvfrom
	 * since send() and recv() aren't called by libc.
	 */
	ADD_SYSCALL(sendto, 0);
	ADD_SYSCALL(recvfrom, 0);

	/* allow returning from the signal handler */
	ADD_SYSCALL(sigreturn, 0);
	ADD_SYSCALL(rt_sigreturn, 0);

	/* we use it in select */
	ADD_SYSCALL(sigprocmask, 0);
	ADD_SYSCALL(rt_sigprocmask, 0);

	ADD_SYSCALL(select, 0);
	/* in x86, glibc uses _newselect() */
	ADD_SYSCALL(_newselect, 0);

	ADD_SYSCALL(pselect6, 0);
	ADD_SYSCALL(close, 0);
	ADD_SYSCALL(exit, 0);
	ADD_SYSCALL(exit_group, 0);
	ADD_SYSCALL(socket, 0);
	ADD_SYSCALL(connect, 0);

	ADD_SYSCALL(getsockopt, 0);
	ADD_SYSCALL(setsockopt, 0);

	/* we need to open files when we have an xml_config_file setup */
	if (ws->config->xml_config_file) {
		ADD_SYSCALL(fstat, 0);
		ADD_SYSCALL(lseek, 0);
		ADD_SYSCALL(open, 0);
	}

	/* this we need to get the MTU from
	 * the TUN device */
	ADD_SYSCALL(ioctl, 1, SCMP_A1(SCMP_CMP_EQ, (int)SIOCGIFMTU));

	ret = seccomp_load(ctx);
	if (ret < 0) {
		oclog(ws, LOG_DEBUG, "could not load seccomp filter");
		ret = -1;
		goto fail;
	}
	
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
