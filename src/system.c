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
#include <system.h>
#include <unistd.h>
#ifdef __linux__
# include <sys/prctl.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/syslog.h>

#include <errno.h>
#include <signal.h>

void kill_on_parent_kill(int sig)
{
#ifdef __linux__
	prctl(PR_SET_PDEATHSIG, sig);
#endif
}

void pr_set_undumpable(const char *mod)
{
#ifdef __linux__
	if (prctl(PR_SET_DUMPABLE, 0) == -1) {
		int e = errno;
		syslog(LOG_ERR, "%s: prctl(PR_SET_DUMPABLE) failed %s",
			mod, strerror(e));
	}
#endif
}

SIGHANDLER_T ocsignal(int signum, SIGHANDLER_T handler)
{
	struct sigaction new_action, old_action;
	
	new_action.sa_handler = handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;
	
	sigaction (signum, &new_action, &old_action);
	return old_action.sa_handler;
}

/* Checks whether the peer in a socket has the expected @uid and @gid.
 * Returns zero on success.
 */
int check_upeer_id(const char *mod, int debug, int cfd, uid_t uid, uid_t gid, uid_t *ruid)
{
	int e, ret;
#if defined(SO_PEERCRED) && defined(HAVE_STRUCT_UCRED)
	struct ucred cr;
	socklen_t cr_len;

	/* This check is superfluous in Linux and mostly for debugging
	 * purposes. The socket permissions set with umask should
	 * be sufficient already for access control, but not all
	 * UNIXes support that. */
	cr_len = sizeof(cr);
	ret = getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len);
	if (ret == -1) {
		e = errno;
		syslog(LOG_ERR, "%s: getsockopt SO_PEERCRED error: %s",
			mod, strerror(e));
		return -1;
	}

	if (debug >= 3)
		syslog(LOG_DEBUG,
		       "%s: received request from pid %u and uid %u",
		       mod, (unsigned)cr.pid, (unsigned)cr.uid);

	if (ruid)
		*ruid = cr.uid;

	if (cr.uid != 0 && (cr.uid != uid || cr.gid != gid)) {
		syslog(LOG_ERR,
		       "%s: received unauthorized request from pid %u and uid %u",
		       mod, (unsigned)cr.pid, (unsigned)cr.uid);
		       return -1;
	}
#elif defined(HAVE_GETPEEREID)
	uid_t euid;
	gid_t egid;

	ret = getpeereid(cfd, &euid, &egid);

	if (ret == -1) {
		e = errno;
		syslog(LOG_DEBUG, "%s: getpeereid error: %s",
			mod, strerror(e));
		return -1;
	}

	if (ruid)
		*ruid = euid;

	if (debug >= 3)
		syslog(LOG_DEBUG,
		       "%s: received request from a processes with uid %u",
		       mod, (unsigned)euid);
	if (euid != 0 && (euid != uid || egid != gid)) {
		syslog(LOG_ERR,
		       "%s: received unauthorized request from a process with uid %u",
			mod, (unsigned)euid);
			return -1;
	}
#else
#error "Unsupported UNIX variant"
#endif
	return 0;
}
