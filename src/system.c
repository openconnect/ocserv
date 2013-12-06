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
#include <system.h>
#include <unistd.h>
#ifdef __linux__
# include <sys/prctl.h>
#endif

void kill_on_parent_kill(int sig)
{
#ifdef __linux__
	prctl(PR_SET_PDEATHSIG, sig);
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
