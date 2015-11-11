/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef DIE_H
# define DIE_H

# include <config.h>
# include <signal.h>
# include <unistd.h>

#ifdef HAVE_SIGHANDLER_T
# define SIGHANDLER_T sighandler_t
#elif HAVE_SIG_T
# define SIGHANDLER_T sig_t
#elif HAVE___SIGHANDLER_T
# define SIGHANDLER_T __sighandler_t
#else
typedef void (*sighandler_t)(int);
# define SIGHANDLER_T sighandler_t
#endif

void pr_set_undumpable(const char* mod);
void kill_on_parent_kill(int sig);

SIGHANDLER_T ocsignal(int signum, SIGHANDLER_T handler);

int check_upeer_id(const char *mod, int debug, int cfg, uid_t uid, uid_t gid, uid_t *ruid, pid_t *pid);

#endif
