/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2016 Red Hat, Inc.
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

#include <fcntl.h>
#include <sys/resource.h>
#include <grp.h>


#include <main.h>
#include <limits.h>
 
void init_fd_limits_default(main_server_st * s)
{
#ifdef RLIMIT_NOFILE
	int ret = getrlimit(RLIMIT_NOFILE, &s->fd_limits_default_set);
	if (ret < 0) {
		fprintf(stderr, "error in getrlimit: %s\n", strerror(errno));
		exit(1);
	}
#endif
}

/* (Maximum clients) + (small buffer) + (sec mod fds)
 * The (small buffer) is to allow unknown fds used by backends (e.g.,
 * gnutls) as well as to allow running up to that many scripts (due to dup2)
 * when close to the maximum limit.
 */
#define MAX_FD_LIMIT(clients) (clients + 128 + s->sec_mod_instance_count * 2)

/* Adjusts the file descriptor limits for the main or worker processes
 */
void update_fd_limits(main_server_st * s, unsigned main)
{
#ifdef RLIMIT_NOFILE
	struct rlimit new_set;
	unsigned max;
	int ret;

	if (main) {
		if (GETCONFIG(s)->max_clients > 0) 
			max = MAX_FD_LIMIT(GETCONFIG(s)->max_clients);
		else
			// If the admin doesn't specify max_clients,
			// then we are limiting it to around 8K.
			max = MAX_FD_LIMIT(8 * 1024);

		if (max > s->fd_limits_default_set.rlim_cur) {
			new_set.rlim_cur = max;
			new_set.rlim_max = s->fd_limits_default_set.rlim_max;
			ret = setrlimit(RLIMIT_NOFILE, &new_set);
			if (ret < 0) {
				fprintf(stderr,
					"error in setrlimit(%u): %s (cur: %u)\n",
					max, strerror(errno),
					(unsigned)s->fd_limits_default_set.
					rlim_cur);
			}
		}
	} else {
		/* set limits for worker processes */
		ret = setrlimit(RLIMIT_NOFILE, &s->fd_limits_default_set);
		if (ret < 0) {
			mslog(s, NULL, LOG_INFO,
			      "cannot update file limit(%u): %s\n",
			      (unsigned)s->fd_limits_default_set.rlim_cur,
			      strerror(errno));
		}
	}
#endif
}

void set_self_oom_score_adj(main_server_st * s)
{
#ifdef __linux__
	const char proc_self_oom_adj_score_path[] = "/proc/self/oom_score_adj";
	const char oom_adj_score_value[] = "1000";
	size_t written = 0;
	int fd;

	fd = open(proc_self_oom_adj_score_path, O_WRONLY,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		int e = errno;
		mslog(s, NULL, LOG_ERR, "cannot open %s: %s",
		      proc_self_oom_adj_score_path, strerror(e));
		goto cleanup;
	}

	written = write(fd, oom_adj_score_value, sizeof(oom_adj_score_value));
	if (written != sizeof(oom_adj_score_value)) {
		int e = errno;
		mslog(s, NULL, LOG_ERR, "cannot write %s: %s",
		      proc_self_oom_adj_score_path, strerror(e));
		goto cleanup;
	}

 cleanup:
	if (fd) {
		close(fd);
	}
#endif
}


void drop_privileges(main_server_st * s)
{
	int ret, e;
	struct rlimit rl;

	if (GETPCONFIG(s)->chroot_dir) {
		ret = chdir(GETPCONFIG(s)->chroot_dir);
		if (ret != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot chdir to %s: %s",
			      GETPCONFIG(s)->chroot_dir, strerror(e));
			exit(1);
		}

		ret = chroot(GETPCONFIG(s)->chroot_dir);
		if (ret != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot chroot to %s: %s",
			      GETPCONFIG(s)->chroot_dir, strerror(e));
			exit(1);
		}
	}

	if (GETPCONFIG(s)->gid != -1 && (getgid() == 0 || getegid() == 0)) {
		ret = setgid(GETPCONFIG(s)->gid);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot set gid to %d: %s\n",
			      (int)GETPCONFIG(s)->gid, strerror(e));
			exit(1);
		}

		ret = setgroups(1, &GETPCONFIG(s)->gid);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot set groups to %d: %s\n",
			      (int)GETPCONFIG(s)->gid, strerror(e));
			exit(1);
		}
	}

	if (GETPCONFIG(s)->uid != -1 && (getuid() == 0 || geteuid() == 0)) {
		ret = setuid(GETPCONFIG(s)->uid);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot set uid to %d: %s\n",
			      (int)GETPCONFIG(s)->uid, strerror(e));
			exit(1);

		}
	}

	update_fd_limits(s, 0);

	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	ret = setrlimit(RLIMIT_NPROC, &rl);
	if (ret < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "cannot enforce NPROC limit: %s\n",
		      strerror(e));
	}
}