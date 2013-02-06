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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#include <utmpx.h>
#include <timespec.h>

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>

static
void call_disconnect_script(main_server_st *s, struct proc_st* proc)
{
pid_t pid;
int ret;

	if (s->config->disconnect_script == NULL)
		return;

	/* XXX: close fds */
	pid = fork();
	if (pid == 0) {
		char real[64];
		char local[64];
		char remote[64];

		if (proc->lease == NULL)
			exit(1);
		
		if (getnameinfo((void*)&proc->remote_addr, proc->remote_addr_len, real, sizeof(real), NULL, 0, NI_NUMERICHOST) != 0)
			exit(1);

		if (proc->lease->lip4_len > 0) {
			if (getnameinfo((void*)&proc->lease->lip4, proc->lease->lip4_len, local, sizeof(local), NULL, 0, NI_NUMERICHOST) != 0)
				exit(1);
		} else {
			if (getnameinfo((void*)&proc->lease->lip6, proc->lease->lip6_len, local, sizeof(local), NULL, 0, NI_NUMERICHOST) != 0)
				exit(1);
		}

		if (proc->lease->rip4_len > 0) {
			if (getnameinfo((void*)&proc->lease->rip4, proc->lease->rip4_len, remote, sizeof(remote), NULL, 0, NI_NUMERICHOST) != 0)
				exit(1);
		} else {
			if (getnameinfo((void*)&proc->lease->rip6, proc->lease->rip6_len, remote, sizeof(remote), NULL, 0, NI_NUMERICHOST) != 0)
				exit(1);
		}
		
		ret = execlp(s->config->disconnect_script, s->config->disconnect_script,
			proc->username, proc->hostname, proc->lease->name, real, local, remote, NULL);
		if (ret == -1)
			exit(1);
			
		exit(0);
	} else if (pid == -1) {
		syslog(LOG_ERR, "Could not fork()");
	}
}

static
int call_connect_script(main_server_st *s, struct proc_st* proc, struct lease_st* lease)
{
pid_t pid;
int ret, status;

	if (s->config->connect_script == NULL)
		return 0;

	if (s->config->auth_types & AUTH_TYPE_PAM) {
		static int warned = 0;
		
		if (warned == 0) {
			syslog(LOG_WARNING, "PAM authentication and UTMP are mutually exclusive. Turn off UTMP and use PAM for accounting.");
			warned = 1;
		}
		return 0;
	}

	pid = fork();
	if (pid == 0) {
		char real[64];
		char local[64];
		char remote[64];
		
		/* Note we don't use proc->lease and accept lease directly
		 * because we are called before proc population is completed */
		
		if (getnameinfo((void*)&proc->remote_addr, proc->remote_addr_len, real, sizeof(real), NULL, 0, NI_NUMERICHOST) != 0)
			exit(1);

		if (lease->lip4_len > 0) {
			if (getnameinfo((void*)&lease->lip4, lease->lip4_len, local, sizeof(local), NULL, 0, NI_NUMERICHOST) != 0)
				exit(1);
		} else {
			if (getnameinfo((void*)&lease->lip6, lease->lip6_len, local, sizeof(local), NULL, 0, NI_NUMERICHOST) != 0)
				exit(1);
		}

		if (lease->rip4_len > 0) {
			if (getnameinfo((void*)&lease->rip4, lease->rip4_len, remote, sizeof(remote), NULL, 0, NI_NUMERICHOST) != 0)
				exit(1);
		} else {
			if (getnameinfo((void*)&lease->rip6, lease->rip6_len, remote, sizeof(remote), NULL, 0, NI_NUMERICHOST) != 0)
				exit(1);
		}

		ret = execlp(s->config->connect_script, s->config->connect_script,
			proc->username, proc->hostname, lease->name, real, local, remote, NULL);
		if (ret == -1)
			exit(1);
			
		exit(0);
	} else if (pid == -1) {
		syslog(LOG_ERR, "Could not fork()");
		return -1;
	}
	
	ret = waitpid(pid, &status, 0);
	if (WEXITSTATUS(status) == 0)
		return 0;
	return -1;
}

static void
add_utmp_entry(main_server_st *s, struct proc_st* proc, struct lease_st* lease)
{
	struct utmpx entry;
	struct timespec tv;
	
	if (s->config->use_utmp == 0)
		return;

	memset(&entry, 0, sizeof(entry));
	entry.ut_type = USER_PROCESS;
	entry.ut_pid = proc->pid;
	snprintf(entry.ut_line, sizeof(entry.ut_line), "%s", lease->name);
	snprintf(entry.ut_user, sizeof(entry.ut_user), "%s", proc->username);
	if (proc->remote_addr_len == sizeof(struct sockaddr_in))
		memcpy(entry.ut_addr_v6, SA_IN_P(&proc->remote_addr), sizeof(struct in_addr));
	else
		memcpy(entry.ut_addr_v6, SA_IN6_P(&proc->remote_addr), sizeof(struct in6_addr));

	gettime(&tv);
	entry.ut_tv.tv_sec = tv.tv_sec;
	entry.ut_tv.tv_usec = tv.tv_nsec / 1000;
	getnameinfo((void*)&proc->remote_addr, proc->remote_addr_len, entry.ut_host, sizeof(entry.ut_host), NULL, 0, NI_NUMERICHOST);

	setutxent();
	pututxline(&entry);
	endutxent();
	
	return;
}

static void remove_utmp_entry(main_server_st *s, struct proc_st* proc)
{
	struct utmpx entry;

	if (s->config->use_utmp == 0)
		return;

	memset(&entry, 0, sizeof(entry));
	entry.ut_type = DEAD_PROCESS;
	if (proc->lease && proc->lease->name)
		snprintf(entry.ut_line, sizeof(entry.ut_line), "%s", proc->lease->name);
	entry.ut_pid = proc->pid;

	setutxent();
	pututxline(&entry);
	endutxent();
	
	return;
}

int user_connected(main_server_st *s, struct proc_st* proc, struct lease_st* lease)
{
int ret;

	add_utmp_entry(s, proc, lease);

	ret = call_connect_script(s, proc, lease);
	if (ret < 0)
		return ret;

	return 0;
}

void user_disconnected(main_server_st *s, struct proc_st* proc)
{
	remove_utmp_entry(s, proc);
	call_disconnect_script(s, proc);
}

