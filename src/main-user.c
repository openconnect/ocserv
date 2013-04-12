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
#ifdef HAVE_LIBUTIL
# include <utmpx.h>
#endif
#include <timespec.h>

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <script-list.h>
#include <ccan/list/list.h>

static
int call_script(main_server_st *s, struct proc_st* proc, unsigned up)
{
pid_t pid;
int ret;
const char* script;

	if (up != 0)
		script = s->config->connect_script;
	else
		script = s->config->disconnect_script;

	if (script == NULL)
		return 0;

	pid = fork();
	if (pid == 0) {
		char real[64];
		char local[64];
		char remote[64];
		
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

		setenv("USERNAME", proc->username, 1);
		setenv("GROUPNAME", proc->groupname, 1);
		setenv("HOSTNAME", proc->hostname, 1);
		setenv("DEVICE", proc->lease->name, 1);
		setenv("IP_REAL", real, 1);
		setenv("IP_LOCAL", local, 1);
		setenv("IP_REMOTE", remote, 1);
		if (up)
			setenv("REASON", "connect", 1);
		else
			setenv("REASON", "disconnect", 1);

		mslog(s, proc, LOG_DEBUG, "executing script %s", script);
		ret = execl(script, script, NULL);
		if (ret == -1) {
			mslog(s, proc, LOG_ERR, "Could execute script %s", script);
			exit(1);
		}
			
		exit(77);
	} else if (pid == -1) {
		mslog(s, proc, LOG_ERR, "Could not fork()");
		return -1;
	}
	
	if (up) {
		add_to_script_list(s, pid, up, proc);
		return ERR_WAIT_FOR_SCRIPT;
	} else {
		return 0;
	}
}

static void
add_utmp_entry(main_server_st *s, struct proc_st* proc)
{
#ifdef HAVE_LIBUTIL
	struct utmpx entry;
	struct timespec tv;
	
	if (s->config->use_utmp == 0)
		return;

	memset(&entry, 0, sizeof(entry));
	entry.ut_type = USER_PROCESS;
	entry.ut_pid = proc->pid;
	snprintf(entry.ut_line, sizeof(entry.ut_line), "%s", proc->lease->name);
	snprintf(entry.ut_user, sizeof(entry.ut_user), "%s", proc->username);
#ifdef __linux__
	if (proc->remote_addr_len == sizeof(struct sockaddr_in))
		memcpy(entry.ut_addr_v6, SA_IN_P(&proc->remote_addr), sizeof(struct in_addr));
	else
		memcpy(entry.ut_addr_v6, SA_IN6_P(&proc->remote_addr), sizeof(struct in6_addr));
#endif

	gettime(&tv);
	entry.ut_tv.tv_sec = tv.tv_sec;
	entry.ut_tv.tv_usec = tv.tv_nsec / 1000;
	getnameinfo((void*)&proc->remote_addr, proc->remote_addr_len, entry.ut_host, sizeof(entry.ut_host), NULL, 0, NI_NUMERICHOST);

	setutxent();
	pututxline(&entry);
	endutxent();

#if defined(WTMPX_FILE)
	updwtmpx(WTMPX_FILE, &entry);
#endif   
	
	return;
#endif
}

static void remove_utmp_entry(main_server_st *s, struct proc_st* proc)
{
#ifdef HAVE_LIBUTIL
	struct utmpx entry;
	struct timespec tv;

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

#if defined(WTMPX_FILE)
	gettime(&tv);
	entry.ut_tv.tv_sec = tv.tv_sec;
	entry.ut_tv.tv_usec = tv.tv_nsec / 1000;
	updwtmpx(WTMPX_FILE, &entry);
#endif   
	return;
#endif
}

int user_connected(main_server_st *s, struct proc_st* proc)
{
int ret;

	add_utmp_entry(s, proc);

	ret = call_script(s, proc, 1);
	if (ret < 0)
		return ret;

	return 0;
}

void user_disconnected(main_server_st *s, struct proc_st* proc)
{
	remove_utmp_entry(s, proc);
	call_script(s, proc, 0);
}

