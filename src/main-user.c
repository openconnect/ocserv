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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#include <errno.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#ifdef HAVE_LIBUTIL
# include <utmpx.h>
#endif
#include <gettime.h>

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <ip-lease.h>
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
		char real[64] = "";
		char local[64] = "";
		char remote[64] = "";

		sigprocmask(SIG_SETMASK, &sig_default_set, NULL);

		snprintf(real, sizeof(real), "%u", (unsigned)proc->pid);
		setenv("ID", real, 1);

		if (proc->remote_addr_len > 0) {
			if (getnameinfo((void*)&proc->remote_addr, proc->remote_addr_len, real, sizeof(real), NULL, 0, NI_NUMERICHOST) != 0) {
				mslog(s, proc, LOG_DEBUG, "cannot determine peer address; script failed");
				exit(1);
			}
			setenv("IP_REAL", real, 1);
		}

		if (proc->ipv4 != NULL || proc->ipv6 != NULL) {
			if (proc->ipv4 && proc->ipv4->lip_len > 0) {
				if (getnameinfo((void*)&proc->ipv4->lip, proc->ipv4->lip_len, local, sizeof(local), NULL, 0, NI_NUMERICHOST) != 0) {
					mslog(s, proc, LOG_DEBUG, "cannot determine local VPN address; script failed");
					exit(1);
				}
				setenv("IP_LOCAL", local, 1);
			}

			if (proc->ipv6 && proc->ipv6->lip_len > 0) {
				if (getnameinfo((void*)&proc->ipv6->lip, proc->ipv6->lip_len, local, sizeof(local), NULL, 0, NI_NUMERICHOST) != 0) {
					mslog(s, proc, LOG_DEBUG, "cannot determine local VPN PtP address; script failed");
					exit(1);
				}
				if (local[0] == 0)
					setenv("IP_LOCAL", local, 1);
				setenv("IPV6_LOCAL", local, 1);
			}

			if (proc->ipv4 && proc->ipv4->rip_len > 0) {
				if (getnameinfo((void*)&proc->ipv4->rip, proc->ipv4->rip_len, remote, sizeof(remote), NULL, 0, NI_NUMERICHOST) != 0) {
					mslog(s, proc, LOG_DEBUG, "cannot determine local VPN address; script failed");
					exit(1);
				}
				setenv("IP_REMOTE", remote, 1);
			}
			if (proc->ipv6 && proc->ipv6->rip_len > 0) {
				if (getnameinfo((void*)&proc->ipv6->rip, proc->ipv6->rip_len, remote, sizeof(remote), NULL, 0, NI_NUMERICHOST) != 0) {
					mslog(s, proc, LOG_DEBUG, "cannot determine local VPN PtP address; script failed");
					exit(1);
				}
				if (remote[0] == 0)
					setenv("IP_REMOTE", remote, 1);
				setenv("IP_REMOTE", remote, 1);
			}
		} else {
			mslog(s, proc, LOG_DEBUG, "no IP for this user; script failed");
			exit(1);
		}

		setenv("USERNAME", proc->username, 1);
		setenv("GROUPNAME", proc->groupname, 1);
		setenv("HOSTNAME", proc->hostname, 1);
		setenv("DEVICE", proc->tun_lease.name, 1);
		if (up)
			setenv("REASON", "connect", 1);
		else {
			/* use remote as temp buffer */
			snprintf(remote, sizeof(remote), "%lu", (unsigned long)proc->bytes_in);
			setenv("STATS_BYTES_IN", remote, 1);
			snprintf(remote, sizeof(remote), "%lu", (unsigned long)proc->bytes_out);
			setenv("STATS_BYTES_OUT", remote, 1);
			if (proc->conn_time > 0) {
				snprintf(remote, sizeof(remote), "%lu", (unsigned long)(time(0)-proc->conn_time));
				setenv("STATS_DURATION", remote, 1);
			}
			setenv("REASON", "disconnect", 1);
		}

		mslog(s, proc, LOG_DEBUG, "executing script %s", script);
		ret = execl(script, script, NULL);
		if (ret == -1) {
			mslog(s, proc, LOG_ERR, "Could not execute script %s", script);
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
	snprintf(entry.ut_line, sizeof(entry.ut_line), "%s", proc->tun_lease.name);
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
	if (proc->tun_lease.name[0] != 0)
		snprintf(entry.ut_line, sizeof(entry.ut_line), "%s", proc->tun_lease.name);
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

