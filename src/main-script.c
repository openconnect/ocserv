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

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <list.h>

void call_disconnect_script(main_server_st *s, struct proc_list_st* proc)
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
			proc->username, proc->lease->name, real, local, remote, NULL);
		if (ret == -1)
			exit(1);
			
		exit(0);
	} else if (pid == -1) {
		syslog(LOG_ERR, "Could not fork()");
	}
}

int call_connect_script(main_server_st *s, struct proc_list_st* proc)
{
pid_t pid;
int ret, status;

	if (s->config->connect_script == NULL)
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

		ret = execlp(s->config->connect_script, s->config->connect_script,
			proc->username, proc->lease->name, real, local, remote, NULL);
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
