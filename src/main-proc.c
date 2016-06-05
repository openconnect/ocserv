/*
 * Copyright (C) 2013, 2014, 2015 Nikos Mavrogiannopoulos
 * Copyright (C) 2014, 2015 Red Hat, Inc.
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
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <system.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#include <sys/un.h>
#include <cloexec.h>
#include "common.h"
#include "str.h"
#include "setproctitle.h"
#include <sec-mod.h>
#include <route-add.h>
#include <ip-lease.h>
#include <proc-search.h>
#include <ipc.pb-c.h>
#include <script-list.h>
#include <inttypes.h>
#include <ev.h>

#ifdef HAVE_MALLOC_TRIM
# include <malloc.h>
#endif

#include <vpn.h>
#include <tun.h>
#include <main.h>
#include <main-ban.h>
#include <ccan/list/list.h>

struct proc_st *new_proc(main_server_st * s, pid_t pid, int cmd_fd,
			struct sockaddr_storage *remote_addr, socklen_t remote_addr_len,
			struct sockaddr_storage *our_addr, socklen_t our_addr_len,
			uint8_t *sid, size_t sid_size)
{
struct proc_st *ctmp;

	ctmp = talloc_zero(s, struct proc_st);
	if (ctmp == NULL)
		return NULL;

	ctmp->pid = pid;
	ctmp->tun_lease.fd = -1;
	ctmp->fd = cmd_fd;
	set_cloexec_flag (cmd_fd, 1);
	ctmp->conn_time = time(0);

	memcpy(&ctmp->remote_addr, remote_addr, remote_addr_len);
	ctmp->remote_addr_len = remote_addr_len;

	memcpy(&ctmp->our_addr, our_addr, our_addr_len);
	ctmp->our_addr_len = our_addr_len;

	list_add(&s->proc_list.head, &(ctmp->list));
	put_into_cgroup(s, s->config->cgroup, pid);
	s->active_clients++;

	return ctmp;
}

/* k: whether to kill the process
 */
void remove_proc(main_server_st * s, struct proc_st *proc, unsigned flags)
{
	pid_t pid;

	ev_io_stop(EV_A_ &proc->io);
	ev_child_stop(EV_A_ &proc->ev_child);

	list_del(&proc->list);
	s->active_clients--;

	if ((flags&RPROC_KILL) && proc->pid != -1 && proc->pid != 0)
		kill(proc->pid, SIGTERM);

	/* close any pending sessions */
	if (proc->active_sid && !(flags & RPROC_QUIT)) {
		if (session_close(s, proc) < 0) {
			mslog(s, proc, LOG_ERR, "error closing session (communication with sec-mod issue)");
			exit(1);
		}
	}

	mslog(s, proc, LOG_INFO, "user disconnected (reason: %s, rx: %"PRIu64", tx: %"PRIu64")",
		discon_reason_to_str(proc->discon_reason), proc->bytes_in, proc->bytes_out);

	pid = remove_from_script_list(s, proc);
	if (proc->status == PS_AUTH_COMPLETED || pid > 0) {
		if (pid > 0) {
			int wstatus;
			/* we were called during the connect script being run.
			 * wait for it to finish and if it returns zero run the
			 * disconnect script */
			 if (waitpid(pid, &wstatus, 0) > 0) {
			 	if (WEXITSTATUS(wstatus) == 0)
					user_disconnected(s, proc);
			 }
		} else { /* pid > 0 or status == PS_AUTH_COMPLETED are mutually exclusive
		          * since PS_AUTH_COMPLETED is set only after a successful script run.
		          */
			user_disconnected(s, proc);
		}
	}

	/* close the intercomm fd */
	if (proc->fd >= 0)
		close(proc->fd);
	proc->fd = -1;
	proc->pid = -1;

	remove_iroutes(s, proc);

	if (proc->ipv4 || proc->ipv6)
		remove_ip_leases(s, proc);

	close_tun(s, proc);
	proc_table_del(s, proc);
	if (proc->config_usage_count && *proc->config_usage_count > 0) {
		(*proc->config_usage_count)--;
	}

	safe_memset(proc->sid, 0, sizeof(proc->sid));
	talloc_free(proc);
}

