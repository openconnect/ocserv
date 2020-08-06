/*
 * Copyright (C) 2013-2015 Nikos Mavrogiannopoulos
 * Copyright (C) 2015 Red Hat, Inc.
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
#include <str.h>
#include <tun.h>
#include <main.h>
#include <main-ctl.h>
#include <ip-lease.h>
#include <script-list.h>
#include <ccan/list/list.h>

#define OCSERV_FW_SCRIPT "/usr/bin/ocserv-fw"

#define APPEND_TO_STR(str, val) \
			ret = str_append_str(str, val); \
			if (ret < 0) { \
				mslog(s, proc, LOG_ERR, "could not append value to environment\n"); \
				exit(1); \
			}

typedef enum script_type_t {
	SCRIPT_CONNECT,
	SCRIPT_HOST_UPDATE,
	SCRIPT_DISCONNECT
} script_type_t;

static const char *type_name[] = {"up", "host-update", "down"};

static void export_fw_info(main_server_st *s, struct proc_st* proc)
{
	str_st str4;
	str_st str6;
	str_st str_common;
	unsigned i, negate = 0;
	int ret;

	str_init(&str4, proc);
	str_init(&str6, proc);
	str_init(&str_common, proc);

	/* We use different export strings for IPv4 and IPv6 to ease handling
	 * with legacy software such as iptables and ip6tables. */

	/* append custom routes to str */
	for (i=0;i<proc->config->n_routes;i++) {
		APPEND_TO_STR(&str_common, proc->config->routes[i]);
		APPEND_TO_STR(&str_common, " ");

		if (strchr(proc->config->routes[i], ':') != 0) {
			APPEND_TO_STR(&str6, proc->config->routes[i]);
			APPEND_TO_STR(&str6, " ");
		} else {
			APPEND_TO_STR(&str4, proc->config->routes[i]);
			APPEND_TO_STR(&str4, " ");
		}
	}

	if (str4.length > 0 && setenv("OCSERV_ROUTES4", (char*)str4.data, 1) == -1) {
		mslog(s, proc, LOG_ERR, "could not export routes\n");
		exit(1);
	}

	if (str6.length > 0 && setenv("OCSERV_ROUTES6", (char*)str6.data, 1) == -1) {
		mslog(s, proc, LOG_ERR, "could not export routes\n");
		exit(1);
	}

	if (str_common.length > 0 && setenv("OCSERV_ROUTES", (char*)str_common.data, 1) == -1) {
		mslog(s, proc, LOG_ERR, "could not export routes\n");
		exit(1);
	}

	/* export the No-routes */

	str_reset(&str4);
	str_reset(&str6);
	str_reset(&str_common);

	/* append custom no_routes to str */
	for (i=0;i<proc->config->n_no_routes;i++) {
		APPEND_TO_STR(&str_common, proc->config->no_routes[i]);
		APPEND_TO_STR(&str_common, " ");

		if (strchr(proc->config->no_routes[i], ':') != 0) {
			APPEND_TO_STR(&str6, proc->config->no_routes[i]);
			APPEND_TO_STR(&str6, " ");
		} else {
			APPEND_TO_STR(&str4, proc->config->no_routes[i]);
			APPEND_TO_STR(&str4, " ");
		}
	}

	if (str4.length > 0 && setenv("OCSERV_NO_ROUTES4", (char*)str4.data, 1) == -1) {
		mslog(s, proc, LOG_ERR, "could not export no-routes\n");
		exit(1);
	}

	if (str6.length > 0 && setenv("OCSERV_NO_ROUTES6", (char*)str6.data, 1) == -1) {
		mslog(s, proc, LOG_ERR, "could not export no-routes\n");
		exit(1);
	}

	if (str_common.length > 0 && setenv("OCSERV_NO_ROUTES", (char*)str_common.data, 1) == -1) {
		mslog(s, proc, LOG_ERR, "could not export no-routes\n");
		exit(1);
	}

	if (proc->config->restrict_user_to_routes) {
		if (setenv("OCSERV_RESTRICT_TO_ROUTES", "1", 1) == -1) {
			mslog(s, proc, LOG_ERR, "could not export OCSERV_RESTRICT_TO_ROUTES\n");
			exit(1);
		}
	}
	/* export the DNS servers */

	str_reset(&str4);
	str_reset(&str6);
	str_reset(&str_common);

	if (proc->config->n_dns > 0) {
		for (i=0;i<proc->config->n_dns;i++) {
			APPEND_TO_STR(&str_common, proc->config->dns[i]);
			APPEND_TO_STR(&str_common, " ");

			if (strchr(proc->config->dns[i], ':') != 0) {
				APPEND_TO_STR(&str6, proc->config->dns[i]);
				APPEND_TO_STR(&str6, " ");
			} else {
				APPEND_TO_STR(&str4, proc->config->dns[i]);
				APPEND_TO_STR(&str4, " ");
			}
		}
	}

	if (str4.length > 0 && setenv("OCSERV_DNS4", (char*)str4.data, 1) == -1) {
		mslog(s, proc, LOG_ERR, "could not export DNS servers\n");
		exit(1);
	}

	if (str6.length > 0 && setenv("OCSERV_DNS6", (char*)str6.data, 1) == -1) {
		mslog(s, proc, LOG_ERR, "could not export DNS servers\n");
		exit(1);
	}

	if (str_common.length > 0 && setenv("OCSERV_DNS", (char*)str_common.data, 1) == -1) {
		mslog(s, proc, LOG_ERR, "could not export DNS servers\n");
		exit(1);
	}

	str_clear(&str4);
	str_clear(&str6);
	str_clear(&str_common);

	/* export the ports to reject */

	str_reset(&str_common);

	if (proc->config->n_fw_ports > 0) {
		for (i=0;i<proc->config->n_fw_ports;i++) {
			if (proc->config->fw_ports[i]->negate)
				negate = 1;

			switch(proc->config->fw_ports[i]->proto) {
				case PROTO_UDP:
					ret = str_append_printf(&str_common, "udp %u ", proc->config->fw_ports[i]->port);
					break;
				case PROTO_TCP:
					ret = str_append_printf(&str_common, "tcp %u ", proc->config->fw_ports[i]->port);
					break;
				case PROTO_SCTP:
					ret = str_append_printf(&str_common, "sctp %u ", proc->config->fw_ports[i]->port);
					break;
				case PROTO_ICMP:
					ret = str_append_printf(&str_common, "icmp all ");
					break;
				case PROTO_ESP:
					ret = str_append_printf(&str_common, "esp all ");
					break;
				case PROTO_ICMPv6:
					ret = str_append_printf(&str_common, "icmpv6 all ");
					break;
				default:
					ret = -1;
			}

			if (ret < 0) {
				mslog(s, proc, LOG_ERR, "could not append value to environment\n");
				exit(1);
			}
		}
	}

	if (str_common.length > 0) {
		if (negate) {
			if (setenv("OCSERV_DENY_PORTS", (char*)str_common.data, 1) == -1) {
				mslog(s, proc, LOG_ERR, "could not export DENY_PORTS\n");
				exit(1);
			}
		} else {
			if (setenv("OCSERV_ALLOW_PORTS", (char*)str_common.data, 1) == -1) {
				mslog(s, proc, LOG_ERR, "could not export ALLOW_PORTS\n");
				exit(1);
			}
		}
	}

	str_clear(&str_common);
}

static
int call_script(main_server_st *s, struct proc_st* proc, script_type_t type)
{
pid_t pid;
int ret;
const char* script, *next_script = NULL;

	if (type == SCRIPT_CONNECT)
		script = GETCONFIG(s)->connect_script;
	else if (type == SCRIPT_HOST_UPDATE)
		script = GETCONFIG(s)->host_update_script;
	else
		script = GETCONFIG(s)->disconnect_script;

	if (type != SCRIPT_HOST_UPDATE) {
		if (proc->config->restrict_user_to_routes || proc->config->n_fw_ports > 0) {
			next_script = script;
			script = OCSERV_FW_SCRIPT;
		}
	}

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
			if ((ret=getnameinfo((void*)&proc->remote_addr, proc->remote_addr_len, real, sizeof(real), NULL, 0, NI_NUMERICHOST)) != 0) {
				mslog(s, proc, LOG_DEBUG, "cannot determine peer address: %s; script failed", gai_strerror(ret));
				exit(1);
			}
			setenv("IP_REAL", real, 1);
		}

		if (proc->our_addr_len > 0) {
			if ((ret=getnameinfo((void*)&proc->our_addr, proc->our_addr_len, real, sizeof(real), NULL, 0, NI_NUMERICHOST)) != 0) {
				mslog(s, proc, LOG_DEBUG, "cannot determine our address: %s", gai_strerror(ret));
			} else {
				setenv("IP_REAL_LOCAL", real, 1);
			}
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
				setenv("IPV6_REMOTE", remote, 1);

				snprintf(remote, sizeof(remote), "%u", proc->ipv6->prefix);
				setenv("IPV6_PREFIX", remote, 1);
			}
		}

		if (proc->vhost)
			setenv("VHOST", VHOSTNAME(proc->vhost), 1);
		setenv("USERNAME", proc->username, 1);
		setenv("GROUPNAME", proc->groupname, 1);
		setenv("HOSTNAME", proc->hostname, 1);
		setenv("REMOTE_HOSTNAME", proc->hostname, 1);
		setenv("DEVICE", proc->tun_lease.name, 1);
		setenv("USER_AGENT", proc->user_agent, 1);
		setenv("DEVICE_TYPE", proc->device_type, 1);
		setenv("DEVICE_PLATFORM", proc->device_platform, 1);

		if (type == SCRIPT_CONNECT) {
			setenv("REASON", "connect", 1);
		} else if (type == SCRIPT_HOST_UPDATE) {
			setenv("REASON", "host-update", 1);
		} else if (type == SCRIPT_DISCONNECT) {
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

		/* export DNS and route info */
		export_fw_info(s, proc);

		/* set stdout to be stderr to avoid confusing scripts - note we have stdout closed */
		if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
			int e = errno;
			mslog(s, proc, LOG_INFO, "cannot dup2(STDERR_FILENO, STDOUT_FILENO): %s", strerror(e));
		}

		if (next_script) {
			setenv("OCSERV_NEXT_SCRIPT", next_script, 1);
			mslog(s, proc, LOG_DEBUG, "executing script %s %s (next: %s)", type_name[type], script, next_script);
		} else
			mslog(s, proc, LOG_DEBUG, "executing script %s %s", type_name[type], script);

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
	
	if (type == SCRIPT_CONNECT) {
		add_to_script_list(s, pid, proc);
		return ERR_WAIT_FOR_SCRIPT;
	} else {
		/* we don't add a specific handler for SCRIPT_CONNECT and SCRIPT_HOST_UPDATE
		 * childs. We rely on libev's child reaping of unwatched children.
		 */
		return 0;
	}
}

static void
add_utmp_entry(main_server_st *s, struct proc_st* proc)
{
#ifdef HAVE_LIBUTIL
	struct utmpx entry;
	struct timespec tv;
	
	if (GETCONFIG(s)->use_utmp == 0)
		return;

	memset(&entry, 0, sizeof(entry));
	entry.ut_type = USER_PROCESS;
	entry.ut_pid = proc->pid;
	strlcpy(entry.ut_line, proc->tun_lease.name, sizeof(entry.ut_line));
	strlcpy(entry.ut_user, proc->username, sizeof(entry.ut_user));
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
#if defined(WTMPX_FILE)
	struct timespec tv;
#endif

	if (GETCONFIG(s)->use_utmp == 0)
		return;

	memset(&entry, 0, sizeof(entry));
	entry.ut_type = DEAD_PROCESS;
	if (proc->tun_lease.name[0] != 0)
		strlcpy(entry.ut_line, proc->tun_lease.name, sizeof(entry.ut_line));
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

	ctl_handler_notify(s,proc, 1);
	add_utmp_entry(s, proc);

	ret = call_script(s, proc, SCRIPT_CONNECT);
	if (ret < 0)
		return ret;

	return 0;
}

void user_hostname_update(main_server_st *s, struct proc_st* proc)
{
	if (proc->host_updated != 0)
		return;
	call_script(s, proc, SCRIPT_HOST_UPDATE);
	proc->host_updated = 1;
}

void user_disconnected(main_server_st *s, struct proc_st* proc)
{
	ctl_handler_notify(s,proc, 0);
	remove_utmp_entry(s, proc);
	call_script(s, proc, SCRIPT_DISCONNECT);
}

