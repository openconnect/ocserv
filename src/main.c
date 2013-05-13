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
#include <system.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <cloexec.h>
#include <script-list.h>

#include <gnutls/x509.h>
#include <tlslib.h>
#include "ipc.h"
#include "setproctitle.h"
#ifdef HAVE_LIBWRAP
# include <tcpd.h>
#endif

#include <main.h>
#include <worker.h>
#include <cookies.h>
#include <tun.h>
#include <ccan/list/list.h>

int syslog_open = 0;
static unsigned int terminate = 0;
static unsigned int reload_conf = 0;
unsigned int need_maintainance = 0;
static unsigned int need_children_cleanup = 0;

static void ms_sleep(unsigned ms)
{
  struct timespec tv;

  tv.tv_sec = 0;
  tv.tv_nsec = ms * 1000 * 1000;

  while(tv.tv_nsec >= 1000000000) {
  	tv.tv_nsec -= 1000000000;
  	tv.tv_sec++;
  }
  
  nanosleep(&tv, NULL);
}

static 
int _listen_ports(struct cfg_st* config, struct addrinfo *res, struct listen_list_st *list)
{
	struct addrinfo *ptr;
	int s, y;
	const char* type = NULL;
	char buf[512];
	struct listener_st *tmp;

	for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
		if (ptr->ai_family != AF_INET && ptr->ai_family != AF_INET6)
			continue;

		if (ptr->ai_socktype == SOCK_STREAM)
			type = "TCP";
		else if (ptr->ai_socktype == SOCK_DGRAM)
			type = "UDP";
		else
			continue;
			
		if (config->foreground != 0)
			fprintf(stderr, "listening (%s) on %s...\n",
				type, human_addr(ptr->ai_addr, ptr->ai_addrlen,
					   buf, sizeof(buf)));

		s = socket(ptr->ai_family, ptr->ai_socktype,
			   ptr->ai_protocol);
		if (s < 0) {
			perror("socket() failed");
			continue;
		}
		
#if defined(IPV6_V6ONLY)
		if (ptr->ai_family == AF_INET6) {
			y = 1;
			/* avoid listen on ipv6 addresses failing
			 * because already listening on ipv4 addresses: */
			setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
				   (const void *) &y, sizeof(y));
		}
#endif

		y = 1;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			       (const void *) &y, sizeof(y)) < 0) {
			perror("setsockopt(SO_REUSEADDR) failed");
		}

		if (ptr->ai_socktype == SOCK_DGRAM) {
#if defined(IP_DONTFRAG)
			y = 1;
			if (setsockopt(s, SOL_IP, IP_DONTFRAG,
				       (const void *) &y, sizeof(y)) < 0)
				perror("setsockopt(IP_DF) failed");
#elif defined(IP_MTU_DISCOVER)
			y = IP_PMTUDISC_DO;
			if (setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER,
				       (const void *) &y, sizeof(y)) < 0)
				perror("setsockopt(IP_DF) failed");
#endif
		}

		set_cloexec_flag (s, 1);

		if (bind(s, ptr->ai_addr, ptr->ai_addrlen) < 0) {
			perror("bind() failed");
			close(s);
			continue;
		}

		if (ptr->ai_socktype == SOCK_STREAM) {
			if (listen(s, 10) < 0) {
				perror("listen() failed");
				return -1;
			}
		}

		tmp = calloc(1, sizeof(struct listener_st));
		tmp->fd = s;
		tmp->family = ptr->ai_family;
		tmp->socktype = ptr->ai_socktype;
		tmp->protocol = ptr->ai_protocol;
		tmp->addr_len = ptr->ai_addrlen;
		memcpy(&tmp->addr, ptr->ai_addr, tmp->addr_len);

		list_add(&list->head, &(tmp->list));
		list->total++;
	}
	
	fflush(stderr);

	return 0;
}

/* Returns 0 on success or negative value on error.
 */
static int
listen_ports(struct cfg_st* config, struct listen_list_st *list, const char *node)
{
	struct addrinfo hints, *res;
	char portname[6];
	int ret;

	list_head_init(&list->head);
	list->total = 0;

	snprintf(portname, sizeof(portname), "%d", config->port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE
#ifdef AI_ADDRCONFIG
	    | AI_ADDRCONFIG
#endif
	    ;

	ret = getaddrinfo(node, portname, &hints, &res);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n",
			gai_strerror(ret));
		return -1;
	}

	ret = _listen_ports(config, res, list);
	if (ret < 0) {
		return -1;
	}

	freeaddrinfo(res);

	if (list->total == 0) {
		fprintf(stderr, "Could not listen to any TCP ports\n");
		exit(1);
	}

	snprintf(portname, sizeof(portname), "%d", config->udp_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE
#ifdef AI_ADDRCONFIG
	    | AI_ADDRCONFIG
#endif
	    ;

	ret = getaddrinfo(node, portname, &hints, &res);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n",
			gai_strerror(ret));
		return -1;
	}

	ret = _listen_ports(config, res, list);
	if (ret < 0) {
		return -1;
	}
	
	freeaddrinfo(res);

	return 0;
}

/* This is a hack. I tried to use connect() on the worker
 * and use connect() with unspec on the master process but all packets
 * were received by master. Reopening the socket seems to resolve
 * that.
 */
static
int reopen_udp_port(struct listener_st *l)
{
int s, y, e;

	close(l->fd);
	l->fd = -1;

	s = socket(l->family, l->socktype, l->protocol);
	if (s < 0) {
		perror("socket() failed");
		return -1;
	}

#if defined(IPV6_V6ONLY)
	if (l->family == AF_INET6) {
		y = 1;
		/* avoid listen on ipv6 addresses failing
		 * because already listening on ipv4 addresses: */
		setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
			   (const void *) &y, sizeof(y));
	}
#endif

	y = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *) &y, sizeof(y));

#if defined(IP_DONTFRAG)
	y = 1;
	setsockopt(s, IPPROTO_IP, IP_DONTFRAG,
		       (const void *) &y, sizeof(y));
#elif defined(IP_MTU_DISCOVER)
	y = IP_PMTUDISC_DO;
	setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER,
		       (const void *) &y, sizeof(y));
#endif
	set_cloexec_flag (s, 1);

	if (bind(s, (void*)&l->addr, l->addr_len) < 0) {
		e = errno;
		syslog(LOG_ERR, "bind() failed: %s", strerror(e));
		close(s);
		return -1;
	}
	
	l->fd = s;

	return 0;
}

static void remove_proc(main_server_st* s, struct proc_st *proc, unsigned k)
{
	if (k)
		kill(proc->pid, SIGTERM);

	user_disconnected(s, proc);

	/* close the intercomm fd */
	if (proc->fd >= 0)
		close(proc->fd);
	proc->fd = -1;
	proc->pid = -1;

	if (proc->lease)
		proc->lease->in_use = 0;
	list_del(&proc->list);
	free(proc);
	s->active_clients--;
}

static void cleanup_children(main_server_st *s)
{
int status, estatus, ret;
pid_t pid;
struct script_wait_st *stmp, *spos;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		estatus = WEXITSTATUS(status);
		
		if (pid == s->sec_mod_pid) {
			mslog(s, NULL, LOG_ERR, "ocserv-secmod died unexpectedly");
			terminate = 1;
		}

		/* check if someone was waiting for that pid */
		list_for_each_safe(&s->script_list.head, stmp, spos, list) {
			if (stmp->pid == pid) {
				mslog(s, stmp->proc, LOG_DEBUG, "%s-script exit status: %u", stmp->up?"connect":"disconnect", estatus);
				ret = handle_script_exit(s, stmp->proc, estatus);
				if (ret < 0)
					remove_proc(s, stmp->proc, 0);
				list_del(&stmp->list);
				free(stmp);
				break;
			}
		}
	
		if (estatus != 0 ||
			(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)) {
			if (WIFSIGNALED(status))
				mslog(s, NULL, LOG_ERR, "Child %u died with sigsegv\n", (unsigned)pid);
		}
	}
	need_children_cleanup = 0;
}

static void handle_children(int signo)
{
	need_children_cleanup = 1;
}

static void handle_alarm(int signo)
{
	need_maintainance = 1;
}

static void drop_privileges(main_server_st* s)
{
	int ret, e;
	struct rlimit rl;

	if (s->config->chroot_dir) {
		chdir(s->config->chroot_dir);
		ret = chroot(s->config->chroot_dir);
		if (ret != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot chroot to %s: %s", s->config->chroot_dir, strerror(e));
			exit(1);
		}
	}

	if (s->config->gid != -1 && (getgid() == 0 || getegid() == 0)) {
		ret = setgid(s->config->gid);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot set gid to %d: %s\n",
			       (int) s->config->gid, strerror(e));
			exit(1);

		}
	}

	if (s->config->uid != -1 && (getuid() == 0 || geteuid() == 0)) {
		ret = setuid(s->config->uid);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot set uid to %d: %s\n",
			       (int) s->config->uid, strerror(e));
			exit(1);

		}
	}

	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	ret = setrlimit(RLIMIT_NPROC, &rl);
	if (ret < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "cannot enforce NPROC limit: %s\n",
		       strerror(e));
	}

#define MAX_WORKER_MEM (4*1024*1024)
	if (s->config->debug == 0) {
		rl.rlim_cur = MAX_WORKER_MEM;
		rl.rlim_max = MAX_WORKER_MEM;
		ret = setrlimit(RLIMIT_AS, &rl);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot enforce AS limit: %s\n",
			       strerror(e));
		}
	}
}

/* clears the server llist and clist. To be used after fork().
 * It frees unused memory and descriptors.
 */
void clear_lists(main_server_st *s)
{
	struct listener_st *ltmp, *lpos;
	struct proc_st *ctmp, *cpos;
	struct script_wait_st *script_tmp, *script_pos;
	struct banned_st *btmp, *bpos;

	list_for_each_safe(&s->llist.head, ltmp, lpos, list) {
		close(ltmp->fd);
		list_del(&ltmp->list);
		free(ltmp);
		s->llist.total--;
	}

	list_for_each_safe(&s->clist.head, ctmp, cpos, list) {
		if (ctmp->fd >= 0)
			close(ctmp->fd);
		list_del(&ctmp->list);
		memset(ctmp, 0, sizeof(*ctmp));
		free(ctmp);
		s->clist.total--;
	}

	list_for_each_safe(&s->ban_list.head, btmp, bpos, list) {
		list_del(&btmp->list);
		free(btmp);
	}

	list_for_each_safe(&s->script_list.head, script_tmp, script_pos, list) {
		list_del(&script_tmp->list);
		free(script_tmp);
	}

	tls_cache_deinit(s->tls_db);
}

static void kill_children(main_server_st* s)
{
	struct proc_st *ctmp;

	/* kill the security module server */
	kill(s->sec_mod_pid, SIGTERM);
	list_for_each(&s->clist.head, ctmp, list) {
		if (ctmp->pid != -1) {
			kill(ctmp->pid, SIGTERM);
			user_disconnected(s, ctmp);
		}
	}
}

static void handle_term(int signo)
{
	/* kill all children */
	terminate = 1;
}

static void handle_reload(int signo)
{
	reload_conf = 1;
}


#define RECORD_PAYLOAD_POS 13
#define HANDSHAKE_SESSION_ID_POS 46
static int forward_udp_to_owner(main_server_st* s, struct listener_st *listener)
{
int ret, e;
struct sockaddr_storage cli_addr;
struct proc_st *ctmp;
socklen_t cli_addr_size;
uint8_t buffer[1024];
uint8_t  *session_id;
int session_id_size;
ssize_t buffer_size;
int connected = 0;

	/* first receive from the correct client and connect socket */
	cli_addr_size = sizeof(cli_addr);
	ret = recvfrom(listener->fd, buffer, sizeof(buffer), MSG_PEEK, (void*)&cli_addr, &cli_addr_size);
	if (ret < 0) {
		mslog(s, NULL, LOG_INFO, "error receiving in UDP socket");
		return -1;
	}
	
	buffer_size = ret;
	
	/* obtain the session id */
	if (buffer_size < RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS+GNUTLS_MAX_SESSION_ID+2)
		goto fail;

	/* check version */
	mslog(s, NULL, LOG_DEBUG, "DTLS record version: %u.%u", (unsigned int)buffer[1], (unsigned int)buffer[2]);
	mslog(s, NULL, LOG_DEBUG, "DTLS hello version: %u.%u", (unsigned int)buffer[RECORD_PAYLOAD_POS], (unsigned int)buffer[RECORD_PAYLOAD_POS+1]);
	if (buffer[1] != 254 && (buffer[1] != 1 && buffer[2] != 0) &&
		buffer[RECORD_PAYLOAD_POS] != 254 && (buffer[RECORD_PAYLOAD_POS] != 0 && buffer[RECORD_PAYLOAD_POS+1] != 0)) {
		mslog(s, NULL, LOG_INFO, "unknown DTLS version: %u.%u", (unsigned)buffer[1], (unsigned)buffer[2]);
		goto fail;
	}
	if (buffer[0] != 22) {
		mslog(s, NULL, LOG_INFO, "unexpected DTLS content type: %u", (unsigned int)buffer[0]);
		goto fail;
	}

	/* read session_id */
	session_id_size = buffer[RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS];
	session_id = &buffer[RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS+1];

	/* search for the IP and the session ID in all procs */

	list_for_each(&s->clist.head, ctmp, list) {
		if (session_id_size == ctmp->session_id_size &&
			memcmp(session_id, ctmp->session_id, session_id_size) == 0) {

			ret = connect(listener->fd, (void*)&cli_addr, cli_addr_size);
			if (ret == -1) {
				e = errno;
				mslog(s, ctmp, LOG_ERR, "connect UDP socket: %s", strerror(e));
				return -1;
			}

			ret = send_udp_fd(s, ctmp, listener->fd);
			if (ret < 0) {
				mslog(s, ctmp, LOG_ERR, "error passing UDP socket");
				return -1;
			}
			mslog(s, ctmp, LOG_DEBUG, "passed UDP socket");
			ctmp->udp_fd_received = 1;
			connected = 1;
			
			reopen_udp_port(listener);
			break;
		}
	}

fail:
	if (connected == 0) {
		/* received packet from unknown host */
		recv(listener->fd, buffer, buffer_size, 0);

		return -1;
	}
	
	return 0;

}

#define MAINTAINANCE_TIME(s) ((s)->config->cookie_validity + 300)

static void check_other_work(main_server_st *s)
{
	if (reload_conf != 0) {
		mslog(s, NULL, LOG_INFO, "HUP signal was received; reloading configuration");
		reload_cfg_file(s->config);
		reload_conf = 0;
	}

	if (need_children_cleanup != 0) {
		cleanup_children(s);
	}

	if (terminate != 0) {
		mslog(s, NULL, LOG_DEBUG, "termination signal received; waiting for children to die");
		kill_children(s);
		closelog();
		remove(s->socket_file);
		remove_pid_file();
		while (waitpid(-1, NULL, 0) > 0);
		exit(0);
	}

	/* Check if we need to expire any cookies */
	if (need_maintainance != 0) {
		need_maintainance = 0;
		mslog(s, NULL, LOG_INFO, "Performing maintainance");
		expire_tls_sessions(s);
		expire_cookies(s);
		expire_banned(s);
		alarm(MAINTAINANCE_TIME(s));
	}
}

#ifdef HAVE_LIBWRAP
static int check_tcp_wrapper(int fd)
{
	struct request_info req;
	
	if (request_init(&req, RQ_FILE, fd, RQ_DAEMON, PACKAGE_NAME, 0) == NULL)
		return -1;
	
	sock_host(&req);
	if (hosts_access(&req) == 0)
		return -1;
		
	return 0;
}
#else
# define check_tcp_wrapper(x) 0
#endif

int main(int argc, char** argv)
{
	int fd, pid, e;
	struct listener_st *ltmp;
	struct proc_st *ctmp, *cpos;
	struct tun_st tun;
	fd_set rd;
	int val, n = 0, ret, flags;
	struct timeval tv;
	int cmd_fd[2];
	struct worker_st ws;
	struct cfg_st config;
	unsigned set;
	main_server_st s;

	memset(&s, 0, sizeof(s));

	list_head_init(&s.clist.head);
	list_head_init(&s.ban_list.head);
	list_head_init(&s.script_list.head);
	tun_st_init(&tun);
	tls_cache_init(&s.tls_db);

	ocsignal(SIGINT, handle_term);
	ocsignal(SIGTERM, handle_term);
	ocsignal(SIGPIPE, SIG_IGN);
	ocsignal(SIGHUP, handle_reload);
	ocsignal(SIGCHLD, handle_children);
	ocsignal(SIGALRM, handle_alarm);

	/* Initialize GnuTLS */
	tls_global_init(&s);

	/* load configuration */
	ret = cmd_parser(argc, argv, &config);
	if (ret < 0) {
		fprintf(stderr, "Error in arguments\n");
		exit(1);
	}

	setproctitle(PACKAGE_NAME"-main");

	if (getuid() != 0) {
		fprintf(stderr, "This server requires root access to operate.\n");
		exit(1);
	}

	s.config = &config;
	s.tun = &tun;

	ret = cookie_db_init(&s);
	if (ret < 0) {
		fprintf(stderr, "Could not initialize cookie database.\n");
		exit(1);
	}
	
	/* Listen to network ports */
	ret = listen_ports(&config, &s.llist, config.name);
	if (ret < 0) {
		fprintf(stderr, "Cannot listen to specified ports\n");
		exit(1);
	}

	flags = LOG_PID|LOG_NDELAY;
#ifdef LOG_PERROR
	if (config.debug != 0)
		flags |= LOG_PERROR;
#endif
	openlog("ocserv", flags, LOG_DAEMON);
	syslog_open = 1;
#ifdef HAVE_LIBWRAP
	allow_severity = LOG_DAEMON|LOG_INFO;
	deny_severity = LOG_DAEMON|LOG_WARNING;
#endif	
	memset(&ws, 0, sizeof(ws));

	if (config.foreground == 0) {
		if (daemon(0, 0) == -1) {
			e = errno;
			fprintf(stderr, "daemon failed: %s\n", strerror(e));
			exit(1);
		}
	}

	write_pid_file();
	
	run_sec_mod(&s);

	/* Initialize certificates */
	tls_global_init_certs(&s);

	alarm(MAINTAINANCE_TIME(&s));

	for (;;) {
		check_other_work(&s);

		/* initialize select */
		FD_ZERO(&rd);

		list_for_each(&s.llist.head, ltmp, list) {
			if (ltmp->fd == -1) continue;

			val = fcntl(ltmp->fd, F_GETFL, 0);
			if ((val == -1)
			    || (fcntl(ltmp->fd, F_SETFL, val | O_NONBLOCK) <
				0)) {
				e = errno;
				mslog(&s, NULL, LOG_ERR, "fcntl() error: %s", strerror(e));
				exit(1);
			}

			FD_SET(ltmp->fd, &rd);
			n = MAX(n, ltmp->fd);
		}

		list_for_each(&s.clist.head, ctmp, list) {
			FD_SET(ctmp->fd, &rd);
			n = MAX(n, ctmp->fd);
		}

		tv.tv_usec = 0;
		tv.tv_sec = 30;
		ret = select(n + 1, &rd, NULL, NULL, &tv);
		if (ret == -1 && errno == EINTR)
			continue;

		if (ret < 0) {
			e = errno;
			mslog(&s, NULL, LOG_ERR, "Error in select(): %s",
			       strerror(e));
			exit(1);
		}

		/* Check for new connections to accept */
		list_for_each(&s.llist.head, ltmp, list) {
			set = FD_ISSET(ltmp->fd, &rd);
			if (set && ltmp->socktype == SOCK_STREAM) {
				/* connection on TCP port */
				ws.remote_addr_len = sizeof(ws.remote_addr);
				fd = accept(ltmp->fd, (void*)&ws.remote_addr, &ws.remote_addr_len);
				if (fd < 0) {
					mslog(&s, NULL, LOG_ERR,
					       "Error in accept(): %s", strerror(errno));
					continue;
				}
				set_cloexec_flag (fd, 1);

				/* Check if the client is on the banned list */
				ret = check_if_banned(&s, &ws.remote_addr, ws.remote_addr_len);
				if (ret < 0) {
					/* banned */
					close(fd);
					mslog(&s, NULL, LOG_INFO, "dropping client connection due to a previous failed authentication attempt");
					break;
				}

				if (config.max_clients > 0 && s.active_clients >= config.max_clients) {
					close(fd);
					mslog(&s, NULL, LOG_INFO, "Reached maximum client limit (active: %u)", s.active_clients);
					break;
				}

				if (check_tcp_wrapper(fd) < 0) {
					close(fd);
					mslog(&s, NULL, LOG_INFO, "TCP wrappers rejected the connection (see /etc/hosts.[allow|deny])");
					break;
				}

				/* Create a command socket */
				ret = socketpair(AF_UNIX, SOCK_STREAM, 0, cmd_fd);
				if (ret < 0) {
					mslog(&s, NULL, LOG_ERR, "Error creating command socket");
					close(fd);
					break;
				}

				pid = fork();
				if (pid == 0) {	/* child */
					/* close any open descriptors, and erase
					 * sensitive data before running the worker
					 */
					close(cmd_fd[0]);
					clear_lists(&s);
					erase_cookies(&s);

					setproctitle(PACKAGE_NAME"-worker");
					kill_on_parent_kill(SIGTERM);

					ws.config = &config;
					ws.cmd_fd = cmd_fd[1];
					ws.tun_fd = -1;
					ws.udp_fd = -1;
					ws.conn_fd = fd;
					ws.creds = &s.creds;

					/* Drop privileges after this point */
					drop_privileges(&s);

					vpn_server(&ws);
					exit(0);
				} else if (pid == -1) {
fork_failed:
					close(cmd_fd[0]);
				} else { /* parent */
					/* add_proc */
					ctmp = calloc(1, sizeof(struct proc_st));
					if (ctmp == NULL) {
						kill(pid, SIGTERM);
						goto fork_failed;
					}
					memcpy(&ctmp->remote_addr, &ws.remote_addr, ws.remote_addr_len);
					ctmp->remote_addr_len = ws.remote_addr_len;

					ctmp->pid = pid;
					ctmp->fd = cmd_fd[0];
					set_cloexec_flag (cmd_fd[0], 1);

					list_add(&s.clist.head, &(ctmp->list));
					s.active_clients++;
				}
				close(cmd_fd[1]);
				close(fd);

				if (config.rate_limit_ms > 0)
					ms_sleep(config.rate_limit_ms);
			} else if (set && ltmp->socktype == SOCK_DGRAM) {
				/* connection on UDP port */
				ret = forward_udp_to_owner(&s, ltmp);
				if (ret < 0) {
					mslog(&s, NULL, LOG_INFO, "could not determine the owner of received UDP packet");
				}

				if (config.rate_limit_ms > 0)
					ms_sleep(config.rate_limit_ms);
			}
		}

		/* Check for any pending commands */
		list_for_each_safe(&s.clist.head, ctmp, cpos, list) {
			if (FD_ISSET(ctmp->fd, &rd)) {
				ret = handle_commands(&s, ctmp);
				if (ret < 0) {
					remove_from_script_list(&s, ctmp);
					remove_proc(&s, ctmp, (ret==ERR_BAD_COMMAND)?1:0);
				}
			}
		}

	}

	return 0;
}
