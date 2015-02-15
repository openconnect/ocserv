/*
 * Copyright (C) 2013-2015 Nikos Mavrogiannopoulos
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
#include <system.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cloexec.h>
#ifdef HAVE_MALLOC_TRIM
# include <malloc.h> /* for malloc_trim() */
#endif
#include <script-list.h>

#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#include "setproctitle.h"
#ifdef HAVE_LIBWRAP
# include <tcpd.h>
#endif

#ifdef HAVE_LIBSYSTEMD
# include <systemd/sd-daemon.h>
#endif
#include <main.h>
#include <main-ctl.h>
#include <route-add.h>
#include <worker.h>
#include <cookies.h>
#include <proc-search.h>
#include <tun.h>
#include <grp.h>
#include <ip-lease.h>
#include <ccan/list/list.h>

int syslog_open = 0;
static unsigned int terminate = 0;
static unsigned int reload_conf = 0;
unsigned int need_maintenance = 0;
static unsigned int need_children_cleanup = 0;
sigset_t sig_default_set;

static void add_listener(void *pool, struct listen_list_st *list,
	int fd, int family, int socktype, int protocol,
	struct sockaddr* addr, socklen_t addr_len)
{
	struct listener_st *tmp;

	tmp = talloc_zero(pool, struct listener_st);
	tmp->fd = fd;
	tmp->family = family;
	tmp->sock_type = socktype;
	tmp->protocol = protocol;

	tmp->addr_len = addr_len;
	memcpy(&tmp->addr, addr, addr_len);

	list_add(&list->head, &(tmp->list));
	list->total++;
}

static void set_udp_socket_options(struct cfg_st* config, int fd, int family)
{
int y;
	if (config->try_mtu) {
#if defined(IP_DONTFRAG)
		y = 1;
		if (setsockopt(fd, SOL_IP, IP_DONTFRAG,
			       (const void *) &y, sizeof(y)) < 0)
			perror("setsockopt(IP_DF) failed");
#elif defined(IP_MTU_DISCOVER)
		y = IP_PMTUDISC_DO;
		if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER,
		       (const void *) &y, sizeof(y)) < 0)
			perror("setsockopt(IP_DF) failed");
#endif
	}
#if defined(IP_PKTINFO)
	y = 1;
	if (setsockopt(fd, SOL_IP, IP_PKTINFO,
		       (const void *)&y, sizeof(y)) < 0)
		perror("setsockopt(IP_PKTINFO) failed");
#elif defined(IP_RECVDSTADDR) /* *BSD */
	y = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR,
		       (const void *)&y, sizeof(y)) < 0)
		perror("setsockopt(IP_RECVDSTADDR) failed");
#endif
#if defined(IPV6_RECVPKTINFO)
	if (family == AF_INET6) {
		y = 1;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
			       (const void *)&y, sizeof(y)) < 0)
			perror("setsockopt(IPV6_RECVPKTINFO) failed");
	}
#endif
}

static void set_common_socket_options(int fd)
{
	set_non_block(fd);
	set_cloexec_flag (fd, 1);
}

static 
int _listen_ports(void *pool, struct cfg_st* config, 
		struct addrinfo *res, struct listen_list_st *list)
{
	struct addrinfo *ptr;
	int s, y;
	const char* type = NULL;
	char buf[512];

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
			set_udp_socket_options(config, s, ptr->ai_family);
		}


		if (bind(s, ptr->ai_addr, ptr->ai_addrlen) < 0) {
			perror("bind() failed");
			close(s);
			continue;
		}

		if (ptr->ai_socktype == SOCK_STREAM) {
			if (listen(s, 1024) < 0) {
				perror("listen() failed");
				close(s);
				return -1;
			}
		}

		set_common_socket_options(s);

		add_listener(pool, list, s, ptr->ai_family, ptr->ai_socktype==SOCK_STREAM?SOCK_TYPE_TCP:SOCK_TYPE_UDP,
			ptr->ai_protocol, ptr->ai_addr, ptr->ai_addrlen);

	}

	fflush(stderr);

	return 0;
}

static 
int _listen_unix_ports(void *pool, struct cfg_st* config, 
		       struct listen_list_st *list)
{
	int s, e, ret;
	struct sockaddr_un sa;

	/* open the UNIX domain socket to accept connections */
	if (config->unix_conn_file) {
		memset(&sa, 0, sizeof(sa));
		sa.sun_family = AF_UNIX;
		strlcpy(sa.sun_path, config->unix_conn_file, sizeof(sa.sun_path));
		remove(sa.sun_path);

		if (config->foreground != 0)
			fprintf(stderr, "listening (UNIX) on %s...\n",
				sa.sun_path);

		s = socket(AF_UNIX, SOCK_STREAM, 0);
		if (s == -1) {
			e = errno;
			fprintf(stderr, "could not create socket '%s': %s", sa.sun_path,
			       strerror(e));
			return -1;
		}

		umask(006);
		ret = bind(s, (struct sockaddr *)&sa, SUN_LEN(&sa));
		if (ret == -1) {
			e = errno;
			fprintf(stderr, "could not bind socket '%s': %s", sa.sun_path,
			       strerror(e));
			return -1;
		}

		ret = chown(sa.sun_path, config->uid, config->gid);
		if (ret == -1) {
			e = errno;
			fprintf(stderr, "could not chown socket '%s': %s", sa.sun_path,
			       strerror(e));
		}

		ret = listen(s, 1024);
		if (ret == -1) {
			e = errno;
			fprintf(stderr, "could not listen to socket '%s': %s",
			       sa.sun_path, strerror(e));
			exit(1);
		}
		add_listener(pool, list, s, AF_UNIX, SOCK_TYPE_UNIX, 0, (struct sockaddr *)&sa, sizeof(sa));
	}
	fflush(stderr);

	return 0;
}

/* Returns 0 on success or negative value on error.
 */
static int
listen_ports(void *pool, struct cfg_st* config, 
		struct listen_list_st *list)
{
	struct addrinfo hints, *res;
	char portname[6];
	int ret;
#ifdef HAVE_LIBSYSTEMD
	int fds;
#endif

	list_head_init(&list->head);
	list->total = 0;

#ifdef HAVE_LIBSYSTEMD
	/* Support for systemd socket-activatable service */
	if ((fds=sd_listen_fds(0)) > 0) {
		/* if we get our fds from systemd */
		unsigned i;
		int family, type, fd;
		struct sockaddr_storage tmp_sock;
		socklen_t tmp_sock_len;

		for (i=0;i<fds;i++) {
			fd = SD_LISTEN_FDS_START+i;

			if (sd_is_socket(fd, AF_INET, 0, -1))
				family = AF_INET;
			else if (sd_is_socket(fd, AF_INET6, 0, -1))
				family = AF_INET6;
			else {
				fprintf(stderr, "Non-internet socket fd received!\n");
				continue;
			}

			if (sd_is_socket(fd, 0, SOCK_STREAM, -1))
				type = SOCK_STREAM;
			else if (sd_is_socket(fd, 0, SOCK_DGRAM, -1))
				type = SOCK_DGRAM;
			else {
				fprintf(stderr, "Non-TCP or UDP socket fd received!\n");
				continue;
			}

			if (type == SOCK_DGRAM)
				set_udp_socket_options(config, fd, family);

			/* obtain socket params */
			tmp_sock_len = sizeof(tmp_sock);
			ret = getsockname(fd, (struct sockaddr*)&tmp_sock, &tmp_sock_len);
			if (ret == -1) {
				perror("getsockname failed");
				continue;
			}

			set_common_socket_options(fd);

			if (type == SOCK_STREAM) {
				if (family == AF_INET)
					config->port = ntohs(((struct sockaddr_in*)&tmp_sock)->sin_port);
				else
					config->port = ntohs(((struct sockaddr_in6*)&tmp_sock)->sin6_port);
			} else if (type == SOCK_DGRAM) {
				if (family == AF_INET)
					config->udp_port = ntohs(((struct sockaddr_in*)&tmp_sock)->sin_port);
				else
					config->udp_port = ntohs(((struct sockaddr_in6*)&tmp_sock)->sin6_port);
			}

			add_listener(pool, list, fd, family, type==SOCK_STREAM?SOCK_TYPE_TCP:SOCK_TYPE_UDP, 0, (struct sockaddr*)&tmp_sock, tmp_sock_len);
		}

		if (list->total == 0) {
			fprintf(stderr, "no useful sockets were provided by systemd\n");
			exit(1);
		}

		if (config->foreground != 0)
			fprintf(stderr, "listening on %d systemd sockets...\n", list->total);

		return 0;
	}
#endif

	if (config->port == 0 && config->unix_conn_file == NULL) {
		fprintf(stderr, "tcp-port option is mandatory!\n");
		return -1;
	}

	if (config->port != 0) {
		snprintf(portname, sizeof(portname), "%d", config->port);

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE
#ifdef AI_ADDRCONFIG
		    | AI_ADDRCONFIG
#endif
		    ;

		ret = getaddrinfo(config->name, portname, &hints, &res);
		if (ret != 0) {
			fprintf(stderr, "getaddrinfo() failed: %s\n",
				gai_strerror(ret));
			return -1;
		}

		ret = _listen_ports(pool, config, res, list);
		if (ret < 0) {
			return -1;
		}

		freeaddrinfo(res);
	}

	ret = _listen_unix_ports(pool, config, list);
	if (ret < 0) {
		return -1;
	}

	if (list->total == 0) {
		fprintf(stderr, "Could not listen to any TCP or UNIX ports\n");
		exit(1);
	}

	if (config->udp_port) {
		snprintf(portname, sizeof(portname), "%d", config->udp_port);

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE
#ifdef AI_ADDRCONFIG
		    | AI_ADDRCONFIG
#endif
		    ;

		ret = getaddrinfo(config->name, portname, &hints, &res);
		if (ret != 0) {
			fprintf(stderr, "getaddrinfo() failed: %s\n",
				gai_strerror(ret));
			return -1;
		}

		ret = _listen_ports(pool, config, res, list);
		if (ret < 0) {
			return -1;
		}

		freeaddrinfo(res);
	}

	return 0;
}

/* Sets the options needed in the UDP socket we forward to
 * worker */
static
void set_worker_udp_opts(int fd, int family)
{
int y;

#ifdef IPV6_V6ONLY
	if (family == AF_INET6) {
		y = 1;
		/* avoid listen on ipv6 addresses failing
		 * because already listening on ipv4 addresses: */
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
			   (const void *) &y, sizeof(y));
	}
#endif

	y = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &y, sizeof(y));

#if defined(IP_DONTFRAG)
	y = 1;
	setsockopt(fd, IPPROTO_IP, IP_DONTFRAG,
		       (const void *) &y, sizeof(y));
#elif defined(IP_MTU_DISCOVER)
	y = IP_PMTUDISC_DO;
	setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER,
		       (const void *) &y, sizeof(y));
#endif
	set_cloexec_flag (fd, 1);

	return;
}


static void cleanup_children(main_server_st *s)
{
int status, estatus, ret;
pid_t pid;
struct script_wait_st *stmp = NULL, *spos;

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
				list_del(&stmp->list);
				ret = handle_script_exit(s, stmp->proc, estatus);
				if (ret < 0) {
					remove_proc(s, stmp->proc, 1);
				} else {
					talloc_free(stmp);
				}
				break;
			}
		}

		if (WIFSIGNALED(status)) {
			if (WTERMSIG(status) == SIGSEGV)
				mslog(s, NULL, LOG_ERR, "Child %u died with sigsegv\n", (unsigned)pid);
			else if (WTERMSIG(status) == SIGSYS)
				mslog(s, NULL, LOG_ERR, "Child %u died with sigsys\n", (unsigned)pid);
			else
				mslog(s, NULL, LOG_ERR, "Child %u died with signal %d\n", (unsigned)pid, (int)WTERMSIG(status));
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
	need_maintenance = 1;
}

static void drop_privileges(main_server_st* s)
{
	int ret, e;
	struct rlimit rl;

	if (s->config->chroot_dir) {
		ret = chdir(s->config->chroot_dir);
		if (ret != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot chdir to %s: %s", s->config->chroot_dir, strerror(e));
			exit(1);
		}

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

		ret = setgroups(1, &s->config->gid);
		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot set groups to %d: %s\n",
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

#if 0
	rl.rlim_cur = 0;
	rl.rlim_max = 0;
	ret = setrlimit(RLIMIT_FSIZE, &rl);
	if (ret < 0) {
		e = errno;
		mslog(s, NULL, LOG_ERR, "cannot enforce FSIZE limit: %s\n",
		       strerror(e));
	}

#define MAX_WORKER_MEM (16*1024*1024)
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
#endif
}

/* clears the server listen_list and proc_list. To be used after fork().
 * It frees unused memory and descriptors.
 */
void clear_lists(main_server_st *s)
{
	struct listener_st *ltmp = NULL, *lpos;
	struct proc_st *ctmp = NULL, *cpos;
	struct script_wait_st *script_tmp = NULL, *script_pos;

	list_for_each_safe(&s->listen_list.head, ltmp, lpos, list) {
		close(ltmp->fd);
		list_del(&ltmp->list);
		talloc_free(ltmp);
		s->listen_list.total--;
	}

	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		if (ctmp->fd >= 0)
			close(ctmp->fd);
		if (ctmp->tun_lease.fd >= 0)
			close(ctmp->tun_lease.fd);
		list_del(&ctmp->list);
		safe_memset(ctmp, 0, sizeof(*ctmp));
		talloc_free(ctmp);
		s->proc_list.total--;
	}

	list_for_each_safe(&s->script_list.head, script_tmp, script_pos, list) {
		list_del(&script_tmp->list);
		talloc_free(script_tmp);
	}

	tls_cache_deinit(&s->tls_db);
	ip_lease_deinit(&s->ip_leases);
	proc_table_deinit(s);
	ctl_handler_deinit(s);
}

static void kill_children(main_server_st* s)
{
	struct proc_st *ctmp = NULL, *cpos;

	/* kill the security module server */
	kill(s->sec_mod_pid, SIGTERM);
	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		if (ctmp->pid != -1) {
			remove_proc(s, ctmp, 1);
		}
	}
}

void request_stop(int signo)
{
	/* kill all children */
	terminate = 1;
}

void request_reload(int signo)
{
	reload_conf = 1;
}


/* A UDP fd will not be forwarded to worker process before this number of
 * seconds has passed. That is to prevent a duplicate message messing the worker.
 */
#define UDP_FD_RESEND_TIME 60

#define RECORD_PAYLOAD_POS 13
#define HANDSHAKE_SESSION_ID_POS 46
static int forward_udp_to_owner(main_server_st* s, struct listener_st *listener)
{
int ret, e;
struct sockaddr_storage cli_addr;
struct sockaddr_storage our_addr;
struct proc_st *proc_to_send = NULL;
socklen_t cli_addr_size, our_addr_size;
uint8_t buffer[1536];
char tbuf[64];
uint8_t  *session_id = NULL;
int session_id_size = 0;
ssize_t buffer_size;
int match_ip_only = 0;
time_t now;
int sfd = -1;

	/* first receive from the correct client and connect socket */
	cli_addr_size = sizeof(cli_addr);
	our_addr_size = sizeof(our_addr);
	ret = oc_recvfrom_at(listener->fd, buffer, sizeof(buffer), 0,
			  (struct sockaddr*)&cli_addr, &cli_addr_size,
			  (struct sockaddr*)&our_addr, &our_addr_size,
			  s->config->udp_port);
	if (ret < 0) {
		mslog(s, NULL, LOG_INFO, "error receiving in UDP socket");
		return -1;
	}
	buffer_size = ret;

	/* obtain the session id */
	if (buffer_size < RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS+GNUTLS_MAX_SESSION_ID+2) {
		mslog(s, NULL, LOG_INFO, "%s: too short UDP packet",
		      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)));
		goto fail;
	}

	/* check version */
	if (buffer[0] == 22) {
		mslog(s, NULL, LOG_DEBUG, "new DTLS session from %s (record v%u.%u, hello v%u.%u)", 
			human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)),
			(unsigned int)buffer[1], (unsigned int)buffer[2],
			(unsigned int)buffer[RECORD_PAYLOAD_POS], (unsigned int)buffer[RECORD_PAYLOAD_POS+1]);
	}

	if (buffer[1] != 254 && (buffer[1] != 1 && buffer[2] != 0) &&
		buffer[RECORD_PAYLOAD_POS] != 254 && (buffer[RECORD_PAYLOAD_POS] != 0 && buffer[RECORD_PAYLOAD_POS+1] != 0)) {
		mslog(s, NULL, LOG_INFO, "%s: unknown DTLS record version: %u.%u", 
		      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)),
		      (unsigned)buffer[1], (unsigned)buffer[2]);
		goto fail;
	}

	if (buffer[0] != 22) {
		mslog(s, NULL, LOG_DEBUG, "%s: unexpected DTLS content type: %u; possibly a firewall disassociated a UDP session",
		      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)),
		      (unsigned int)buffer[0]);
		/* Here we received a non-client hello packet. It may be that
		 * the client's NAT changed its UDP source port and the previous
		 * connection is invalidated. Try to see if we can simply match
		 * the IP address and forward the socket.
		 */
		match_ip_only = 1;

		/* don't bother IP matching when the listen-clear-file is in use */
		if (s->config->unix_conn_file)
			goto fail;
	} else {
		/* read session_id */
		session_id_size = buffer[RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS];
		session_id = &buffer[RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS+1];
	}

	/* search for the IP and the session ID in all procs */
	now = time(0);

	if (match_ip_only == 0) {
		proc_to_send = proc_search_dtls_id(s, session_id, session_id_size);
	} else {
		proc_to_send = proc_search_ip(s, &cli_addr, cli_addr_size);
	}

	if (proc_to_send != 0) {
		UdpFdMsg msg = UDP_FD_MSG__INIT;

		if (now - proc_to_send->udp_fd_receive_time <= UDP_FD_RESEND_TIME) {
			mslog(s, proc_to_send, LOG_DEBUG, "received UDP connection too soon from %s",
			      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)));
			goto fail;
		}

		sfd = socket(listener->family, SOCK_DGRAM, listener->protocol);
		if (sfd < 0) {
			e = errno;
			mslog(s, proc_to_send, LOG_ERR, "new UDP socket failed: %s",
			      strerror(e));
			goto fail;
		}

		set_worker_udp_opts(sfd, listener->family);

		if (our_addr_size > 0) {
			ret = bind(sfd, (struct sockaddr *)&our_addr, our_addr_size);
			if (ret == -1) {
				e = errno;
				mslog(s, proc_to_send, LOG_ERR, "bind UDP to %s: %s",
				      human_addr((struct sockaddr*)&listener->addr, listener->addr_len, tbuf, sizeof(tbuf)),
				      strerror(e));
			}
		}

		ret = connect(sfd, (void*)&cli_addr, cli_addr_size);
		if (ret == -1) {
			e = errno;
			mslog(s, proc_to_send, LOG_ERR, "connect UDP socket from %s: %s",
			      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)),
			      strerror(e));
			goto fail;
		}

		if (match_ip_only != 0) {
			msg.hello = 0;
		} else {
			msg.has_data = 1;
		}
		msg.data.data = buffer;
		msg.data.len = buffer_size;

		ret = send_socket_msg_to_worker(s, proc_to_send, CMD_UDP_FD,
			sfd,
			&msg, 
			(pack_size_func)udp_fd_msg__get_packed_size,
			(pack_func)udp_fd_msg__pack);
		if (ret < 0) {
			mslog(s, proc_to_send, LOG_ERR, "error passing UDP socket from %s",
			      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)));
			goto fail;
		}
		mslog(s, proc_to_send, LOG_DEBUG, "passed UDP socket from %s",
		      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)));
		proc_to_send->udp_fd_receive_time = now;
	}

fail:
	if (sfd != -1)
		close(sfd);

	return 0;

}

#define MAINTAINANCE_TIME(s) (900)

static void check_other_work(main_server_st *s)
{
unsigned total = 10;

	if (reload_conf != 0) {
		mslog(s, NULL, LOG_INFO, "reloading configuration");
		reload_cfg_file(s->main_pool, s->config);
		tls_reload_crl(s, s->creds);
		reload_conf = 0;
		kill(s->sec_mod_pid, SIGHUP);
	}

	if (need_children_cleanup != 0) {
		cleanup_children(s);
	}

	if (terminate != 0) {
		mslog(s, NULL, LOG_INFO, "termination request received; waiting for children to die");
		kill_children(s);
		remove(s->full_socket_file);
		remove(s->config->occtl_socket_file);
		remove_pid_file();

		while (waitpid(-1, NULL, WNOHANG) >= 0) {
			if (total == 0) {
				mslog(s, NULL, LOG_INFO, "not everyone died; forcing kill");
				kill(0, SIGKILL);
			}
			ms_sleep(500);
			total--;
		}

		/* try to clean-up everything allocated to ease checks 
		 * for memory leaks.
		 */
		clear_lists(s);
		tls_global_deinit(s->creds);
		clear_cfg_file(s->config);
		talloc_free(s->config);
		talloc_free(s->main_pool);
		closelog();
		exit(0);
	}

	/* Check if we need to expire any cookies */
	if (need_maintenance != 0) {
		need_maintenance = 0;
		mslog(s, NULL, LOG_DEBUG, "performing maintenance");
		expire_tls_sessions(s);
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

typedef pid_t (*fork_func)(void);

int main(int argc, char** argv)
{
	int fd, pid, e;
	struct listener_st *ltmp = NULL;
	struct proc_st *ctmp = NULL, *cpos;
	fd_set rd_set, wr_set;
	int n = 0, ret, flags;
	char *p;
#ifdef HAVE_PSELECT
	struct timespec ts;
#else
	struct timeval ts;
#endif
	int cmd_fd[2];
	struct worker_st *ws;
	void *worker_pool;
	void *main_pool;
	unsigned set;
	main_server_st *s;
	sigset_t emptyset, blockset;
	/* tls credentials */
	struct tls_st creds;
	fork_func our_fork = fork;

#ifdef DEBUG_LEAKS
	talloc_enable_leak_report_full();
#endif

	memset(&creds, 0, sizeof(creds));

	/* main pool */
	main_pool = talloc_init("main");
	if (main_pool == NULL) {
		fprintf(stderr, "talloc init error\n");
		exit(1);
	}

	s = talloc_zero(main_pool, main_server_st);
	if (s == NULL) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}
	s->main_pool = main_pool;
	s->creds = &creds;
	s->start_time = time(0);

	list_head_init(&s->proc_list.head);
	list_head_init(&s->script_list.head);
	tls_cache_init(s, &s->tls_db);
	ip_lease_init(&s->ip_leases);
	proc_table_init(s);

	sigemptyset(&blockset);
	sigemptyset(&emptyset);
	sigaddset(&blockset, SIGALRM);
	sigaddset(&blockset, SIGTERM);
	sigaddset(&blockset, SIGINT);
	sigaddset(&blockset, SIGCHLD);
	sigaddset(&blockset, SIGHUP);

	ocsignal(SIGINT, request_stop);
	ocsignal(SIGTERM, request_stop);
	ocsignal(SIGPIPE, SIG_IGN);
	ocsignal(SIGHUP, request_reload);
	ocsignal(SIGCHLD, handle_children);
	ocsignal(SIGALRM, handle_alarm);

	/* Initialize GnuTLS */
	tls_global_init(&creds);

	/* this is the key used to sign and verify cookies. It is used
	 * by sec-mod (for signing) and main (for verification). */
	ret = gnutls_rnd(GNUTLS_RND_RANDOM, s->cookie_key, sizeof(s->cookie_key));
	if (ret < 0) {
		fprintf(stderr, "Error in cookie key generation\n");
		exit(1);
	}

	/* load configuration */
	ret = cmd_parser(main_pool, argc, argv, &s->config);
	if (ret < 0) {
		fprintf(stderr, "Error in arguments\n");
		exit(1);
	}

	setproctitle(PACKAGE_NAME"-main");

	if (getuid() != 0) {
		fprintf(stderr, "This server requires root access to operate.\n");
		exit(1);
	}

	/* Listen to network ports */
	ret = listen_ports(s, s->config, &s->listen_list);
	if (ret < 0) {
		fprintf(stderr, "Cannot listen to specified ports\n");
		exit(1);
	}

	flags = LOG_PID|LOG_NDELAY;
#ifdef LOG_PERROR
	if (s->config->debug != 0)
		flags |= LOG_PERROR;
#endif
	openlog("ocserv", flags, LOG_DAEMON);
	syslog_open = 1;
#ifdef HAVE_LIBWRAP
	allow_severity = LOG_DAEMON|LOG_INFO;
	deny_severity = LOG_DAEMON|LOG_WARNING;
#endif

	if (s->config->foreground == 0) {
		if (daemon(0, 0) == -1) {
			e = errno;
			fprintf(stderr, "daemon failed: %s\n", strerror(e));
			exit(1);
		}
	}

	/* override the default fork function */
	if (s->config->isolate)
		our_fork = safe_fork;

	write_pid_file();

	run_sec_mod(s);

	ret = ctl_handler_init(s);
	if (ret < 0) {
		fprintf(stderr, "Cannot create command handler\n");
		exit(1);
	}

	mslog(s, NULL, LOG_INFO, "initialized %s", PACKAGE_STRING);

	/* chdir to our chroot directory, to allow opening the sec-mod
	 * socket if necessary. */
	if (s->config->chroot_dir) {
		if (chdir(s->config->chroot_dir) != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot chdir to %s: %s", s->config->chroot_dir, strerror(e));
			exit(1);
		}
	}
	ms_sleep(100); /* give some time for sec-mod to initialize */

	/* Initialize certificates */
	tls_load_certs(s, &creds);

	s->secmod_addr.sun_family = AF_UNIX;
	p = s->socket_file;
	if (s->config->chroot_dir) /* if we are on chroot make the socket file path relative */
		while (*p == '/') p++;
	strlcpy(s->secmod_addr.sun_path, p, sizeof(s->secmod_addr.sun_path));
	s->secmod_addr_len = SUN_LEN(&s->secmod_addr);

	/* initialize memory for worker process */
	worker_pool = talloc_named(main_pool, 0, "worker");
	if (worker_pool == NULL) {
		fprintf(stderr, "talloc init error\n");
		exit(1);
	}

	ws = talloc_zero(worker_pool, struct worker_st);
	if (ws == NULL) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}

	sigprocmask(SIG_BLOCK, &blockset, &sig_default_set);
	alarm(MAINTAINANCE_TIME(s));

	for (;;) {
		check_other_work(s);

		/* initialize select */
		FD_ZERO(&rd_set);
		FD_ZERO(&wr_set);

		list_for_each(&s->listen_list.head, ltmp, list) {
			if (ltmp->fd == -1) continue;

			FD_SET(ltmp->fd, &rd_set);
			n = MAX(n, ltmp->fd);
		}

		list_for_each(&s->proc_list.head, ctmp, list) {
			if (ctmp->fd > 0) {
				FD_SET(ctmp->fd, &rd_set);
				n = MAX(n, ctmp->fd);
			}
		}

		ret = ctl_handler_set_fds(s, &rd_set, &wr_set);
		n = MAX(n, ret);

#ifdef HAVE_PSELECT
		ts.tv_nsec = 0;
		ts.tv_sec = 30;
		ret = pselect(n + 1, &rd_set, &wr_set, NULL, &ts, &emptyset);
#else
		ts.tv_usec = 0;
		ts.tv_sec = 30;
		sigprocmask(SIG_UNBLOCK, &blockset, NULL);
		ret = select(n + 1, &rd_set, &wr_set, NULL, &ts);
		sigprocmask(SIG_BLOCK, &blockset, NULL);
#endif
		if (ret == -1 && errno == EINTR)
			continue;

		if (ret < 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "Error in pselect(): %s",
			       strerror(e));
			exit(1);
		}

		/* Check for new connections to accept */
		list_for_each(&s->listen_list.head, ltmp, list) {
			set = FD_ISSET(ltmp->fd, &rd_set);
			if (set && (ltmp->sock_type == SOCK_TYPE_TCP || ltmp->sock_type == SOCK_TYPE_UNIX)) {
				/* connection on TCP port */
				int stype = ltmp->sock_type;

				ws->remote_addr_len = sizeof(ws->remote_addr);
				fd = accept(ltmp->fd, (void*)&ws->remote_addr, &ws->remote_addr_len);
				if (fd < 0) {
					mslog(s, NULL, LOG_ERR,
					       "Error in accept(): %s", strerror(errno));
					continue;
				}
				set_cloexec_flag (fd, 1);
#ifndef __linux__
				/* OpenBSD sets the non-blocking flag if accept's fd is non-blocking */
				set_block(fd);
#endif

				if (s->config->max_clients > 0 && s->active_clients >= s->config->max_clients) {
					close(fd);
					mslog(s, NULL, LOG_INFO, "Reached maximum client limit (active: %u)", s->active_clients);
					break;
				}

				if (check_tcp_wrapper(fd) < 0) {
					close(fd);
					mslog(s, NULL, LOG_INFO, "TCP wrappers rejected the connection (see /etc/hosts->[allow|deny])");
					break;
				}

				/* Create a command socket */
				ret = socketpair(AF_UNIX, SOCK_STREAM, 0, cmd_fd);
				if (ret < 0) {
					mslog(s, NULL, LOG_ERR, "Error creating command socket");
					close(fd);
					break;
				}

				pid = our_fork();
				if (pid == 0) {	/* child */
					/* close any open descriptors, and erase
					 * sensitive data before running the worker
					 */
					sigprocmask(SIG_SETMASK, &sig_default_set, NULL);
					close(cmd_fd[0]);
					clear_lists(s);

					/* clear the cookie key */
					safe_memset(s->cookie_key, 0, sizeof(s->cookie_key));

					setproctitle(PACKAGE_NAME"-worker");
					kill_on_parent_kill(SIGTERM);

					/* write sec-mod's address */
					memcpy(&ws->secmod_addr, &s->secmod_addr, s->secmod_addr_len);
					ws->secmod_addr_len = s->secmod_addr_len;

					ws->main_pool = main_pool;
					ws->config = s->config;
					ws->cmd_fd = cmd_fd[1];
					ws->tun_fd = -1;
					ws->dtls_tptr.fd = -1;
					ws->conn_fd = fd;
					ws->conn_type = stype;
					ws->creds = &creds;

					/* Drop privileges after this point */
					drop_privileges(s);

					/* creds and config are not allocated
					 * under s.
					 */
					talloc_free(s);
#ifdef HAVE_MALLOC_TRIM
					/* try to return all the pages we've freed to
					 * the operating system, to prevent the child from
					 * accessing them. That's totally unreliable, so
					 * sensitive data have to be overwritten anyway. */
					malloc_trim(0);
#endif
					vpn_server(ws);
					exit(0);
				} else if (pid == -1) {
fork_failed:
					mslog(s, NULL, LOG_ERR, "fork failed");
					close(cmd_fd[0]);
				} else { /* parent */
					/* add_proc */
					ctmp = new_proc(s, pid, cmd_fd[0], 
							&ws->remote_addr, ws->remote_addr_len,
							ws->sid, sizeof(ws->sid));
					if (ctmp == NULL) {
						kill(pid, SIGTERM);
						goto fork_failed;
					}

				}
				close(cmd_fd[1]);
				close(fd);

				if (s->config->rate_limit_ms > 0)
					ms_sleep(s->config->rate_limit_ms);
			} else if (set && ltmp->sock_type == SOCK_TYPE_UDP) {
				/* connection on UDP port */
				forward_udp_to_owner(s, ltmp);

				if (s->config->rate_limit_ms > 0)
					ms_sleep(s->config->rate_limit_ms);
			}
		}

		/* Check for any pending commands */
		list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
			if (ctmp->fd >= 0 && FD_ISSET(ctmp->fd, &rd_set)) {
				ret = handle_commands(s, ctmp);
				if (ret < 0) {
					remove_proc(s, ctmp, (ret!=ERR_WORKER_TERMINATED)?1:0);
				}
			}
		}

		/* Check for pending control commands */
		ctl_handler_run_pending(s, &rd_set, &wr_set);

#ifdef DEBUG_LEAKS
		talloc_report_full(s, stderr);
#endif
	}

	return 0;
}
