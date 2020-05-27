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
#include <ev.h>

#ifdef HAVE_LIBSYSTEMD
# include <systemd/sd-daemon.h>
#endif
#include <main.h>
#include <main-ctl.h>
#include <main-ban.h>
#include <route-add.h>
#include <worker.h>
#include <proc-search.h>
#include <tun.h>
#include <grp.h>
#include <ip-lease.h>
#include <ccan/list/list.h>
#include <hmac.h>
#include <base64-helper.h>
#include <snapshot.h>
#include <isolate.h>

#ifdef HAVE_GSSAPI
# include <libtasn1.h>

extern const ASN1_ARRAY_TYPE kkdcp_asn1_tab[];
ASN1_TYPE _kkdcp_pkix1_asn = ASN1_TYPE_EMPTY;
#endif

// Name of environment variable used to pass worker_startup_msg 
// between ocserv-main and ocserv-worker.
#define OCSERV_ENV_WORKER_STARTUP_MSG "OCSERV_WORKER_STARTUP_MSG"

extern struct snapshot_t * config_snapshot;


int worker_argc = 0;
char **worker_argv = NULL;

static void listen_watcher_cb (EV_P_ ev_io *w, int revents);

int syslog_open = 0;
sigset_t sig_default_set;
struct ev_loop *loop = NULL;
static unsigned allow_broken_clients = 0;

/* EV watchers */
ev_io ctl_watcher;
ev_io sec_mod_watcher;
ev_timer maintenance_watcher;
ev_signal maintenance_sig_watcher;
ev_signal term_sig_watcher;
ev_signal int_sig_watcher;
ev_signal reload_sig_watcher;
ev_child child_watcher;
#if defined(CAPTURE_LATENCY_SUPPORT)
ev_timer latency_watcher;
#endif

static int set_env_from_ws(main_server_st * ws);

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

	ev_init(&tmp->io, listen_watcher_cb);
	ev_io_set(&tmp->io, fd, EV_READ);

	list_add(&list->head, &(tmp->list));
	list->total++;
}

static void set_udp_socket_options(struct perm_cfg_st* config, int fd, int family)
{
int y;
	if (config->config->try_mtu) {
		set_mtu_disc(fd, family, 1);
	}
#if defined(IP_PKTINFO)
	y = 1;
	if (setsockopt(fd, SOL_IP, IP_PKTINFO,
		       (const void *)&y, sizeof(y)) < 0)
		perror("setsockopt(IP_PKTINFO) failed");
#elif defined(IP_RECVDSTADDR) /* *BSD */
	if (family == AF_INET) {
		y = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR,
			       (const void *)&y, sizeof(y)) < 0)
			perror("setsockopt(IP_RECVDSTADDR) failed");
	}
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
int _listen_ports(void *pool, struct perm_cfg_st* config, 
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
int _listen_unix_ports(void *pool, struct perm_cfg_st* config, 
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
			close(s);
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
listen_ports(void *pool, struct perm_cfg_st* config, 
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

		ret = getaddrinfo(config->listen_host, portname, &hints, &res);
		if (ret != 0) {
			fprintf(stderr, "getaddrinfo() failed: %s\n",
				gai_strerror(ret));
			return -1;
		}

		ret = _listen_ports(pool, config, res, list);
		freeaddrinfo(res);

		if (ret < 0) {
			return -1;
		}

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

		ret = getaddrinfo(config->udp_listen_host, portname, &hints, &res);
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
void set_worker_udp_opts(main_server_st *s, int fd, int family)
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

	if (GETCONFIG(s)->try_mtu) {
		set_mtu_disc(fd, family, 1);
	}
	set_cloexec_flag (fd, 1);

	return;
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
		ev_child_stop(EV_A_ &ctmp->ev_child);
		ev_io_stop(EV_A_ &ctmp->io);
		safe_memset(ctmp, 0, sizeof(*ctmp));
		talloc_free(ctmp);
		s->proc_list.total--;
	}

	list_for_each_safe(&s->script_list.head, script_tmp, script_pos, list) {
		list_del(&script_tmp->list);
		ev_child_stop(loop, &script_tmp->ev_child);
		talloc_free(script_tmp);
	}

	ip_lease_deinit(&s->ip_leases);
	proc_table_deinit(s);
	ctl_handler_deinit(s);
	main_ban_db_deinit(s);

	/* clear libev state */
	if (loop) {
		ev_io_stop (loop, &ctl_watcher);
		ev_io_stop (loop, &sec_mod_watcher);
		ev_child_stop (loop, &child_watcher);
		ev_timer_stop(loop, &maintenance_watcher);
#if defined(CAPTURE_LATENCY_SUPPORT)
		ev_timer_stop(loop, &latency_watcher);		
#endif
		/* free memory and descriptors by the event loop */
		ev_loop_destroy (loop);
	}
}

#define SKIP16(pos, total) { \
	uint16_t _s; \
	if (pos+2 > total) goto fallback; \
	_s = (buffer[pos] << 8) | buffer[pos+1]; \
	if ((size_t)(pos+2+_s) > total) goto fallback; \
	pos += 2+_s; \
	}

#define SKIP8(pos, total) { \
	uint8_t _s; \
	if (pos+1 > total) goto fallback; \
	_s = buffer[pos]; \
	if ((size_t)(pos+1+_s) > total) goto fallback; \
	pos += 1+_s; \
	}

#define TLS_EXT_APP_ID 48018
#define RECORD_PAYLOAD_POS 13
#define HANDSHAKE_SESSION_ID_POS 46
#define HANDSHAKE_RANDOM_POS 14

/* This returns either the application-specific ID extension contents,
 * or the session ID contents. The former is used on the new protocol,
 * while the latter on the legacy protocol.
 *
 * Extension ID: 48018
 * opaque ApplicationID<1..2^8-1>;
 *
 * struct {
 *          ExtensionType extension_type;
 *          opaque extension_data<0..2^16-1>;
 *      } Extension;
 *
 *      struct {
 *          ProtocolVersion server_version;
 *          Random random;
 *          SessionID session_id;
 *          opaque cookie<0..2^8-1>;
 *          CipherSuite cipher_suite;
 *          CompressionMethod compression_method;
 *          Extension server_hello_extension_list<0..2^16-1>;
 *      } ServerHello;
 */
static
unsigned get_session_id(main_server_st* s, uint8_t *buffer, size_t buffer_size, uint8_t **id, int *id_size)
{
	size_t pos;

	/* A client hello packet. We can get the session ID and figure
	 * the associated connection. */
	if (buffer_size < RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS+GNUTLS_MAX_SESSION_ID+2) {
		return 0;
	}

	if (!GETCONFIG(s)->dtls_psk)
		goto fallback;

	/* try to read the extension data */
	pos = RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS;
	SKIP8(pos, buffer_size);

	/* Cookie */
	SKIP8(pos, buffer_size);

	/* CipherSuite */
	SKIP16(pos, buffer_size);

	/* CompressionMethod */

	SKIP8(pos, buffer_size);

	if (pos+2 > buffer_size)
		goto fallback;
	pos+=2;

	/* Extension(s) */
	while (pos < buffer_size) {
		uint16_t type;
		uint16_t s;

		if (pos+4 > buffer_size)
			goto fallback;

		type = (buffer[pos] << 8) | buffer[pos+1];
		pos+=2;
		if (type != TLS_EXT_APP_ID) {
			SKIP16(pos, buffer_size);
		} else { /* found */
			if (pos+2 > buffer_size)
				return 0; /* invalid format */

			s = (buffer[pos] << 8) | buffer[pos+1];
			if ((size_t)(pos+2+s) > buffer_size)
				return 0; /* invalid format */
			pos+=2;

			s = buffer[pos];
			if ((size_t)(pos+1+s) > buffer_size)
				return 0; /* invalid format */
			pos++;
			*id_size = s;
			*id = &buffer[pos];
			return 1;
		}
	}

 fallback:
	/* read session_id */
	*id_size = buffer[RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS];
	*id = &buffer[RECORD_PAYLOAD_POS+HANDSHAKE_SESSION_ID_POS+1];

	return 1;
}

static
unsigned has_broken_random(main_server_st* s, uint8_t *buffer, size_t buffer_size)
{
	size_t pos,i;

	if (allow_broken_clients)
		return 0;

	if (buffer_size < RECORD_PAYLOAD_POS+HANDSHAKE_RANDOM_POS+32)
		return 0;

	/* check whether the client hello contains a random value of all zeros;
	 * if that's the case it indicates a broken DTLS client. Relates to:
	 * https://gitlab.com/gnutls/gnutls/-/issues/960 */
	pos = RECORD_PAYLOAD_POS+HANDSHAKE_RANDOM_POS;

	for (i=0;i<32;i++) {
		if (buffer[pos+i] != 0)
			return 0;
	}

	return 1;
}

/* A UDP fd will not be forwarded to worker process before this number of
 * seconds has passed. That is to prevent a duplicate message messing the worker.
 */
#define UDP_FD_RESEND_TIME 3

static int forward_udp_to_owner(main_server_st* s, struct listener_st *listener)
{
int ret, e;
struct sockaddr_storage cli_addr;
struct sockaddr_storage our_addr;
struct proc_st *proc_to_send = NULL;
socklen_t cli_addr_size, our_addr_size;
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
	ret = oc_recvfrom_at(listener->fd, s->msg_buffer, sizeof(s->msg_buffer), 0,
			  (struct sockaddr*)&cli_addr, &cli_addr_size,
			  (struct sockaddr*)&our_addr, &our_addr_size,
			  GETPCONFIG(s)->udp_port);
	if (ret < 0) {
		mslog(s, NULL, LOG_INFO, "error receiving in UDP socket");
		return -1;
	}
	buffer_size = ret;

	if (buffer_size < RECORD_PAYLOAD_POS) {
		mslog(s, NULL, LOG_INFO, "%s: too short UDP packet",
		      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)));
		goto fail;
	}

	/* check version */
	if (s->msg_buffer[0] == 22) {
		mslog(s, NULL, LOG_DEBUG, "new DTLS session from %s (record v%u.%u, hello v%u.%u)", 
			human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)),
			(unsigned int)s->msg_buffer[1], (unsigned int)s->msg_buffer[2],
			(unsigned int)s->msg_buffer[RECORD_PAYLOAD_POS], (unsigned int)s->msg_buffer[RECORD_PAYLOAD_POS+1]);
	}

	if (s->msg_buffer[1] != 254 && (s->msg_buffer[1] != 1 && s->msg_buffer[2] != 0) &&
		s->msg_buffer[RECORD_PAYLOAD_POS] != 254 && (s->msg_buffer[RECORD_PAYLOAD_POS] != 0 && s->msg_buffer[RECORD_PAYLOAD_POS+1] != 0)) {
		mslog(s, NULL, LOG_INFO, "%s: unknown DTLS record version: %u.%u", 
		      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)),
		      (unsigned)s->msg_buffer[1], (unsigned)s->msg_buffer[2]);
		goto fail;
	}

	if (s->msg_buffer[0] != 22) {
		mslog(s, NULL, LOG_DEBUG, "%s: unexpected DTLS content type: %u; possibly a firewall disassociated a UDP session",
		      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)),
		      (unsigned int)s->msg_buffer[0]);
		/* Here we received a non-client-hello packet. It may be that
		 * the client's NAT changed its UDP source port and the previous
		 * connection is invalidated. Try to see if we can simply match
		 * the IP address and forward the socket.
		 */
		match_ip_only = 1;

		/* don't bother IP matching when the listen-clear-file is in use */
		if (GETPCONFIG(s)->unix_conn_file)
			goto fail;
	} else {
		if (has_broken_random(s, s->msg_buffer, buffer_size)) {
			mslog(s, NULL, LOG_INFO, "%s: detected broken DTLS client hello (no randomness); ignoring",
			      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)));
			goto fail;
		}

		if (!get_session_id(s, s->msg_buffer, buffer_size, &session_id, &session_id_size)) {
			mslog(s, NULL, LOG_INFO, "%s: too short handshake packet",
			      human_addr((struct sockaddr*)&cli_addr, cli_addr_size, tbuf, sizeof(tbuf)));
			goto fail;
		}
	}

	/* search for the IP and the session ID in all procs */
	now = time(0);

	if (match_ip_only == 0) {
		proc_to_send = proc_search_dtls_id(s, session_id, session_id_size);
	} else {
		proc_to_send = proc_search_single_ip(s, &cli_addr, cli_addr_size);
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

		set_worker_udp_opts(s, sfd, listener->family);

		if (our_addr_size > 0) {
			ret = bind(sfd, (struct sockaddr *)&our_addr, our_addr_size);
			if (ret == -1) {
				e = errno;
				mslog(s, proc_to_send, LOG_INFO, "bind UDP to %s: %s",
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
			msg.hello = 0; /* by default this is one */
		} else {
			/* a new DTLS session, store the DTLS IPs into proc and add it into hash table */
			proc_table_update_dtls_ip(s, proc_to_send, &cli_addr, cli_addr_size);
		}

		msg.data.data = s->msg_buffer;
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

static void sec_mod_child_watcher_cb(struct ev_loop *loop, ev_child *w, int revents)
{
	main_server_st *s = ev_userdata(loop);

	if (WIFSIGNALED(w->rstatus)) {
		if (WTERMSIG(w->rstatus) == SIGSEGV)
			mslog(s, NULL, LOG_ERR, "Sec-mod %u died with sigsegv\n", (unsigned)w->pid);
		else if (WTERMSIG(w->rstatus) == SIGSYS)
			mslog(s, NULL, LOG_ERR, "Sec-mod %u died with sigsys\n", (unsigned)w->pid);
		else
			mslog(s, NULL, LOG_ERR, "Sec-mod %u died with signal %d\n", (unsigned)w->pid, (int)WTERMSIG(w->rstatus));
	}

	ev_child_stop(loop, w);
	mslog(s, NULL, LOG_ERR, "ocserv-secmod died unexpectedly");
	ev_feed_signal_event (loop, SIGTERM);

}

void script_child_watcher_cb(struct ev_loop *loop, ev_child *w, int revents)
{
	main_server_st *s = ev_userdata(loop);
	int ret;
	struct script_wait_st *stmp = (struct script_wait_st*)w;
	unsigned estatus;

	estatus = WEXITSTATUS(w->rstatus);
	if (WIFSIGNALED(w->rstatus))
		estatus = 1;

	/* check if someone was waiting for that pid */
	mslog(s, stmp->proc, LOG_DEBUG, "connect-script exit status: %u", estatus);
	list_del(&stmp->list);
	ev_child_stop(loop, &stmp->ev_child);

	ret = handle_script_exit(s, stmp->proc, estatus);
	if (ret < 0) {
		/* takes care of free */
		remove_proc(s, stmp->proc, RPROC_KILL);
	} else {
		talloc_free(stmp);
	}
}

static void worker_child_watcher_cb(struct ev_loop *loop, ev_child *w, int revents)
{
	main_server_st *s = ev_userdata(loop);

	if (WIFSIGNALED(w->rstatus)) {
		if (WTERMSIG(w->rstatus) == SIGSEGV)
			mslog(s, NULL, LOG_ERR, "Child %u died with sigsegv\n", (unsigned)w->pid);
		else if (WTERMSIG(w->rstatus) == SIGSYS)
			mslog(s, NULL, LOG_ERR, "Child %u died with sigsys\n", (unsigned)w->pid);
		else
			mslog(s, NULL, LOG_ERR, "Child %u died with signal %d\n", (unsigned)w->pid, (int)WTERMSIG(w->rstatus));
	}

	ev_child_stop(loop, w);
}

static void kill_children(main_server_st* s)
{
	struct proc_st *ctmp = NULL, *cpos;

	/* kill the security module server */
	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		if (ctmp->pid != -1) {
			remove_proc(s, ctmp, RPROC_KILL|RPROC_QUIT);
		}
	}
	kill(s->sec_mod_pid, SIGTERM);
}

static void kill_children_auth_timeout(main_server_st* s)
{
	struct proc_st *ctmp = NULL, *cpos;
	time_t oldest_permitted_session = time(NULL) - GETCONFIG(s)->auth_timeout;

	/* kill the security module server */
	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		/* If the worker has not completed it's auth within auth_timeout seconds, kill it */
		if ((ctmp->status < PS_AUTH_COMPLETED) &&
		    (ctmp->conn_time < oldest_permitted_session) && 
			(ctmp->pid != -1)) {
			remove_proc(s, ctmp, RPROC_KILL);
		}
	}
}

static void term_sig_watcher_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	main_server_st *s = ev_userdata(loop);
	unsigned total = 10;

	mslog(s, NULL, LOG_INFO, "termination request received; waiting for children to die");
	kill_children(s);

	while (waitpid(-1, NULL, WNOHANG) >= 0) {
		if (total == 0) {
			mslog(s, NULL, LOG_INFO, "not everyone died; forcing kill");
			kill(0, SIGKILL);
		}
		ms_sleep(500);
		total--;
	}

	ev_break (loop, EVBREAK_ALL);
}

static void reload_sig_watcher_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	main_server_st *s = ev_userdata(loop);
	int ret;

	mslog(s, NULL, LOG_INFO, "reloading configuration");
	kill(s->sec_mod_pid, SIGHUP);

	/* Reload on main needs to happen later than sec-mod.
	 * That's because of a test that the certificate matches the
	 * used key. */
	ret = secmod_reload(s);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "could not reload sec-mod!\n");
		ev_feed_signal_event (loop, SIGTERM);
	}

	reload_cfg_file(s->config_pool, s->vconfig, 0);
}

static void cmd_watcher_cb (EV_P_ ev_io *w, int revents)
{
	main_server_st *s = ev_userdata(loop);
	struct proc_st *ctmp = (struct proc_st*)w;
	int ret;

	/* Check for any pending commands */
	ret = handle_worker_commands(s, ctmp);
	if (ret < 0) {
		remove_proc(s, ctmp, (ret!=ERR_WORKER_TERMINATED)?RPROC_KILL:0);
	}
}

static void listen_watcher_cb (EV_P_ ev_io *w, int revents)
{
	main_server_st *s = ev_userdata(loop);
	struct listener_st *ltmp = (struct listener_st *)w;
	struct proc_st *ctmp = NULL;
	struct worker_st *ws = s->ws;
	int fd, ret;
	int cmd_fd[2];
	pid_t pid;
	hmac_component_st hmac_components[3];
	char path[_POSIX_PATH_MAX];
	char worker_path[_POSIX_PATH_MAX];
	size_t path_length;

	if (ltmp->sock_type == SOCK_TYPE_TCP || ltmp->sock_type == SOCK_TYPE_UNIX) {
		/* connection on TCP port */
		int stype = ltmp->sock_type;

		ws->remote_addr_len = sizeof(ws->remote_addr);
		fd = accept(ltmp->fd, (void*)&ws->remote_addr, &ws->remote_addr_len);
		if (fd < 0) {
			mslog(s, NULL, LOG_ERR,
			       "error in accept(): %s", strerror(errno));
			return;
		}
		set_cloexec_flag (fd, 1);
#ifndef __linux__
		/* OpenBSD sets the non-blocking flag if accept's fd is non-blocking */
		set_block(fd);
#endif

		if (GETCONFIG(s)->max_clients > 0 && s->stats.active_clients >= GETCONFIG(s)->max_clients) {
			close(fd);
			mslog(s, NULL, LOG_INFO, "reached maximum client limit (active: %u)", s->stats.active_clients);
			return;
		}

		if (check_tcp_wrapper(fd) < 0) {
			close(fd);
			mslog(s, NULL, LOG_INFO, "TCP wrappers rejected the connection (see /etc/hosts->[allow|deny])");
			return;
		}

		if (ws->conn_type != SOCK_TYPE_UNIX && !GETCONFIG(s)->listen_proxy_proto) {
			memset(&ws->our_addr, 0, sizeof(ws->our_addr));
			ws->our_addr_len = sizeof(ws->our_addr);
			if (getsockname(fd, (struct sockaddr*)&ws->our_addr, &ws->our_addr_len) < 0)
				ws->our_addr_len = 0;

			if (check_if_banned(s, &ws->remote_addr, ws->remote_addr_len) != 0) {
				close(fd);
				return;
			}
		}

		/* Create a command socket */
		ret = socketpair(AF_UNIX, SOCK_STREAM, 0, cmd_fd);
		if (ret < 0) {
			mslog(s, NULL, LOG_ERR, "error creating command socket");
			close(fd);
			return;
		}

		pid = fork();
		if (pid == 0) {	/* child */
			/* close any open descriptors, and erase
			 * sensitive data before running the worker
			 */
			sigprocmask(SIG_SETMASK, &sig_default_set, NULL);
			close(cmd_fd[0]);
			clear_lists(s);
			if (s->top_fd != -1) close(s->top_fd);
			close(s->sec_mod_fd);
			close(s->sec_mod_fd_sync);

			setproctitle(PACKAGE_NAME"-worker");
			kill_on_parent_kill(SIGTERM);

			set_self_oom_score_adj(s);

			/* write sec-mod's address */
			memcpy(&ws->secmod_addr, &s->secmod_addr, s->secmod_addr_len);
			ws->secmod_addr_len = s->secmod_addr_len;

			ws->main_pool = s->main_pool;

			ws->vconfig = s->vconfig;

			ws->cmd_fd = cmd_fd[1];
			ws->tun_fd = -1;
			ws->dtls_tptr.fd = -1;
			set_cloexec_flag(fd, false);
			ws->conn_fd = fd;
			ws->conn_type = stype;
			ws->session_start_time = time(0);

			human_addr2((const struct sockaddr *)&ws->remote_addr, ws->remote_addr_len, ws->remote_ip_str, sizeof(ws->remote_ip_str), 0);
			human_addr2((const struct sockaddr *)&ws->our_addr, ws->our_addr_len, ws->our_ip_str, sizeof(ws->our_ip_str), 0);

			hmac_components[0].data = ws->remote_ip_str;
			hmac_components[0].length = strlen(ws->remote_ip_str);
			hmac_components[1].data = ws->our_ip_str;
			hmac_components[1].length = strlen(ws->our_ip_str);
			hmac_components[2].data = &ws->session_start_time;
			hmac_components[2].length = sizeof(ws->session_start_time);

			generate_hmac(sizeof(s->hmac_key), s->hmac_key, sizeof(hmac_components) / sizeof(hmac_components[0]), hmac_components, (uint8_t*) ws->sec_auth_init_hmac);
			
			// Clear the HMAC key
			safe_memset((uint8_t*)s->hmac_key, 0, sizeof(s->hmac_key));

			set_env_from_ws(s);
			path_length = readlink("/proc/self/exe", path, sizeof(path)-1);
			if (path_length == -1) {
				mslog(s, NULL, LOG_ERR, "readlink failed %s", strerror(ret));
				exit(1);
			}
			path[path_length] = '\0';
			if (snprintf(worker_path, sizeof(worker_path), "%s-worker", path) >= sizeof(worker_path)) {
				mslog(s, NULL, LOG_ERR, "snprint of path %s and ocserv-worker failed", path);
				exit(1);
			}

			worker_argv[0] = worker_path;
			execv(worker_path, worker_argv);
			ret = errno;
			mslog(s, NULL, LOG_ERR, "exec %s failed %s", worker_path, strerror(ret));
			exit(1);
		} else if (pid == -1) {
fork_failed:
			mslog(s, NULL, LOG_ERR, "fork failed");
			close(cmd_fd[0]);
		} else { /* parent */
			/* add_proc */
			ctmp = new_proc(s, pid, cmd_fd[0], 
					&ws->remote_addr, ws->remote_addr_len,
					&ws->our_addr, ws->our_addr_len,
					ws->sid, sizeof(ws->sid));
			if (ctmp == NULL) {
				kill(pid, SIGTERM);
				goto fork_failed;
			}

			ev_io_init(&ctmp->io, cmd_watcher_cb, cmd_fd[0], EV_READ);
			ev_io_start(loop, &ctmp->io);

			ev_child_init(&ctmp->ev_child, worker_child_watcher_cb, pid, 0);
			ev_child_start(loop, &ctmp->ev_child);
		}
		close(cmd_fd[1]);
		close(fd);
	} else if (ltmp->sock_type == SOCK_TYPE_UDP) {
		/* connection on UDP port */
		forward_udp_to_owner(s, ltmp);
	}

	if (GETCONFIG(s)->rate_limit_ms > 0)
		ms_sleep(GETCONFIG(s)->rate_limit_ms);
}

static void sec_mod_watcher_cb (EV_P_ ev_io *w, int revents)
{
	main_server_st *s = ev_userdata(loop);
	int ret;

	ret = handle_sec_mod_commands(s);
	if (ret < 0) { /* bad commands from sec-mod are unacceptable */
		mslog(s, NULL, LOG_ERR,
		       "error in command from sec-mod");
		ev_feed_signal_event (loop, SIGTERM);
	}
}

static void ctl_watcher_cb (EV_P_ ev_io *w, int revents)
{
	main_server_st *s = ev_userdata(loop);

	ctl_handler_run_pending(s, w);
}

static void perform_maintenance(main_server_st *s)
{
	vhost_cfg_st *vhost = NULL;

	/* Check if we need to expire any data */
	mslog(s, NULL, LOG_DEBUG, "performing maintenance");
	cleanup_banned_entries(s);
	clear_old_configs(s->vconfig);
	
	kill_children_auth_timeout(s);

	list_for_each_rev(s->vconfig, vhost, list) {
		tls_reload_crl(s, vhost, 0);
	}
}

static void maintenance_watcher_cb(EV_P_ ev_timer *w, int revents)
{
	main_server_st *s = ev_userdata(loop);

	perform_maintenance(s);
}

#if defined(CAPTURE_LATENCY_SUPPORT)
static void latency_watcher_cb(EV_P_ ev_timer *w, int revents)
{
	main_server_st *s = ev_userdata(loop);
	s->stats.current_latency_stats = s->stats.delta_latency_stats;
	s->stats.delta_latency_stats.median_total = 0;
	s->stats.delta_latency_stats.rms_total = 0;
	s->stats.delta_latency_stats.sample_count = 0;
	mslog(
		s, 
		NULL, 
		LOG_INFO, 
		"Latency: Median Total %ld RMS Total %ld Sample Count %ld", 
		s->stats.current_latency_stats.median_total, 
		s->stats.current_latency_stats.rms_total, 
		s->stats.current_latency_stats.sample_count);
}
#endif

static void maintenance_sig_watcher_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	main_server_st *s = ev_userdata(loop);

	mslog(s, NULL, LOG_INFO, "forcing maintenance cycle");
	perform_maintenance(s);
}


static void syserr_cb (const char *msg)
{
	main_server_st *s = ev_userdata(loop);

	mslog(s, NULL, LOG_ERR, "libev fatal error: %s", msg);
	abort();
}

extern char secmod_socket_file_name_socket_file[_POSIX_PATH_MAX];

int main(int argc, char** argv)
{
	int e;
	struct listener_st *ltmp = NULL;
	int ret, flags;
	char *p;
	void *worker_pool;
	void *main_pool, *config_pool;
	main_server_st *s;
	char *str;
	int i;

#ifdef DEBUG_LEAKS
	talloc_enable_leak_report_full();
#endif

	saved_argc = argc;
	saved_argv = argv;

	/* main pool */
	main_pool = talloc_init("main");
	if (main_pool == NULL) {
		fprintf(stderr, "talloc init error\n");
		exit(1);
	}

	config_pool = talloc_init("config");
	if (config_pool == NULL) {
		fprintf(stderr, "talloc init error\n");
		exit(1);
	}

	if (snapshot_init(config_pool, &config_snapshot, "/tmp/ocserv_") < 0) {
		fprintf(stderr, "failed to init snapshot");
		exit(1);
	}

	s = talloc_zero(main_pool, main_server_st);
	if (s == NULL) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}
	s->main_pool = main_pool;
	s->config_pool = config_pool;
	s->stats.start_time = s->stats.last_reset = time(0);
	s->top_fd = -1;
	s->ctl_fd = -1;

	if (!hmac_init_key(sizeof(s->hmac_key), (uint8_t*)(s->hmac_key))) {
		fprintf(stderr, "unable to generate hmac key\n");
		exit(1);
	}

	// getopt processing mutates argv. Save a copy to pass to the child.
	worker_argc = argc;
	worker_argv = talloc_zero_array(main_pool, char*, worker_argc + 1);
	if (!worker_argv) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}
	for (i = 0; i < argc; i ++) {
		worker_argv[i] = talloc_strdup(main_pool, argv[i]);
		if (!worker_argv[i]) {
			fprintf(stderr, "memory error\n");
			exit(1);
		}
	}

	init_fd_limits_default(s);

	str = getenv("OCSERV_ALLOW_BROKEN_CLIENTS");
	if (str && str[0] == '1' && str[1] == 0)
		allow_broken_clients = 1;

	list_head_init(&s->proc_list.head);
	list_head_init(&s->script_list.head);
	ip_lease_init(&s->ip_leases);
	proc_table_init(s);
	main_ban_db_init(s);

	sigemptyset(&sig_default_set);

	ocsignal(SIGPIPE, SIG_IGN);

	/* Initialize GnuTLS */
	tls_global_init();

	/* load configuration */
	s->vconfig = talloc_zero(config_pool, struct list_head);
	if (s->vconfig == NULL) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}
	list_head_init(s->vconfig);

	ret = cmd_parser(config_pool, argc, argv, s->vconfig, false);
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
	ret = listen_ports(s, GETPCONFIG(s), &s->listen_list);
	if (ret < 0) {
		fprintf(stderr, "Cannot listen to specified ports\n");
		exit(1);
	}

	flags = LOG_PID|LOG_NDELAY;
#ifdef LOG_PERROR
	if (GETPCONFIG(s)->debug != 0)
		flags |= LOG_PERROR;
#endif
	openlog("ocserv", flags, LOG_DAEMON);
	syslog_open = 1;
#ifdef HAVE_LIBWRAP
	allow_severity = LOG_DAEMON|LOG_INFO;
	deny_severity = LOG_DAEMON|LOG_WARNING;
#endif

	if (GETPCONFIG(s)->foreground == 0) {
		if (daemon(GETPCONFIG(s)->no_chdir, 0) == -1) {
			e = errno;
			fprintf(stderr, "daemon failed: %s\n", strerror(e));
			exit(1);
		}
	}

	/* create our process group */
	setpgid(0, 0);

	/* we don't need them */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	write_pid_file();

	s->sec_mod_fd = run_sec_mod(s, &s->sec_mod_fd_sync);
	ret = ctl_handler_init(s);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "Cannot create command handler");
		exit(1);
	}

	loop = EV_DEFAULT;
	if (loop == NULL) {
		mslog(s, NULL, LOG_ERR, "could not initialise libev");
		exit(1);
	}

	mslog(s, NULL, LOG_INFO, "initialized %s", PACKAGE_STRING);

	/* chdir to our chroot directory, to allow opening the sec-mod
	 * socket if necessary. */
	if (GETPCONFIG(s)->chroot_dir) {
		if (chdir(GETPCONFIG(s)->chroot_dir) != 0) {
			e = errno;
			mslog(s, NULL, LOG_ERR, "cannot chdir to %s: %s", GETPCONFIG(s)->chroot_dir, strerror(e));
			exit(1);
		}
	}
	ms_sleep(100); /* give some time for sec-mod to initialize */

	s->secmod_addr.sun_family = AF_UNIX;
	p = s->socket_file;
	if (GETPCONFIG(s)->chroot_dir) /* if we are on chroot make the socket file path relative */
		while (*p == '/') p++;
	strlcpy(s->secmod_addr.sun_path, p, sizeof(s->secmod_addr.sun_path));
	s->secmod_addr_len = SUN_LEN(&s->secmod_addr);

	/* initialize memory for worker process */
	worker_pool = talloc_named(main_pool, 0, "worker");
	if (worker_pool == NULL) {
		mslog(s, NULL, LOG_ERR, "talloc init error");
		exit(1);
	}

	s->ws = talloc_zero(worker_pool, struct worker_st);
	if (s->ws == NULL) {
		mslog(s, NULL, LOG_ERR, "memory error");
		exit(1);
	}

#ifdef HAVE_GSSAPI
	/* Initialize kkdcp structures */
	ret = asn1_array2tree(kkdcp_asn1_tab, &_kkdcp_pkix1_asn, NULL);
	if (ret != ASN1_SUCCESS) {
		mslog(s, NULL, LOG_ERR, "KKDCP ASN.1 initialization error");
		exit(1);
	}
#endif

	init_fd_limits_default(s);

	/* increase the number of our allowed file descriptors */
	update_fd_limits(s, 1);

	ev_set_userdata (loop, s);
	ev_set_syserr_cb(syserr_cb);

	ev_init(&ctl_watcher, ctl_watcher_cb);
	ev_init(&sec_mod_watcher, sec_mod_watcher_cb);

	ev_init (&int_sig_watcher, term_sig_watcher_cb);
	ev_signal_set (&int_sig_watcher, SIGINT);
	ev_signal_start (loop, &int_sig_watcher);

	ev_init (&term_sig_watcher, term_sig_watcher_cb);
	ev_signal_set (&term_sig_watcher, SIGTERM);
	ev_signal_start (loop, &term_sig_watcher);

	ev_init (&reload_sig_watcher, reload_sig_watcher_cb);
	ev_signal_set (&reload_sig_watcher, SIGHUP);
	ev_signal_start (loop, &reload_sig_watcher);

	/* set the standard fds we watch */
	list_for_each(&s->listen_list.head, ltmp, list) {
		if (ltmp->fd == -1) continue;

		ev_io_start (loop, &ltmp->io);
	}

	ev_io_set(&sec_mod_watcher, s->sec_mod_fd, EV_READ);
	ctl_handler_set_fds(s, &ctl_watcher);

	ev_io_start (loop, &ctl_watcher);
	ev_io_start (loop, &sec_mod_watcher);

	ev_child_init(&child_watcher, sec_mod_child_watcher_cb, s->sec_mod_pid, 0);
	ev_child_start (loop, &child_watcher);

	ev_init(&maintenance_watcher, maintenance_watcher_cb);
	ev_timer_set(&maintenance_watcher, MAIN_MAINTENANCE_TIME, MAIN_MAINTENANCE_TIME);
	ev_timer_start(loop, &maintenance_watcher);

#if defined(CAPTURE_LATENCY_SUPPORT)
	ev_init(&latency_watcher, latency_watcher_cb);
	ev_timer_set(&latency_watcher, LATENCY_AGGREGATION_TIME, LATENCY_AGGREGATION_TIME);
	ev_timer_start(loop, &latency_watcher);
#endif

	/* allow forcing maintenance with SIGUSR2 */
	ev_init (&maintenance_sig_watcher, maintenance_sig_watcher_cb);
	ev_signal_set (&maintenance_sig_watcher, SIGUSR2);
	ev_signal_start (loop, &maintenance_sig_watcher);

	/* Main server loop */
	ev_run (loop, 0);

	/* try to clean-up everything allocated to ease checks 
	 * for memory leaks.
	 */
	remove(s->full_socket_file);
	remove(GETPCONFIG(s)->occtl_socket_file);
	remove_pid_file();

	snapshot_terminate(config_snapshot);

	clear_lists(s);
	clear_vhosts(s->vconfig);
	talloc_free(s->config_pool);
	talloc_free(s->main_pool);
	closelog();

	return 0;
}

extern char ** pam_auth_group_list;
extern char ** gssapi_auth_group_list;
extern char ** plain_auth_group_list;
extern unsigned pam_auth_group_list_size;
extern unsigned gssapi_auth_group_list_size;
extern unsigned plain_auth_group_list_size;

static int set_env_from_ws(main_server_st *s)
{
	worker_st *ws = s->ws;
	WorkerStartupMsg msg = WORKER_STARTUP_MSG__INIT;
	size_t msg_size;
	uint8_t *msg_buffer = NULL;
	size_t string_size = 0;
	char *string_buffer = NULL;
	int ret = 0;
	SnapshotEntryMsg **entries = NULL;
	SnapshotEntryMsg entry_template = SNAPSHOT_ENTRY_MSG__INIT;
	size_t entry_count;
	size_t index = 0;
	struct htable_iter iter;

	msg.secmod_addr.data = (uint8_t *)&ws->secmod_addr;
	msg.secmod_addr.len = ws->secmod_addr_len;
	msg.cmd_fd = ws->cmd_fd;
	msg.conn_fd = ws->conn_fd;
	msg.conn_type = (WorkerStartupMsg__CONNTYPE)ws->conn_type;
	msg.remote_ip_str = ws->remote_ip_str;
	msg.our_ip_str = ws->our_ip_str;
	msg.session_start_time = ws->session_start_time;
	msg.remote_addr.data = (uint8_t *)&ws->remote_addr;
	msg.remote_addr.len = ws->remote_addr_len;
	msg.our_addr.data = (uint8_t *)&ws->our_addr;
	msg.our_addr.len = ws->our_addr_len;
	msg.sec_auth_init_hmac.data = (uint8_t *)ws->sec_auth_init_hmac;
	msg.sec_auth_init_hmac.len = sizeof(ws->sec_auth_init_hmac);

	entry_count = snapshot_entry_count(config_snapshot);

	entries = talloc_zero_array(s, SnapshotEntryMsg *, entry_count);
	if (!entries)
		goto cleanup;

	for (index = 0; index < entry_count; index++) {
		int fd;
		const char *file_name;
		if (index == 0) {
			snapshot_first(config_snapshot, &iter, &fd, &file_name);
		} else {
			snapshot_next(config_snapshot, &iter, &fd, &file_name);
		}

		entries[index] = talloc_zero(s, SnapshotEntryMsg);
		*entries[index] = entry_template;
		entries[index]->file_descriptor = fd;
		entries[index]->file_name = (char *)file_name;
	}

	msg.n_snapshot_entries = entry_count;
	msg.snapshot_entries = entries;

	msg.n_gssapi_auth_group_list = gssapi_auth_group_list_size;
	msg.gssapi_auth_group_list = gssapi_auth_group_list;
	msg.n_pam_auth_group_list = pam_auth_group_list_size;
	msg.pam_auth_group_list = pam_auth_group_list;
	msg.n_plain_auth_group_list = plain_auth_group_list_size;
	msg.plain_auth_group_list = plain_auth_group_list;

	msg_size = worker_startup_msg__get_packed_size(&msg);
	if (msg_size == 0) {
		mslog(s, NULL, LOG_ERR, "worker_startup_msg__get_packed_size failed\n");
		goto cleanup;
	}

	msg_buffer = talloc_size(ws, msg_size);
	if (!msg_buffer) {
		mslog(s, NULL, LOG_ERR, "talloc_size failed\n");
		goto cleanup;
	}
	msg_size = worker_startup_msg__pack(&msg, msg_buffer);
	if (msg_size == 0) {
		mslog(s, NULL, LOG_ERR, "worker_startup_msg__pack failed\n");
		goto cleanup;
	}
	string_size = BASE64_ENCODE_RAW_LENGTH(msg_size) + 1;
	string_buffer = talloc_size(ws, string_size);
	if (!msg_buffer) {
		mslog(s, NULL, LOG_ERR, "talloc_size failed\n");
		goto cleanup;
	}

	oc_base64_encode((const char *)msg_buffer, msg_size, string_buffer, string_size);
	if (setenv(OCSERV_ENV_WORKER_STARTUP_MSG, string_buffer, 1)) {
		mslog(s, NULL, LOG_ERR, "setenv failed\n");
		goto cleanup;
	}

	ret = 1;

cleanup:
	if (entries)
		talloc_free(entries);

	if (msg_buffer)
		talloc_free(msg_buffer);

	if (string_buffer)
		talloc_free(string_buffer);

	return ret;
}
