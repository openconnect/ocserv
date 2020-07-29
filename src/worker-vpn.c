/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
 * Copyright (C) 2015, 2016 Red Hat, Inc.
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <gnutls/crypto.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <system.h>
#include <time.h>
#include <gettime.h>
#include <common.h>
#include <html.h>
#include <c-strcase.h>
#include <c-ctype.h>
#include <worker-bandwidth.h>
#include <signal.h>
#include <poll.h>
#include <math.h>

#if defined(__linux__) && !defined(IPV6_PATHMTU)
# define IPV6_PATHMTU 61
#endif

#include <vpn.h>
#include "ipc.pb-c.h"
#include <worker.h>
#include <tlslib.h>
#include <http_parser.h>

#if defined(CAPTURE_LATENCY_SUPPORT)
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>
#include <worker-latency.h>
#endif

#define MIN_MTU(ws) (((ws)->vinfo.ipv6!=NULL)?1280:800)

#define PERIODIC_CHECK_TIME 30
#define MIN_STATS_INTERVAL 10

/* The number of DPD packets a client skips before he's kicked */
#define DPD_TRIES 2
#define DPD_MAX_TRIES 3

/* HTTP requests prior to disconnection */
#define MAX_HTTP_REQUESTS 16

#define CSTP_DTLS_OVERHEAD 1
#define CSTP_OVERHEAD 8

#define IP_HEADER_SIZE 20
#define IPV6_HEADER_SIZE 40
#define TCP_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8

#define MSS_ADJUST(x) x += TCP_HEADER_SIZE + ((ws->proto == AF_INET)?(IP_HEADER_SIZE):(IPV6_HEADER_SIZE))

struct worker_st *global_ws = NULL;

static int terminate = 0;
static int terminate_reason = REASON_SERVER_DISCONNECT;

static int parse_cstp_data(struct worker_st *ws, uint8_t * buf, size_t buf_size,
			   time_t);
static int parse_dtls_data(struct worker_st *ws, uint8_t * buf, size_t buf_size,
			   time_t);
static int connect_handler(worker_st * ws);
static void session_info_send(worker_st * ws);
static void set_net_priority(worker_st * ws, int fd, int priority);
static void set_socket_timeout(worker_st * ws, int fd);

static void link_mtu_set(worker_st * ws, unsigned mtu);

static void handle_alarm(int signo)
{
	if (global_ws)
		exit_worker_reason(global_ws, terminate_reason);

	_exit(1);
}

static void handle_term(int signo)
{
	terminate = 1;
	terminate_reason = REASON_SERVER_DISCONNECT;
	alarm(2);		/* force exit by SIGALRM */
}

/* we override that function to force gnutls use poll()
 */
static
int tls_pull_timeout(gnutls_transport_ptr_t ptr, unsigned int ms)
{
	int ret;
	int fd = (long)ptr;
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	ret = poll(&pfd, 1, ms);
	if (ret <= 0)
		return ret;

	return ret;
}

inline static ssize_t dtls_pull_buffer_non_empty(gnutls_transport_ptr_t ptr)
{
	dtls_transport_ptr *p = ptr;
	if (p->msg)
		return 1;
	return 0;
}

static
ssize_t dtls_pull(gnutls_transport_ptr_t ptr, void *data, size_t size)
{
	dtls_transport_ptr *p = ptr;

	if (p->msg) {
		ssize_t need = p->msg->data.len;
		if (need > size) {
			need = size;
		}
		memcpy(data, p->msg->data.data, need);

		udp_fd_msg__free_unpacked(p->msg, NULL);
		p->msg = NULL;
		return need;
	}
	return recv(p->fd, data, size, 0);
}

static
int dtls_pull_timeout(gnutls_transport_ptr_t ptr, unsigned int ms)
{
	int ret;
	dtls_transport_ptr *p = ptr;
	int fd = p->fd;
	struct pollfd pfd;

	if (dtls_pull_buffer_non_empty(ptr)) {
		return 1;
	}

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	ret = poll(&pfd, 1, ms);
	if (ret <= 0)
		return ret;

	return ret;
}

static
ssize_t dtls_push(gnutls_transport_ptr_t ptr, const void *data, size_t size)
{
	dtls_transport_ptr *p = ptr;

	return send(p->fd, data, size, 0);
}

int get_psk_key(gnutls_session_t session,
		const char *username, gnutls_datum_t *key)
{
	struct worker_st *ws = gnutls_session_get_ptr(session);

	key->data = gnutls_malloc(PSK_KEY_SIZE);
	if (key->data == NULL)
		return GNUTLS_E_MEMORY_ERROR;

	memcpy(key->data, ws->master_secret, PSK_KEY_SIZE);
	key->size = PSK_KEY_SIZE;

	return 0;
}

#if GNUTLS_VERSION_NUMBER < 0x030318
# define VERS_STRING "-VERS-TLS-ALL"
#else
# define VERS_STRING "-VERS-ALL"
#endif

#define PSK_LABEL "EXPORTER-openconnect-psk"
#define PSK_LABEL_SIZE sizeof(PSK_LABEL)-1
/* We initial a PSK connection with ciphers and MAC matching the TLS negotiated
 * ciphers and MAC. The key is 32-bytes generated from gnutls_prf_rfc5705()
 * with label being the PSK_LABEL.
 */
static int setup_dtls_psk_keys(gnutls_session_t session, struct worker_st *ws)
{
	int ret;
	char prio_string[256];
	gnutls_mac_algorithm_t mac;
	gnutls_cipher_algorithm_t cipher;

	gnutls_psk_set_server_credentials_function(WSCREDS(ws)->pskcred, get_psk_key);

	if (!ws->session) {
		oclog(ws, LOG_ERR, "cannot setup PSK keys without an encrypted CSTP channel");
		return -1;
	}

	if (WSCONFIG(ws)->match_dtls_and_tls) {
		cipher = gnutls_cipher_get(ws->session);
		mac = gnutls_mac_get(ws->session);

		snprintf(prio_string, sizeof(prio_string), "%s:"VERS_STRING":-CIPHER-ALL:-MAC-ALL:-KX-ALL:+PSK:+VERS-DTLS-ALL:+%s:+%s",
			 WSCONFIG(ws)->priorities, gnutls_mac_get_name(mac), gnutls_cipher_get_name(cipher));
	} else {
		/* if we haven't an associated session, enable all ciphers we would have enabled
		 * otherwise for TLS. */
		snprintf(prio_string, sizeof(prio_string), "%s:"VERS_STRING":-KX-ALL:+PSK:+VERS-DTLS-ALL",
			 WSCONFIG(ws)->priorities);
	}

	ret =
	    gnutls_priority_set_direct(session, prio_string, NULL);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS priority: '%s': %s",
		      prio_string, gnutls_strerror(ret));
		return ret;
	}

	/* we should have used gnutls_prf_rfc5705() but since we don't use
	 * the RFC5705 context, the output is identical with gnutls_prf(). The
	 * latter is available in much earlier versions of gnutls. */
	ret = gnutls_prf(ws->session, PSK_LABEL_SIZE, PSK_LABEL, 0, 0, 0, PSK_KEY_SIZE,	(char*)ws->master_secret);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error in PSK key generation: %s",
		      gnutls_strerror(ret));
		return ret;
	}

	ret =
	    gnutls_credentials_set(session, GNUTLS_CRD_PSK,
				   WSCREDS(ws)->pskcred);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS PSK credentials: %s",
		      gnutls_strerror(ret));
		return ret;
	}

	return 0;
}

static int setup_legacy_dtls_keys(gnutls_session_t session, struct worker_st *ws)
{
	int ret;
	gnutls_datum_t master =
	    { ws->master_secret, sizeof(ws->master_secret) };
	gnutls_datum_t sid = { ws->session_id, sizeof(ws->session_id) };

	if (ws->req.selected_ciphersuite == NULL) {
		oclog(ws, LOG_ERR, "no DTLS ciphersuite negotiated");
		return -1;
	}

	ret =
	    gnutls_priority_set_direct(session,
				       ws->req.
				       selected_ciphersuite->gnutls_name, NULL);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS priority: %s",
		      gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_session_set_premaster(session, GNUTLS_SERVER,
					   ws->req.
					   selected_ciphersuite->gnutls_version,
					   ws->req.
					   selected_ciphersuite->gnutls_kx,
					   ws->req.
					   selected_ciphersuite->gnutls_cipher,
					   ws->req.
					   selected_ciphersuite->gnutls_mac,
					   GNUTLS_COMP_NULL, &master, &sid);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS premaster: %s",
		      gnutls_strerror(ret));
		return ret;
	}

	gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);

	ret =
	    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				   WSCREDS(ws)->xcred);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS credentials: %s",
		      gnutls_strerror(ret));
		return ret;
	}

	return 0;
}

static int setup_dtls_connection(struct worker_st *ws)
{
	int ret;
	gnutls_session_t session;
#if defined(CAPTURE_LATENCY_SUPPORT)
	int ts_socket_opt = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
#endif

	/* DTLS cookie verified.
	 * Initialize session.
	 */
	ret = gnutls_init(&session, GNUTLS_SERVER|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not initialize TLS session: %s",
		      gnutls_strerror(ret));
		return -1;
	}

	gnutls_session_set_ptr(session, ws);

	if (ws->req.use_psk && ws->session) {
		oclog(ws, LOG_INFO, "setting up DTLS-PSK connection");
		ret = setup_dtls_psk_keys(session, ws);
	} else {
		if (!WSCONFIG(ws)->dtls_legacy) {
			oclog(ws, LOG_INFO, "CISCO client compatibility (dtls-legacy) is disabled; will not setup a DTLS session");
			goto fail;
		}
		oclog(ws, LOG_INFO, "setting up legacy DTLS (resumption) connection");
		ret = setup_legacy_dtls_keys(session, ws);
	}

	if (ret < 0) {
		goto fail;
	}

	gnutls_transport_set_push_function(session, dtls_push);
#if defined(CAPTURE_LATENCY_SUPPORT)
	gnutls_transport_set_pull_function(session, dtls_pull_latency);
#else
	gnutls_transport_set_pull_function(session, dtls_pull);
#endif
	gnutls_transport_set_pull_timeout_function(session, dtls_pull_timeout);
	gnutls_transport_set_ptr(session, &ws->dtls_tptr);

	/* we decrease the default retransmission timeout to bring
	 * our DTLS support in par with the DTLS1.3 recommendations.
	 */
	gnutls_dtls_set_timeouts(session, 400, 60*1000);

	ws->udp_state = UP_HANDSHAKE;

#if defined(CAPTURE_LATENCY_SUPPORT)
	ret = setsockopt(ws->dtls_tptr.fd, SOL_SOCKET, SO_TIMESTAMPING, &ts_socket_opt, sizeof(ts_socket_opt));
	if (ret == -1)
		oclog(ws, LOG_DEBUG, "setsockopt(UDP, SO_TIMESTAMPING), failed.");
#endif

	/* Setup the fd settings */
	if (WSCONFIG(ws)->output_buffer > 0) {
		int t = MIN(2048, ws->link_mtu * WSCONFIG(ws)->output_buffer);
		ret = setsockopt(ws->dtls_tptr.fd, SOL_SOCKET, SO_SNDBUF, &t,
			   sizeof(t));
		if (ret == -1)
			oclog(ws, LOG_DEBUG,
			      "setsockopt(UDP, SO_SNDBUF) to %u, failed.",
			      t);
	}
	set_net_priority(ws, ws->dtls_tptr.fd, ws->user_config->net_priority);
	set_socket_timeout(ws, ws->dtls_tptr.fd);

	/* reset MTU */
	link_mtu_set(ws, ws->adv_link_mtu);

	if (ws->dtls_session != NULL) {
		gnutls_deinit(ws->dtls_session);
	}

	ws->dtls_session = session;

	return 0;
 fail:
	gnutls_deinit(session);
	return -1;
}

void ws_add_score_to_ip(worker_st *ws, unsigned points, unsigned final)
{
	int ret, e;
	BanIpMsg msg = BAN_IP_MSG__INIT;
	BanIpReplyMsg *reply = NULL;
	PROTOBUF_ALLOCATOR(pa, ws);

	/* no reporting if banning is disabled */
	if (WSCONFIG(ws)->max_ban_score == 0)
		return;

	/* In final call, no score added, we simply send */
	if (final == 0) {
		ws->ban_points += points;
		/* do not use IPC for small values */
		if (points < WSCONFIG(ws)->ban_points_wrong_password)
			return;
	}

	msg.ip = ws->remote_ip_str;
	msg.score = points;

	ret = send_msg(ws, ws->cmd_fd, CMD_BAN_IP, &msg,
				(pack_size_func) ban_ip_msg__get_packed_size,
				(pack_func) ban_ip_msg__pack);
	if (ret < 0) {
		e = errno;
		oclog(ws, LOG_WARNING, "error in sending BAN IP message: %s", strerror(e));
		return;
	}

	ret = recv_msg(ws, ws->cmd_fd, CMD_BAN_IP_REPLY,
		       (void *)&reply, (unpack_func) ban_ip_reply_msg__unpack, DEFAULT_SOCKET_TIMEOUT);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error receiving BAN IP reply message");
		return;
	}

	if (final ==0 && reply->reply != AUTH__REP__OK) {
		/* we have exceeded the maximum score */
		exit(1);
	}

	ban_ip_reply_msg__free_unpacked(reply, &pa);

	return;
}

void send_stats_to_secmod(worker_st * ws, time_t now, unsigned discon_reason)
{
	CliStatsMsg msg = CLI_STATS_MSG__INIT;
	int sd, ret, e;

	/* this is only used by certain tests */
	if (WSPCONFIG(ws)->debug_no_secmod_stats != 0)
		return;

	ws->last_stats_msg = now;

	sd = connect_to_secmod(ws);
	if (sd >= 0) {
		char buf[64];
		msg.bytes_in = ws->tun_bytes_in;
		msg.bytes_out = ws->tun_bytes_out;
		msg.uptime = now - ws->session_start_time;
		msg.sid.len = sizeof(ws->sid);
		msg.sid.data = ws->sid;
		msg.has_sid = 1;

		if (discon_reason) {
			msg.has_discon_reason = 1;
			msg.discon_reason = discon_reason;
		}

		msg.remote_ip = human_addr2((void *)&ws->remote_addr, ws->remote_addr_len,
		       		     buf, sizeof(buf), 0);

		msg.ipv4 = ws->vinfo.ipv4;
		msg.ipv6 = ws->vinfo.ipv6;

		ret = send_msg_to_secmod(ws, sd, CMD_SEC_CLI_STATS, &msg,
				 (pack_size_func)cli_stats_msg__get_packed_size,
				 (pack_func) cli_stats_msg__pack);
		if (discon_reason) /* wait for sec-mod to close connection to verify data have been accounted */
			(void)read(sd, buf, sizeof(buf));
		close(sd);

		if (ret >= 0) {
			oclog(ws, LOG_INFO,
			      "sent periodic stats (in: %lu, out: %lu) to sec-mod",
			      (unsigned long)msg.bytes_in,
			      (unsigned long)msg.bytes_out);
		} else {
			e = errno;
			oclog(ws, LOG_WARNING, "could not send periodic stats to sec-mod: %s\n", strerror(e));
		}
	}
}

/* Terminates the worker process, but communicates any required
 * data to main process before (stats/ban points).
 */
void exit_worker(worker_st * ws)
{
	exit_worker_reason(ws, REASON_ANY);
}

void exit_worker_reason(worker_st * ws, unsigned reason)
{
	/* send statistics to parent */
	if (ws->auth_state == S_AUTH_COMPLETE) {
		send_stats_to_secmod(ws, time(0), reason);
	}

	if (ws->ban_points > 0)
		ws_add_score_to_ip(ws, 0, 1);

	talloc_free(ws->main_pool);
	closelog();
	_exit(1);
}

#define HANDSHAKE_SESSION_ID_POS (34)
#define SKIP_V16(pos, total) \
	{ uint16_t _s; \
	  if (pos+2 > total) goto finish; \
	  _s = (msg->data[pos] << 8) | msg->data[pos+1]; \
	  if (pos+2+_s > total) goto finish; \
	  pos += 2+_s; \
	}

#define SKIP16(pos, total) \
	  if (pos+2 > total) goto finish; \
	  pos += 2

#define SKIP8(pos, total) \
	  if (pos+1 > total) goto finish; \
	  pos++

#define SKIP_V8(pos, total) \
	{ uint8_t _s; \
	  if (pos+1 > total) goto finish; \
	  _s = msg->data[pos]; \
	  if (pos+1+_s > total) goto finish; \
	  pos += 1+_s; \
	}

#define SET_VHOST_CREDS \
	ret = \
	    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, \
				   WSCREDS(ws)->xcred); \
	GNUTLS_FATAL_ERR(ret); \
	gnutls_certificate_server_set_request(session, WSCONFIG(ws)->cert_req); \
	ret = gnutls_priority_set(session, WSCREDS(ws)->cprio); \
	GNUTLS_FATAL_ERR(ret); \
	gnutls_db_set_cache_expiration(session, TLS_SESSION_EXPIRATION_TIME(WSCONFIG(ws)))

/* Parse the TLS client hello to figure vhost */
static int hello_hook_func(gnutls_session_t session, unsigned int htype,
			   unsigned when, unsigned int incoming,
			   const gnutls_datum_t *msg)

{
	ssize_t ret;
	size_t pos;
	size_t hsize;
	struct worker_st *ws = gnutls_session_get_ptr(session);

	if (htype != GNUTLS_HANDSHAKE_CLIENT_HELLO || when != GNUTLS_HOOK_PRE)
		goto finish;

	/* find the server name extension */

	pos = HANDSHAKE_SESSION_ID_POS;
	if (msg->size <= pos)
		goto finish;

	if (msg->data[0] != 0x03) {
		/* unknown packet version */
		goto finish;
	}

	/* skip session id */
	SKIP_V8(pos, msg->size);

	/* CipherSuites */
	SKIP_V16(pos, msg->size);

	/* legacy_compression_methods */
	SKIP_V8(pos, msg->size);

	/* Skip extension total size */
	SKIP16(pos, msg->size);

	while (pos < msg->size) {
		uint16_t type;

		/* read ExtensionType */
		SKIP16(pos, msg->size);
		type = (msg->data[pos-2] << 8) | msg->data[pos-1];

		if (type == 0) { /* server name ext */
			SKIP16(pos, msg->size);
			SKIP16(pos, msg->size); /* we don't support anything but a single name */

			SKIP8(pos, msg->size);
			if (msg->data[pos-1] != 0) { /* HostName */
				oclog(ws, LOG_DEBUG,
				      "received server name extension with invalid name type field");
				goto finish;
			}

			SKIP16(pos, msg->size);
			hsize = (msg->data[pos-2] << 8) | msg->data[pos-1];

			if (hsize == 0 || hsize + pos > msg->size || hsize > sizeof(ws->buffer)-1) {
				oclog(ws, LOG_DEBUG,
				      "received server name extension with too large name");
				goto finish;
			}

			memcpy(ws->buffer, &msg->data[pos], hsize);
			ws->buffer[hsize] = 0;

			oclog(ws, LOG_DEBUG,
			      "client requested hostname: %s", (char*)ws->buffer);

			ws->vhost = find_vhost(ws->vconfig, (char*)ws->buffer);
			if (ws->vhost->name && c_strcasecmp(ws->vhost->name, (char*)ws->buffer) != 0) {
				oclog(ws, LOG_INFO,
				      "client requested hostname %s does not match known vhost", (char*)ws->buffer);
			}

			goto finish;
		} else {
			SKIP_V16(pos, msg->size);
		}
	}

 finish:
	/* We set credentials irrespective of whether a virtual host was found,
	 * as they have not been previously set. */
	SET_VHOST_CREDS;

	return 0;
}

#if GNUTLS_VERSION_NUMBER < 0x030400
# define SIMULATE_CLIENT_HELLO_HOOK
#endif

#ifdef SIMULATE_CLIENT_HELLO_HOOK
#define TLS_RECORD_HEADER 5
#define TLS_HANDSHAKE_HEADER 4

/* In gnutls 3.3 we don't get the size in the handshake callback
 * so we try to simulate.
 */
static void peek_client_hello(struct worker_st *ws, gnutls_session_t session, int fd)
{
	unsigned read_tries = 0;
	int ret;
	size_t size, hsize;
	gnutls_datum_t msg;

	do {
		if (read_tries > 0) {
			if (read_tries > 5)
				goto fallback;
			ms_sleep(150);
		}
		read_tries++;

		ret = recv(fd, ws->buffer, sizeof(ws->buffer), MSG_PEEK);
		if (ret == -1)
			goto fallback;
		size = ret;

		if (size < TLS_RECORD_HEADER)
			goto fallback;

		hsize = (ws->buffer[3] << 8) | ws->buffer[4];
	} while(hsize+TLS_RECORD_HEADER > size);

	if (size < TLS_RECORD_HEADER+TLS_HANDSHAKE_HEADER+HANDSHAKE_SESSION_ID_POS)
		goto fallback;

	msg.data = ws->buffer + TLS_RECORD_HEADER+TLS_HANDSHAKE_HEADER;
	msg.size = size - (TLS_RECORD_HEADER+TLS_HANDSHAKE_HEADER);
	hello_hook_func(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
			GNUTLS_HOOK_PRE, 1, &msg);

	return;

 fallback:
	SET_VHOST_CREDS;
}
#endif

/* vpn_server:
 * @ws: an initialized worker structure
 *
 * This is the main worker process. It is executed
 * by the main server after fork and drop of privileges.
 *
 * It handles the client connection including:
 *  - HTTPS authentication using XML forms that are parsed and
 *    forwarded to main.
 *  - TLS authentication (using certificate)
 *  - TCP VPN tunnel establishment (after HTTP CONNECT)
 *  - UDP VPN tunnel establishment (once an FD is forwarded by main)
 *
 */
void vpn_server(struct worker_st *ws)
{
	int ret;
	ssize_t nparsed, nrecvd;
	gnutls_session_t session = NULL;
	http_parser parser;
	http_parser_settings settings;
	url_handler_fn fn;
	int requests_left = MAX_HTTP_REQUESTS;

	ocsigaltstack(ws);

	ocsignal(SIGTERM, handle_term);
	ocsignal(SIGINT, handle_term);
	ocsignal(SIGHUP, SIG_IGN);
	ocsignal(SIGALRM, handle_alarm);

	global_ws = ws;
	if (GETCONFIG(ws)->auth_timeout) {
		terminate_reason = REASON_SERVER_DISCONNECT;
		alarm(GETCONFIG(ws)->auth_timeout);
	}

	/* do not allow this process to be traced. That
	 * prevents worker processes tracing each other. */
	if (GETPCONFIG(ws)->debug == 0)
		pr_set_undumpable("worker");
	if (GETCONFIG(ws)->isolate != 0) {
		ret = disable_system_calls(ws);
		if (ret < 0) {
			oclog(ws, LOG_INFO,
			      "could not disable system calls, kernel might not support seccomp");
		}
	}

	if (ws->remote_addr_len == sizeof(struct sockaddr_in))
		ws->proto = AF_INET;
	else
		ws->proto = AF_INET6;

	if (GETCONFIG(ws)->listen_proxy_proto) {
		oclog(ws, LOG_DEBUG, "accepted proxy protocol connection");
		ret = parse_proxy_proto_header(ws, ws->conn_fd);
		if (ret < 0) {
			oclog(ws, LOG_ERR,
			      "could not parse proxy protocol header; discarding connection");
			exit_worker(ws);
		}
	} else {
		oclog(ws, LOG_DEBUG, "accepted connection");
	}

	if (ws->conn_type != SOCK_TYPE_UNIX) {
		/* ws->vhost is being assigned in gnutls_handshake()
		 * after client hello is received. We set temporarily a value
		 * as we need to set some cipher priorities for handshake to start. */
		ws->vhost = find_vhost(ws->vconfig, NULL);

		/* initialize the session */
		ret = gnutls_init(&session, GNUTLS_SERVER);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_priority_set(session, WSCREDS(ws)->cprio);
		GNUTLS_FATAL_ERR(ret);
		gnutls_session_set_ptr(session, ws);

		/* if we have a single vhost, avoid going through a callback to set credentials. */
		if (!HAVE_VHOSTS(ws)) {
			SET_VHOST_CREDS;
		} else {
#ifdef SIMULATE_CLIENT_HELLO_HOOK
			peek_client_hello(ws, session, ws->conn_fd);
#else
			gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
							   GNUTLS_HOOK_PRE, hello_hook_func);
#endif
		}

		gnutls_transport_set_ptr(session,
				 (gnutls_transport_ptr_t) (long)ws->conn_fd);

		set_resume_db_funcs(session);
		gnutls_db_set_ptr(session, ws);

		gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
		gnutls_transport_set_pull_timeout_function(session, tls_pull_timeout);
		do {
			ret = gnutls_handshake(session);
		} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
		GNUTLS_FATAL_ERR(ret);

		oclog(ws, LOG_DEBUG, "TLS handshake completed");
	} else {
		ws->vhost = find_vhost(ws->vconfig, NULL);

		oclog(ws, LOG_DEBUG, "Accepted unix connection");
	}

	ws->session = session;

	session_info_send(ws);

	memset(&settings, 0, sizeof(settings));

	ws->selected_auth = &WSPCONFIG(ws)->auth[0];
	if (ws->cert_auth_ok)
		ws_switch_auth_to(ws, AUTH_TYPE_CERTIFICATE);

	settings.on_url = http_url_cb;
	settings.on_header_field = http_header_field_cb;
	settings.on_header_value = http_header_value_cb;
	settings.on_headers_complete = http_header_complete_cb;
	settings.on_message_complete = http_message_complete_cb;
	settings.on_body = http_body_cb;
	http_req_init(ws);

	if (WSCONFIG(ws)->listen_proxy_proto) {
		oclog(ws, LOG_DEBUG, "proxy-hdr: peer is %s\n", ws->remote_ip_str);
	}

	ws->parser = &parser;

 restart:
	if (requests_left-- <= 0) {
		oclog(ws, LOG_INFO, "maximum number of HTTP requests reached");
		exit_worker(ws);
	}

	http_parser_init(&parser, HTTP_REQUEST);
	parser.data = ws;
	http_req_reset(ws);
	/* parse as we go */
	do {
		nrecvd = cstp_recv(ws, ws->buffer, sizeof(ws->buffer));
		if (nrecvd <= 0) {
			if (nrecvd == 0)
				goto finish;
			if (nrecvd != GNUTLS_E_PREMATURE_TERMINATION)
				oclog(ws, LOG_ERR,
				      "error receiving client data");
			exit_worker(ws);
		}

		nparsed =
		    http_parser_execute(&parser, &settings, (void *)ws->buffer,
					nrecvd);
		if (nparsed == 0) {
			oclog(ws, LOG_INFO, "error parsing HTTP request");
			exit_worker(ws);
		}
	} while (ws->req.headers_complete == 0);

	if (parser.method == HTTP_GET) {
		oclog(ws, LOG_HTTP_DEBUG, "HTTP GET %s", ws->req.url);
		fn = http_get_url_handler(ws->req.url);
		if (fn == NULL) {
			oclog(ws, LOG_HTTP_DEBUG, "unexpected URL %s", ws->req.url);
			response_404(ws, parser.http_minor);
			goto finish;
		}
		ret = fn(ws, parser.http_minor);
		if (ret == 0
		    && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else if (parser.method == HTTP_POST) {
		/* continue reading */
		oclog(ws, LOG_HTTP_DEBUG, "HTTP POST %s", ws->req.url);
		while (ws->req.message_complete == 0) {
			nrecvd = cstp_recv(ws, ws->buffer, sizeof(ws->buffer));
			CSTP_FATAL_ERR(ws, nrecvd);

			if (nrecvd == 0) {
				oclog(ws, LOG_HTTP_DEBUG,
				      "EOF while receiving HTTP POST request");
				exit_worker(ws);
			}

			nparsed =
			    http_parser_execute(&parser, &settings, (void *)ws->buffer,
						nrecvd);
			if (nparsed == 0) {
				oclog(ws, LOG_HTTP_DEBUG,
				      "error parsing HTTP POST request");
				exit_worker(ws);
			}
		}

		fn = http_post_url_handler(ws, ws->req.url);
		if (fn == NULL) {
			oclog(ws, LOG_HTTP_DEBUG, "unexpected POST URL %s",
			      ws->req.url);
			response_404(ws, parser.http_minor);
			goto finish;
		}

		ret = fn(ws, parser.http_minor);
		if (ret == 0
		    && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else if (parser.method == HTTP_CONNECT) {
		oclog(ws, LOG_HTTP_DEBUG, "HTTP CONNECT %s", ws->req.url);
		ret = connect_handler(ws);
		if (ret == 0
		    && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else {
		oclog(ws, LOG_HTTP_DEBUG, "unexpected HTTP method %s",
		      http_method_str(parser.method));
		response_404(ws, parser.http_minor);
	}

 finish:
	cstp_close(ws);
}

static
void data_mtu_send(worker_st * ws, unsigned mtu)
{
	TunMtuMsg msg = TUN_MTU_MSG__INIT;

	msg.mtu = mtu;
	send_msg_to_main(ws, CMD_TUN_MTU, &msg,
			 (pack_size_func) tun_mtu_msg__get_packed_size,
			 (pack_func) tun_mtu_msg__pack);

	oclog(ws, LOG_DEBUG, "setting data MTU to %u", msg.mtu);
}

static
void session_info_send(worker_st * ws)
{
	SessionInfoMsg msg = SESSION_INFO_MSG__INIT;

	if (ws->session) {
		msg.tls_ciphersuite = gnutls_session_get_desc(ws->session);
		if (ws->cstp_selected_comp)
			msg.cstp_compr = (char*)ws->cstp_selected_comp->name;
	}

	if (ws->udp_state != UP_DISABLED && ws->dtls_session) {
		msg.dtls_ciphersuite =
		    gnutls_session_get_desc(ws->dtls_session);
		if (ws->dtls_selected_comp)
			msg.dtls_compr = (char*)ws->dtls_selected_comp->name;
	}

	if (WSCONFIG(ws)->listen_proxy_proto) {
		msg.our_addr.data = (uint8_t*)&ws->our_addr;
		msg.our_addr.len = ws->our_addr_len;
		msg.has_our_addr = 1;
		msg.remote_addr.data = (uint8_t*)&ws->remote_addr;
		msg.remote_addr.len = ws->remote_addr_len;
		msg.has_remote_addr = 1;
	}

	send_msg_to_main(ws, CMD_SESSION_INFO, &msg,
			 (pack_size_func) session_info_msg__get_packed_size,
			 (pack_func) session_info_msg__pack);

	gnutls_free(msg.tls_ciphersuite);
	gnutls_free(msg.dtls_ciphersuite);
}

/* link_mtu_set: Sets the link MTU for the session
 *
 * @ws: a worker structure
 * @mtu: the link MTU
 */
static
void link_mtu_set(worker_st * ws, unsigned mtu)
{
	if (ws->link_mtu == mtu || mtu > sizeof(ws->buffer))
		return;

	ws->link_mtu = mtu;

	oclog(ws, LOG_DEBUG, "setting connection link MTU to %u", mtu);
	if (ws->dtls_session)
		gnutls_dtls_set_mtu(ws->dtls_session,
				    ws->link_mtu - ws->dtls_proto_overhead);

	data_mtu_send(ws, DATA_MTU(ws, ws->link_mtu));
}

/* data_mtu_set: Sets the data MTU for the session
 *
 * @ws: a worker structure
 * @mtu: the "plaintext" data MTU (not including the DTLS protocol byte)
 */
static
void data_mtu_set(worker_st * ws, unsigned mtu)
{
	if (ws->dtls_session) {
		gnutls_dtls_set_data_mtu(ws->dtls_session, mtu+1);

		mtu = gnutls_dtls_get_mtu(ws->dtls_session);
		if (mtu <= 0 || mtu == ws->link_mtu)
			return;

		mtu += ws->dtls_proto_overhead;
		link_mtu_set(ws, mtu);
	}
}

static void disable_mtu_disc(worker_st *ws)
{
	oclog(ws, LOG_DEBUG, "disabling MTU discovery on UDP socket");
	set_mtu_disc(ws->dtls_tptr.fd, ws->proto, 0);
	link_mtu_set(ws, ws->adv_link_mtu);
	WSCONFIG(ws)->try_mtu = 0;
}

/* sets the current value of mtu as bad,
 * and returns an estimation of good.
 *
 * Returns -1 on failure.
 */
static
int mtu_not_ok(worker_st * ws)
{
	if (WSCONFIG(ws)->try_mtu == 0 || ws->dtls_session == NULL)
		return 0;

	if (ws->proto == AF_INET) {
		const unsigned min = MIN_MTU(ws);

		ws->last_bad_mtu = ws->link_mtu;

		if (ws->last_good_mtu == min) {
			oclog(ws, LOG_INFO,
			      "could not calculate a sufficient MTU; disabling MTU discovery");
			disable_mtu_disc(ws);
			link_mtu_set(ws, min);
			return 0;
		}

		if (ws->last_good_mtu >= ws->link_mtu) {
			ws->last_good_mtu = MAX(((2 * (ws->link_mtu)) / 3), min);
		}

		link_mtu_set(ws, ws->last_good_mtu);
		oclog(ws, LOG_INFO, "MTU %u is too large, switching to %u",
		      ws->last_bad_mtu, ws->link_mtu);
	} else if (ws->proto == AF_INET6) { /* IPv6 */
#ifdef IPV6_PATHMTU
		struct ip6_mtuinfo mtuinfo;
		socklen_t len = sizeof(mtuinfo);

		if (getsockopt(ws->dtls_tptr.fd, IPPROTO_IPV6, IPV6_PATHMTU, &mtuinfo, &len) < 0 || mtuinfo.ip6m_mtu < 1280) {
			oclog(ws, LOG_INFO, "cannot obtain IPv6 MTU (was %u); disabling MTU discovery",
			      ws->link_mtu);
			disable_mtu_disc(ws);
			link_mtu_set(ws, MIN_MTU(ws));
			return 0;
		}

		oclog(ws, LOG_DEBUG, "setting (via IPV6_PATHMTU) connection MTU to %u", mtuinfo.ip6m_mtu);
		link_mtu_set(ws, mtuinfo.ip6m_mtu);

		if (mtuinfo.ip6m_mtu > ws->adv_link_mtu) {
			oclog(ws, LOG_INFO, "the discovered IPv6 MTU (%u) is larger than the advertised (%u); disabling MTU discovery",
			      (unsigned)mtuinfo.ip6m_mtu, ws->adv_link_mtu);
			return 0;
		}
#else
		link_mtu_set(ws, MIN_MTU(ws));
#endif
	}

	return 0;
}

/* mtu_discovery_init: initiates MTU discovery
 *
 * @ws: a worker structure
 * @mtu: the current "plaintext" data MTU
 */
static void mtu_discovery_init(worker_st * ws, unsigned mtu)
{
	const unsigned min = MIN_MTU(ws);
	if (mtu <= min) {
		oclog(ws, LOG_INFO,
		      "our initial MTU is too low; disabling MTU discovery");
		disable_mtu_disc(ws);
	}

	if (!WSCONFIG(ws)->try_mtu)
		oclog(ws, LOG_DEBUG,
		      "Initializing MTU discovery; initial MTU: %u\n", mtu);

	ws->last_good_mtu = mtu;
	ws->last_bad_mtu = mtu;
}

static
void mtu_ok(worker_st * ws)
{
	unsigned int c;

	if (WSCONFIG(ws)->try_mtu == 0 || ws->proto == AF_INET6)
		return;

	if (ws->last_bad_mtu == (ws->link_mtu) + 1 ||
	    ws->last_bad_mtu == (ws->link_mtu))
		return;

	ws->last_good_mtu = ws->link_mtu;
	c = (ws->link_mtu + ws->last_bad_mtu) / 2;

	link_mtu_set(ws, c);
	return;
}

#define FUZZ(x, diff, rnd) \
		if (x > diff) { \
			int16_t r = rnd; \
			x += r % diff; \
		}

int get_pmtu_approx(worker_st *ws)
{
	socklen_t sl;
	int ret, e;

#if defined(__linux__) && defined(TCP_INFO)
	struct tcp_info ti;
	sl = sizeof(ti);

	ret = getsockopt(ws->conn_fd, IPPROTO_TCP, TCP_INFO, &ti, &sl);
	if (ret == -1) {
		e = errno;
		oclog(ws, LOG_INFO, "error in getting TCP_INFO: %s",
		      strerror(e));
		return -1;
	} else {
		return ti.tcpi_pmtu;
	}
#else
	int max = -1;

	sl = sizeof(max);
	ret = getsockopt(ws->conn_fd, IPPROTO_TCP, TCP_MAXSEG, &max, &sl);
	if (ret == -1) {
		e = errno;
		oclog(ws, LOG_INFO, "error in getting TCP_MAXSEG: %s",
		      strerror(e));
		return -1;
	} else {
		MSS_ADJUST(max);
		return max;
	}
#endif
}

static
int periodic_check(worker_st * ws, struct timespec *tnow, unsigned dpd)
{
	int max, ret;
	time_t now = tnow->tv_sec;
	time_t periodic_check_time = PERIODIC_CHECK_TIME;

	/* modify timers with a fuzzying factor, to prevent all worker processes
	 * to act at exactly the same time (e.g., after a server restart on which
	 * all clients reconnect at the same time). */
	FUZZ(periodic_check_time, 5, tnow->tv_nsec);

	if (now - ws->last_periodic_check < periodic_check_time)
		return 0;

	/* we set an alarm at each periodic check to prevent any
	 * freezes in the worker due to an unexpected block (due to worker
	 * bug or kernel bug). In that case the worker will be killed due
	 * the the alarm instead of hanging. */
	terminate_reason = REASON_SERVER_DISCONNECT;
	alarm(1800);

	if (WSCONFIG(ws)->idle_timeout > 0) {
		if (now - ws->last_nc_msg > WSCONFIG(ws)->idle_timeout) {
			oclog(ws, LOG_ERR,
			      "idle timeout reached for process (%d secs)",
			      (int)(now - ws->last_nc_msg));
			terminate = 1;
			terminate_reason = REASON_IDLE_TIMEOUT;
			goto cleanup;
		}
	}

	if (ws->user_config->session_timeout_secs > 0) {
		if (now - ws->session_start_time > ws->user_config->session_timeout_secs) {
			oclog(ws, LOG_ERR,
			      "session timeout reached for process (%d secs)",
			      (int)(now - ws->session_start_time));
			terminate = 1;
			terminate_reason = REASON_SESSION_TIMEOUT;
			goto cleanup;
		}
	}

	if (ws->user_config->interim_update_secs > 0 &&
	    now - ws->last_stats_msg >= ws->user_config->interim_update_secs &&
	    ws->sid_set) {
		send_stats_to_secmod(ws, now, 0);
	}

#if defined(CAPTURE_LATENCY_SUPPORT)
	if (now - ws->latency.last_stats_msg >= LATENCY_WORKER_AGGREGATION_TIME) {
		send_latency_stats_delta_to_main(ws, now);
	}
#endif

	/* check DPD. Otherwise exit */
	if (ws->udp_state == UP_ACTIVE &&
	    now - ws->last_msg_udp > DPD_TRIES * dpd && dpd > 0) {
	    	unsigned data_mtu = DATA_MTU(ws, ws->link_mtu);
		oclog(ws, LOG_ERR,
		      "have not received any UDP message or DPD for long (%d secs, DPD is %d)",
		      (int)(now - ws->last_msg_udp), dpd);

		memset(ws->buffer+1, 0, data_mtu);
		ws->buffer[0] = AC_PKT_DPD_OUT;

		ret = dtls_send(ws, ws->buffer, data_mtu+1);
		DTLS_FATAL_ERR_CMD(ret, exit_worker_reason(ws, REASON_ERROR));

		if (now - ws->last_msg_udp > DPD_MAX_TRIES * dpd) {
			oclog(ws, LOG_ERR,
			      "have not received UDP message or DPD for very long; disabling UDP port");
			ws->udp_state = UP_INACTIVE;
		}
	}
	if (dpd > 0 && now - ws->last_msg_tcp > DPD_TRIES * dpd) {
		oclog(ws, LOG_DEBUG,
		      "have not received TCP DPD for long (%d secs)",
		      (int)(now - ws->last_msg_tcp));
		ws->buffer[0] = 'S';
		ws->buffer[1] = 'T';
		ws->buffer[2] = 'F';
		ws->buffer[3] = 1;
		ws->buffer[4] = 0;
		ws->buffer[5] = 0;
		ws->buffer[6] = AC_PKT_DPD_OUT;
		ws->buffer[7] = 0;

		ret = cstp_send(ws, ws->buffer, 8);
		CSTP_FATAL_ERR_CMD(ws, ret, exit_worker_reason(ws, REASON_ERROR));

		if (now - ws->last_msg_tcp > DPD_MAX_TRIES * dpd) {
			oclog(ws, LOG_ERR,
			      "connection timeout (DPD); tearing down connection");
			exit_worker_reason(ws, REASON_DPD_TIMEOUT);
		}
	}

	if (ws->conn_type != SOCK_TYPE_UNIX && ws->udp_state != UP_DISABLED) {
		max = get_pmtu_approx(ws);
		if (max > 0 && max < ws->link_mtu) {
			oclog(ws, LOG_DEBUG, "reducing MTU due to TCP/PMTU to %u",
			      max);
			link_mtu_set(ws, max);
		}
	}

 cleanup:
	ws->last_periodic_check = now;

	return 0;
}

/* Disable any TCP queuing on the TLS port. This allows a connection that works over
 * TCP instead of UDP to still be interactive.
 */
static void set_no_delay(worker_st * ws, int fd)
{
	int flag = 1;
	int ret;

	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	if (ret == -1) {
		oclog(ws, LOG_DEBUG,
		      "setsockopt(TCP_NODELAY) to %x, failed.", (unsigned)flag);
		return;
	}
}

#define TOSCLASS(x) (IPTOS_CLASS_CS##x)

static void set_net_priority(worker_st * ws, int fd, int priority)
{
	int t;
	int ret;
#if defined(IP_TOS)
	if (priority != 0 && IS_TOS(priority)) {
		t = TOS_UNPACK(priority);
		ret = setsockopt(fd, IPPROTO_IP, IP_TOS, &t, sizeof(t));
		if (ret == -1)
			oclog(ws, LOG_DEBUG,
			      "setsockopt(IP_TOS) to %x, failed.", (unsigned)t);

		return;
	}
#endif

#ifdef SO_PRIORITY
	if (priority != 0 && priority <= 7) {
		t = ws->user_config->net_priority - 1;
		ret = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &t, sizeof(t));
		if (ret == -1)
			oclog(ws, LOG_DEBUG,
			      "setsockopt(SO_PRIORITY) to %d, failed.", t);

		return;
	}
#endif
	return;
}

#define SEND_ERR(x) if (x<0) goto send_error

static int dtls_mainloop(worker_st * ws, struct timespec *tnow)
{
	int ret;
	gnutls_datum_t data;
	void *packet = NULL;

	switch (ws->udp_state) {
	case UP_ACTIVE:
	case UP_INACTIVE:
		ret = dtls_recv_packet(ws, &data, &packet);
		oclog(ws, LOG_TRANSFER_DEBUG,
		      "received %d byte(s) (DTLS)", ret);

		DTLS_FATAL_ERR_CMD(ret, exit_worker_reason(ws, REASON_ERROR));

		if (ret == GNUTLS_E_REHANDSHAKE) {

			if (ws->last_dtls_rehandshake > 0 &&
			    tnow->tv_sec - ws->last_dtls_rehandshake <
			    WSCONFIG(ws)->rekey_time / 2) {
				oclog(ws, LOG_INFO,
				      "client requested DTLS rehandshake too soon");
				ret = -1;
				goto cleanup;
			}

			/* there is not much we can rehandshake on the DTLS channel,
			 * at least not the way AnyConnect sets it up.
			 */
			oclog(ws, LOG_DEBUG,
			      "client requested rehandshake on DTLS channel");

			do {
				ret = gnutls_handshake(ws->dtls_session);
			} while (ret == GNUTLS_E_AGAIN
				 || ret == GNUTLS_E_INTERRUPTED);

			DTLS_FATAL_ERR_CMD(ret, exit_worker_reason(ws, REASON_ERROR));
			oclog(ws, LOG_DEBUG, "DTLS rehandshake completed");

			ws->last_dtls_rehandshake = tnow->tv_sec;
		} else if (ret >= 1) {
			/* where we receive any DTLS UDP packet we reset the state
			 * to active */
			ws->udp_state = UP_ACTIVE;

			if (bandwidth_update
			    (&ws->b_rx, data.size - CSTP_DTLS_OVERHEAD, tnow) != 0) {
				ret =
				    parse_dtls_data(ws, data.data, data.size,
						    tnow->tv_sec);
				if (ret < 0) {
					oclog(ws, LOG_INFO,
					      "error parsing CSTP data");
					goto cleanup;
				}
			}
		} else
			oclog(ws, LOG_TRANSFER_DEBUG,
			      "no data received (%d)", ret);

		ws->udp_recv_time = tnow->tv_sec;
		break;
	case UP_SETUP:
		ret = setup_dtls_connection(ws);
		if (ret < 0) {
			ret = -1;
			goto cleanup;
		}

		gnutls_dtls_set_mtu(ws->dtls_session, ws->link_mtu - ws->dtls_proto_overhead);
		mtu_discovery_init(ws, ws->link_mtu);
		break;

	case UP_HANDSHAKE:
 hsk_restart:
		ret = gnutls_handshake(ws->dtls_session);
		if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
			if (ret == GNUTLS_E_FATAL_ALERT_RECEIVED)
				oclog(ws, LOG_ERR,
				      "error in DTLS handshake: %s: %s\n",
				      gnutls_strerror(ret),
				      gnutls_alert_get_name
				      (gnutls_alert_get(ws->dtls_session)));
			else
				oclog(ws, LOG_ERR,
				      "error in DTLS handshake: %s\n",
				      gnutls_strerror(ret));
			ws->udp_state = UP_DISABLED;
			break;
		}

		if (ret == GNUTLS_E_LARGE_PACKET) {
			/* adjust mtu */
			mtu_not_ok(ws);
			goto hsk_restart;
		} else if (ret == 0) {
			unsigned data_mtu;

			/* gnutls_dtls_get_data_mtu() already subtracts the crypto overhead */
			data_mtu =
			    gnutls_dtls_get_data_mtu(ws->dtls_session) -
			    CSTP_DTLS_OVERHEAD;

			ws->udp_state = UP_ACTIVE;
			oclog(ws, LOG_DEBUG,
			      "DTLS handshake completed (link MTU: %u, data MTU: %u)\n",
			      ws->link_mtu, data_mtu);
			session_info_send(ws);
		}

		break;
	default:
		break;
	}

	ret = 0;
 cleanup:
 	packet_deinit(packet);
	return ret;
}

static int tls_mainloop(struct worker_st *ws, struct timespec *tnow)
{
	int ret;
	gnutls_datum_t data;
	void *packet = NULL;

	ret = cstp_recv_packet(ws, &data, &packet);
	if (ret == GNUTLS_E_PREMATURE_TERMINATION) {
		oclog(ws, LOG_DEBUG, "client disconnected prematurely");
		ret = -1;
		goto cleanup;
	}

	CSTP_FATAL_ERR_CMD(ws, ret, exit_worker_reason(ws, REASON_ERROR));

	if (ret == 0) {		/* disconnect */
		oclog(ws, LOG_DEBUG, "client disconnected");
		ret = -1;
		goto cleanup;
	} else if (ret >= 8) {
		oclog(ws, LOG_TRANSFER_DEBUG, "received %d byte(s) (TLS)", data.size);

		if (bandwidth_update(&ws->b_rx, data.size - 8, tnow) != 0) {
			ret = parse_cstp_data(ws, data.data, data.size, tnow->tv_sec);
			if (ret < 0) {
				oclog(ws, LOG_ERR, "error parsing CSTP data");
				goto cleanup;
			}

			if ((ret == AC_PKT_DATA || ret == AC_PKT_COMPRESSED) && ws->udp_state == UP_ACTIVE) {
				/* client switched to TLS for some reason */
				if (tnow->tv_sec - ws->udp_recv_time >
				    UDP_SWITCH_TIME)
					ws->udp_state = UP_INACTIVE;
			}
		}

	} else if (ret == GNUTLS_E_REHANDSHAKE) {
		/* rekey? */
		if (ws->last_tls_rehandshake > 0 &&
		    tnow->tv_sec - ws->last_tls_rehandshake <
		    WSCONFIG(ws)->rekey_time / 2) {
			oclog(ws, LOG_INFO,
			      "client requested TLS rehandshake too soon");
			ret = -1;
			goto cleanup;
		}

		oclog(ws, LOG_INFO,
		      "client requested rehandshake on TLS channel");
		do {
			ret = gnutls_handshake(ws->session);
		} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
		DTLS_FATAL_ERR_CMD(ret, exit_worker_reason(ws, REASON_ERROR));

		ws->last_tls_rehandshake = tnow->tv_sec;
		oclog(ws, LOG_INFO, "TLS rehandshake completed");
	}

	ret = 0;
 cleanup:
 	packet_deinit(packet);
	return ret;
}

static int tun_mainloop(struct worker_st *ws, struct timespec *tnow)
{
	int ret, l, e;
	unsigned tls_retry;
	int dtls_type = AC_PKT_DATA;
	int cstp_type = AC_PKT_DATA;
	gnutls_datum_t dtls_to_send;
	gnutls_datum_t cstp_to_send;

	l = tun_read(ws->tun_fd, ws->buffer + 8, DATA_MTU(ws, ws->link_mtu));
	if (l < 0) {
		e = errno;

		if (e != EAGAIN && e != EINTR) {
			oclog(ws, LOG_ERR,
			      "received corrupt data from tun (%d): %s",
			      l, strerror(e));
			return -1;
		}

		return 0;
	}

	if (l == 0) {
		oclog(ws, LOG_INFO, "TUN device returned zero");
		return 0;
	}


	dtls_to_send.data = ws->buffer;
	dtls_to_send.size = l;

	cstp_to_send.data = ws->buffer;
	cstp_to_send.size = l;

	if (WSCONFIG(ws)->switch_to_tcp_timeout &&
	    ws->udp_state == UP_ACTIVE &&
	    tnow->tv_sec > ws->udp_recv_time + WSCONFIG(ws)->switch_to_tcp_timeout) {
		oclog(ws, LOG_DEBUG, "No UDP data received for %li seconds, using TCP instead\n",
				tnow->tv_sec - ws->udp_recv_time);
		ws->udp_state = UP_INACTIVE;
	}

#ifdef ENABLE_COMPRESSION
	if (ws->udp_state == UP_ACTIVE && ws->dtls_selected_comp != NULL && l > WSCONFIG(ws)->no_compress_limit) {
		/* otherwise don't compress */
		ret = ws->dtls_selected_comp->compress(ws->decomp+8, sizeof(ws->decomp)-8, ws->buffer+8, l);
		oclog(ws, LOG_TRANSFER_DEBUG, "compressed %d to %d\n", (int)l, ret);
		if (ret > 0 && ret < l) {
			dtls_to_send.data = ws->decomp;
			dtls_to_send.size = ret;
			dtls_type = AC_PKT_COMPRESSED;

			if (ws->cstp_selected_comp) {
				if (ws->cstp_selected_comp->id == ws->dtls_selected_comp->id) {
					cstp_to_send.data = ws->decomp;
					cstp_to_send.size = ret;
					cstp_type = AC_PKT_COMPRESSED;
				}
			}
		}
	} else if (ws->cstp_selected_comp != NULL && l > WSCONFIG(ws)->no_compress_limit) {
		/* otherwise don't compress */
		ret = ws->cstp_selected_comp->compress(ws->decomp+8, sizeof(ws->decomp)-8, ws->buffer+8, l);
		oclog(ws, LOG_TRANSFER_DEBUG, "compressed %d to %d\n", (int)l, ret);
		if (ret > 0 && ret < l) {
			cstp_to_send.data = ws->decomp;
			cstp_to_send.size = ret;
			cstp_type = AC_PKT_COMPRESSED;
		}
	}
#endif 

	/* only transmit if allowed */
	if (bandwidth_update(&ws->b_tx, dtls_to_send.size, tnow)
	    != 0) {
		tls_retry = 0;

		oclog(ws, LOG_TRANSFER_DEBUG, "sending %d byte(s)\n", l);

		if (ws->udp_state == UP_ACTIVE) {

			ws->tun_bytes_out += dtls_to_send.size;

			dtls_to_send.data[7] = dtls_type;
			ret = dtls_send(ws, dtls_to_send.data + 7, dtls_to_send.size + 1);
			DTLS_FATAL_ERR_CMD(ret, exit_worker_reason(ws, REASON_ERROR));

			if (ret == GNUTLS_E_LARGE_PACKET) {
				mtu_not_ok(ws);

				oclog(ws, LOG_TRANSFER_DEBUG,
				      "retrying (TLS) %d\n", l);
				tls_retry = 1;
			} else if (ret >= 1+DATA_MTU(ws, ws->link_mtu) &&
				   WSCONFIG(ws)->try_mtu != 0) {
				mtu_ok(ws);
			}
		}

		if (ws->udp_state != UP_ACTIVE || tls_retry != 0) {
			cstp_to_send.data[0] = 'S';
			cstp_to_send.data[1] = 'T';
			cstp_to_send.data[2] = 'F';
			cstp_to_send.data[3] = 1;
			cstp_to_send.data[4] = cstp_to_send.size >> 8;
			cstp_to_send.data[5] = cstp_to_send.size & 0xff;
			cstp_to_send.data[6] = cstp_type;
			cstp_to_send.data[7] = 0;

			ws->tun_bytes_out += cstp_to_send.size;

			ret = cstp_send(ws, cstp_to_send.data, cstp_to_send.size + 8);
			CSTP_FATAL_ERR_CMD(ws, ret, exit_worker_reason(ws, REASON_ERROR));
		}
		ws->last_nc_msg = tnow->tv_sec;
	}

	return 0;
}

static
char *replace_vals(worker_st *ws, const char *txt)
{
	str_st str;
	int ret;
	str_rep_tab tab[3];

	STR_TAB_SET(0, "%{U}", ws->username);
	STR_TAB_SET(1, "%{G}", ws->groupname);
	STR_TAB_TERM(2);

	str_init(&str, ws);

	ret = str_append_str(&str, txt);
	if (ret < 0)
		return NULL;

	ret = str_replace_str(&str, tab);
	if (ret < 0) {
		str_clear(&str);
		return NULL;
	}

	return (char*)str.data;
}

static int send_routes(worker_st *ws, struct http_req_st *req,
		       char **routes, unsigned routes_size,
		       bool include)
{
	unsigned i;
	unsigned ip6;
	const char *txt;
	int ret;

	if (include)
		txt = "Include";
	else
		txt = "Exclude";

	for (i = 0; i < routes_size; i++) {
		if (strchr(routes[i], ':') != 0)
			ip6 = 1;
		else
			ip6 = 0;

		if (req->no_ipv6 != 0 && ip6 != 0)
			continue;
		if (req->no_ipv4 != 0 && ip6 == 0)
			continue;
		oclog(ws, LOG_INFO, "%s route %s", txt, routes[i]);

		if (ip6 != 0 && ws->full_ipv6) {
			ret = cstp_printf(ws,
				 "X-CSTP-Split-%s-IP6: %s\r\n",
				 txt, routes[i]);
		} else {
			ret = cstp_printf(ws,
				 "X-CSTP-Split-%s: %s\r\n",
				 txt, routes[i]);
		}
		if (ret < 0)
			return ret;
	}
	return 0;
}

/* Enforces a socket timeout. That is because, although we
 * use poll() to see whether a call to recv() would block,
 * there are certain cases in Linux where recv() blocks even
 * though poll() notified of data */
static void set_socket_timeout(worker_st * ws, int fd)
{
	struct timeval tval;
	int ret;

	tval.tv_sec = DEFAULT_SOCKET_TIMEOUT;
	tval.tv_usec = 0;
	ret =
	    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tval,
			       sizeof(tval));
	if (ret == -1) {
		int e = errno;
		oclog(ws, LOG_DEBUG,
		      "setsockopt(%s, SO_RCVTIMEO) failed: %s", (fd==ws->conn_fd)?"ΤCP":"UDP", strerror(e));
	}
}

/* wild but conservative guess; this ciphersuite has the largest overhead */
#define MAX_CSTP_CRYPTO_OVERHEAD (CSTP_OVERHEAD+tls_get_overhead(GNUTLS_TLS1_0, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1))
#define MAX_DTLS_CRYPTO_OVERHEAD (CSTP_DTLS_OVERHEAD+tls_get_overhead(GNUTLS_DTLS1_0, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1))
#define MAX_DTLS_PROTO_OVERHEAD(ws) ((ws->proto == AF_INET)?(IP_HEADER_SIZE+UDP_HEADER_SIZE):(IPV6_HEADER_SIZE+UDP_HEADER_SIZE))

/* Calculate MTU for CSTP and DTLS channels.
 */
static void calc_mtu_values(worker_st * ws)
{
	/* assume that if IPv6 is used over TCP then the same would be used over UDP */
	if (ws->proto == AF_INET) {
		ws->cstp_proto_overhead = IP_HEADER_SIZE;
		ws->dtls_proto_overhead = IP_HEADER_SIZE;
	} else {
		ws->cstp_proto_overhead = IPV6_HEADER_SIZE;
		ws->dtls_proto_overhead = IPV6_HEADER_SIZE;
	}
	ws->cstp_proto_overhead += TCP_HEADER_SIZE;
	ws->dtls_proto_overhead += UDP_HEADER_SIZE;

	if (ws->session == NULL) {
		ws->cstp_crypto_overhead = MAX_CSTP_CRYPTO_OVERHEAD;
	} else {
		ws->cstp_crypto_overhead = CSTP_OVERHEAD +
		    tls_get_overhead(gnutls_protocol_get_version(ws->session),
				     gnutls_cipher_get(ws->session),
				     gnutls_mac_get(ws->session));
	}

	/* link MTU is the device MTU */
	ws->link_mtu = ws->vinfo.mtu;

	if (ws->udp_state != UP_DISABLED) {
		/* crypto overhead for DTLS */
		if (ws->req.use_psk) {
			if (ws->session == NULL) {
				ws->dtls_crypto_overhead = MAX_DTLS_CRYPTO_OVERHEAD;
			} else {
				ws->dtls_crypto_overhead = tls_get_overhead(
						GNUTLS_DTLS1_0,
						gnutls_cipher_get(ws->session),
						gnutls_mac_get(ws->session));
			}
		} else if (ws->req.selected_ciphersuite) {
			ws->dtls_crypto_overhead =
			    tls_get_overhead(ws->req.
					     selected_ciphersuite->gnutls_version,
					     ws->req.
					     selected_ciphersuite->gnutls_cipher,
					     ws->req.selected_ciphersuite->gnutls_mac);
		}
		ws->dtls_crypto_overhead += CSTP_DTLS_OVERHEAD;

		oclog(ws, LOG_DEBUG,
		      "DTLS overhead is %u",
		      ws->dtls_proto_overhead + ws->dtls_crypto_overhead);
	}

	/* This is the data MTU we advertised to peer, we will never exceed this value */
	ws->adv_link_mtu = ws->link_mtu;
}

/* connect_handler:
 * @ws: an initialized worker structure
 *
 * This function handles the HTTPS session after a CONNECT
 * command has been issued by the peer. The @ws->auth_state
 * should be set to %S_AUTH_COMPLETE or the client will be
 * disconnected.
 *
 * If the user is authenticate it handles the TCP and UDP VPN
 * tunnels.
 *
 */
static int connect_handler(worker_st * ws)
{
	struct http_req_st *req = &ws->req;
	struct pollfd pfd[4];
	unsigned pfd_size;
	int max, ret, t;
	char *p;
	unsigned rnd;
#ifdef HAVE_PPOLL
	struct timespec tv;
#endif
	unsigned tls_pending, dtls_pending = 0, i;
	struct timespec tnow;
	unsigned ip6;
	sigset_t emptyset, blockset;

	sigemptyset(&blockset);
	sigemptyset(&emptyset);
	sigaddset(&blockset, SIGTERM);

	gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(rnd));

	ws->buffer_size = sizeof(ws->buffer);

	cookie_authenticate_or_exit(ws);

	if (strcmp(req->url, "/CSCOSSLC/tunnel") != 0) {
		oclog(ws, LOG_INFO, "bad connect request: '%s'\n", req->url);
		response_404(ws, 1);
		cstp_fatal_close(ws, GNUTLS_A_ACCESS_DENIED);
		exit_worker(ws);
	}

	if (WSCONFIG(ws)->network.name[0] == 0) {
		oclog(ws, LOG_ERR,
		      "no networks are configured; rejecting client");
		cstp_puts(ws, "HTTP/1.1 503 Service Unavailable\r\n");
		cstp_puts(ws,
			 "X-Reason: Server configuration error\r\n\r\n");
		return -1;
	}

	ret = complete_vpn_info(ws, &ws->vinfo);
	if (ret < 0) {
		oclog(ws, LOG_ERR,
		      "no networks are configured; rejecting client");
		cstp_puts(ws, "HTTP/1.1 503 Service Unavailable\r\n");
		cstp_puts(ws,
			 "X-Reason: Server configuration error\r\n\r\n");
		return -1;
	}

	/* override any hostname sent by the peer if we have one already configured */
	if (ws->user_config->hostname) {
		strlcpy(ws->req.hostname, ws->user_config->hostname, sizeof(ws->req.hostname));
	}

	FUZZ(ws->user_config->interim_update_secs, 5, rnd);
	FUZZ(WSCONFIG(ws)->rekey_time, 30, rnd);

	/* Connected. Turn of the alarm */
	if (WSCONFIG(ws)->auth_timeout)
		alarm(0);
	http_req_deinit(ws);

	cstp_cork(ws);
	ret = cstp_puts(ws, "HTTP/1.1 200 CONNECTED\r\n");
	SEND_ERR(ret);

	ret = cstp_puts(ws, "X-CSTP-Version: 1\r\n");
	SEND_ERR(ret);

	ret = cstp_puts(ws, "X-CSTP-Server-Name: "PACKAGE_STRING"\r\n");
	SEND_ERR(ret);

	if (req->is_mobile) {
		ws->user_config->dpd = ws->user_config->mobile_dpd;
		WSCONFIG(ws)->idle_timeout = WSCONFIG(ws)->mobile_idle_timeout;
	}

	/* Notify back the client about the accepted hostname */
	if (ws->req.hostname[0] != 0) {
		ret = cstp_printf(ws, "X-CSTP-Hostname: %s\r\n", ws->req.hostname);
		SEND_ERR(ret);
	}

	oclog(ws, LOG_INFO, "suggesting DPD of %d secs", ws->user_config->dpd);
	if (ws->user_config->dpd > 0) {
		ret =
		    cstp_printf(ws, "X-CSTP-DPD: %u\r\n",
			       ws->user_config->dpd);
		SEND_ERR(ret);
	}

	if (WSCONFIG(ws)->default_domain) {
		ret =
		    cstp_printf(ws, "X-CSTP-Default-Domain: %s\r\n",
			       WSCONFIG(ws)->default_domain);
		SEND_ERR(ret);
	}

	ws->udp_state = UP_DISABLED;
	if (WSPCONFIG(ws)->udp_port != 0 && req->master_secret_set != 0) {
		memcpy(ws->master_secret, req->master_secret, TLS_MASTER_SIZE);
		ws->udp_state = UP_WAIT_FD;
	} else {
		oclog(ws, LOG_DEBUG, "disabling UDP (DTLS) connection");
	}

	if (ws->user_config->mtu > 0)
		ws->vinfo.mtu = ws->user_config->mtu;
	oclog(ws, LOG_INFO, "configured link MTU is %u", ws->vinfo.mtu);

	if (req->link_mtu > 0) {
		oclog(ws, LOG_INFO, "peer's link MTU is %u", req->link_mtu);
		ws->vinfo.mtu = MIN(ws->vinfo.mtu, req->link_mtu);
	} else if (req->tunnel_mtu > 0) {
		/* Old clients didn't send their link MTU, they send the plaintext MTU
		 * they can transfer. */
		ws->vinfo.mtu = MIN(ws->vinfo.mtu, req->tunnel_mtu + MAX_DTLS_PROTO_OVERHEAD(ws) + MAX_DTLS_CRYPTO_OVERHEAD);
		oclog(ws, LOG_INFO, "peer's data MTU is %u / link is %u", req->tunnel_mtu, ws->vinfo.mtu);
	}

	/* Attempt to use the TCP connection maximum segment size to set a more
	 * precise MTU. */
	if (ws->conn_type != SOCK_TYPE_UNIX) {
		max = get_pmtu_approx(ws);
		if (max > 0 && max < ws->vinfo.mtu) {
			oclog(ws, LOG_DEBUG, "reducing MTU due to TCP/PMTU to %u",
			      max);
			link_mtu_set(ws, max);
		}
	}

	calc_mtu_values(ws);

	if (DATA_MTU(ws, ws->link_mtu) < 1280 && ws->vinfo.ipv6 && req->no_ipv6 == 0) {
		oclog(ws, LOG_INFO, "Connection MTU (link: %u, data: %u) is not sufficient for IPv6 (1280)", ws->link_mtu, DATA_MTU(ws, ws->link_mtu));
		req->no_ipv6 = 1;
	}

	/* Send IP addresses */
	if (ws->vinfo.ipv4 && req->no_ipv4 == 0) {
		oclog(ws, LOG_INFO, "sending IPv4 %s", ws->vinfo.ipv4);
		ret =
		    cstp_printf(ws, "X-CSTP-Address: %s\r\n",
			       ws->vinfo.ipv4);
		SEND_ERR(ret);

		if (ws->user_config->ipv4_netmask) {
			ret =
			    cstp_printf(ws, "X-CSTP-Netmask: %s\r\n",
				       ws->user_config->ipv4_netmask);
			SEND_ERR(ret);
		}
	}

	if (ws->vinfo.ipv6 && req->no_ipv6 == 0 && ws->user_config->ipv6_prefix != 0) {
		oclog(ws, LOG_INFO, "sending IPv6 %s/%u", ws->vinfo.ipv6, ws->user_config->ipv6_subnet_prefix);
		if (ws->full_ipv6 && ws->user_config->ipv6_subnet_prefix) {
			ret =
			    cstp_printf(ws,
				       "X-CSTP-Address-IP6: %s/%u\r\n",
				       ws->vinfo.ipv6, ws->user_config->ipv6_subnet_prefix);
			SEND_ERR(ret);
		} else {
			const char *net;

			ret =
			    cstp_printf(ws, "X-CSTP-Address: %s\r\n",
				       ws->vinfo.ipv6);
			SEND_ERR(ret);

			net = ws->user_config->ipv6_net;
			if (net == NULL)
				net = ws->vinfo.ipv6;

			ret =
			    cstp_printf(ws, "X-CSTP-Netmask: %s/%u\r\n",
				        net, ws->user_config->ipv6_subnet_prefix);
			SEND_ERR(ret);
		}
	}

	/* While anyconnect clients can handle the assignment
	 * of an IPv6 address, they cannot handle routes or DNS
	 * in IPv6. So we disable IPv6 after an IP is assigned. */
	if (ws->full_ipv6 == 0) {
		req->no_ipv6 = 1;
		oclog(ws, LOG_INFO, "IPv6 routes/DNS disabled because IPv6 support was not requested.");
	} else if (req->user_agent_type != AGENT_OPENCONNECT && req->user_agent_type != AGENT_ANYCONNECT) {
		req->no_ipv6 = 1;
		oclog(ws, LOG_INFO, "IPv6 routes/DNS disabled because the agent is not known.");
	}

	for (i = 0; i < ws->user_config->n_dns; i++) {
		if (strchr(ws->user_config->dns[i], ':') != 0)
			ip6 = 1;
		else
			ip6 = 0;

		if (req->no_ipv6 != 0 && ip6 != 0)
			continue;
		if (req->no_ipv4 != 0 && ip6 == 0)
			continue;

		oclog(ws, LOG_INFO, "adding DNS %s", ws->user_config->dns[i]);
		if (req->user_agent_type == AGENT_ANYCONNECT) {
			ret =
			    cstp_printf(ws, "X-CSTP-%s: %s\r\n",
				       ip6 ? "DNS-IP6" : "DNS",
				       ws->user_config->dns[i]);
		} else { /* openconnect does not require the split
			  * of DNS and DNS-IP6 and only recent versions
			  * understand the IP6 variant. */
			ret =
			    cstp_printf(ws, "X-CSTP-DNS: %s\r\n",
				        ws->user_config->dns[i]);
		}
		SEND_ERR(ret);
	}

	for (i = 0; i < ws->user_config->n_nbns; i++) {
		if (strchr(ws->user_config->nbns[i], ':') != 0)
			ip6 = 1;
		else
			ip6 = 0;

		if (req->no_ipv6 != 0 && ip6 != 0)
			continue;
		if (req->no_ipv4 != 0 && ip6 == 0)
			continue;

		oclog(ws, LOG_INFO, "adding NBNS %s", ws->user_config->nbns[i]);
		ret =
		    cstp_printf(ws, "X-CSTP-NBNS: %s\r\n",
			       ws->user_config->nbns[i]);
		SEND_ERR(ret);
	}

	for (i = 0; i < ws->user_config->n_split_dns; i++) {
		if (strchr(ws->user_config->split_dns[i], ':') != 0)
			ip6 = 1;
		else
			ip6 = 0;

		if (req->no_ipv6 != 0 && ip6 != 0)
			continue;
		if (req->no_ipv4 != 0 && ip6 == 0)
			continue;

		oclog(ws, LOG_INFO, "adding split DNS %s",
		      ws->user_config->split_dns[i]);
		ret =
		    cstp_printf(ws, "X-CSTP-Split-DNS: %s\r\n",
			       ws->user_config->split_dns[i]);
		SEND_ERR(ret);
	}

	/* Anyconnect on IOS requires this route in order to use IPv6 */
	if (ws->full_ipv6 && req->is_ios &&
	    (ws->user_config->n_routes == 0 || ws->default_route == 0)) {
		oclog(ws, LOG_INFO, "adding special split DNS for Apple");
		ret =
		    cstp_printf(ws, "X-CSTP-Split-Include-IP6: 2000::/3\r\n");
		SEND_ERR(ret);
	}

	if (ws->default_route == 0) {
		ret = send_routes(ws, req, ws->user_config->routes, ws->user_config->n_routes, 1);
		SEND_ERR(ret);

	} else {
		/* default route */
		WSCONFIG(ws)->tunnel_all_dns = 1;
	}

	if (WSCONFIG(ws)->tunnel_all_dns) {
		ret = cstp_puts(ws, "X-CSTP-Tunnel-All-DNS: true\r\n");
	} else {
		ret = cstp_puts(ws, "X-CSTP-Tunnel-All-DNS: false\r\n");
	}
	SEND_ERR(ret);

	ret = send_routes(ws, req, ws->user_config->no_routes, ws->user_config->n_no_routes, 0);
	SEND_ERR(ret);

	ret =
	    cstp_printf(ws, "X-CSTP-Keepalive: %u\r\n",
		       ws->user_config->keepalive);
	SEND_ERR(ret);

	if (WSCONFIG(ws)->idle_timeout > 0) {
		ret =
		    cstp_printf(ws,
			       "X-CSTP-Idle-Timeout: %u\r\n",
			       (unsigned)WSCONFIG(ws)->idle_timeout);
	} else {
		ret = cstp_puts(ws, "X-CSTP-Idle-Timeout: none\r\n");
	}
	SEND_ERR(ret);

	ret =
	    cstp_puts(ws,
		     "X-CSTP-Smartcard-Removal-Disconnect: true\r\n");
	SEND_ERR(ret);

	if (WSCONFIG(ws)->is_dyndns != 0) {
		ret =
		    cstp_puts(ws,
			     "X-CSTP-DynDNS: true\r\n");
		SEND_ERR(ret);
	}

	if (WSCONFIG(ws)->rekey_time > 0) {
		unsigned method;

		ret =
		    cstp_printf(ws, "X-CSTP-Rekey-Time: %u\r\n",
			       (unsigned)(WSCONFIG(ws)->rekey_time));
		SEND_ERR(ret);

		/* if the peer isn't patched for safe renegotiation, always
		 * require him to open a new tunnel. */
		if (ws->session != NULL && gnutls_safe_renegotiation_status(ws->session) != 0)
			method = WSCONFIG(ws)->rekey_method;
		else
			method = REKEY_METHOD_NEW_TUNNEL;

		ret = cstp_printf(ws, "X-CSTP-Rekey-Method: %s\r\n",
				 (method ==
				  REKEY_METHOD_SSL) ? "ssl" : "new-tunnel");
		SEND_ERR(ret);
	} else {
		ret = cstp_puts(ws, "X-CSTP-Rekey-Method: none\r\n");
		SEND_ERR(ret);
	}

	if (WSCONFIG(ws)->proxy_url != NULL) {
		char *url = replace_vals(ws, WSCONFIG(ws)->proxy_url);
		if (url != NULL) {
			ret =
			    cstp_printf(ws, "X-CSTP-MSIE-Proxy-Pac-URL: %s\r\n",
			       url);
			SEND_ERR(ret);
			talloc_free(url);
		}
	}

	ret = cstp_puts(ws, "X-CSTP-Session-Timeout: none\r\n"
		       "X-CSTP-Disconnected-Timeout: none\r\n"
		       "X-CSTP-Keep: true\r\n"
		       "X-CSTP-TCP-Keepalive: true\r\n"
		       "X-CSTP-License: accept\r\n");
	SEND_ERR(ret);

	for (i = 0; i < WSCONFIG(ws)->custom_header_size; i++) {
		char *h = replace_vals(ws, WSCONFIG(ws)->custom_header[i]);

		if (h) {
			oclog(ws, LOG_INFO, "adding custom header '%s'", h);
			ret =
			    cstp_printf(ws, "%s\r\n", h);
			SEND_ERR(ret);
			talloc_free(h);
		}
	}


	/* set TCP socket options */
	if (WSCONFIG(ws)->output_buffer > 0) {
		t = ws->link_mtu;
		t *= WSCONFIG(ws)->output_buffer;

		ret =
		    setsockopt(ws->conn_fd, SOL_SOCKET, SO_SNDBUF, &t,
			       sizeof(t));
		if (ret == -1)
			oclog(ws, LOG_DEBUG,
			      "setsockopt(TCP, SO_SNDBUF) to %u, failed.", t);
	}

	set_socket_timeout(ws, ws->conn_fd);
	set_non_block(ws->conn_fd);
	set_net_priority(ws, ws->conn_fd, ws->user_config->net_priority);
	set_no_delay(ws, ws->conn_fd);

	if (ws->udp_state != UP_DISABLED) {

		if (ws->user_config->dpd > 0) {
			ret =
			    cstp_printf(ws, "X-DTLS-DPD: %u\r\n",
				       ws->user_config->dpd);
			SEND_ERR(ret);
		}

		ret =
		    cstp_printf(ws, "X-DTLS-Port: %u\r\n",
			       WSPCONFIG(ws)->udp_port);
		SEND_ERR(ret);

		if (WSCONFIG(ws)->rekey_time > 0) {
			ret =
			    cstp_printf(ws, "X-DTLS-Rekey-Time: %u\r\n",
				       (unsigned)(WSCONFIG(ws)->rekey_time + 10));
			SEND_ERR(ret);

			/* This is our private extension */
			if (WSCONFIG(ws)->rekey_method == REKEY_METHOD_SSL) {
				ret =
				    cstp_puts(ws,
					     "X-DTLS-Rekey-Method: ssl\r\n");
				SEND_ERR(ret);
			}
		}

		ret =
		    cstp_printf(ws, "X-DTLS-Keepalive: %u\r\n",
			       ws->user_config->keepalive);
		SEND_ERR(ret);

		p = (char *)ws->buffer;
		for (i = 0; i < sizeof(ws->session_id); i++) {
			sprintf(p, "%.2x", (unsigned int)ws->session_id[i]);
			p += 2;
		}

		if (ws->req.use_psk || !WSCONFIG(ws)->dtls_legacy) {
			oclog(ws, LOG_INFO, "X-DTLS-App-ID: %s", ws->buffer);

			ret =
			    cstp_printf(ws, "X-DTLS-App-ID: %s\r\n",
				       ws->buffer);
			SEND_ERR(ret);

			oclog(ws, LOG_INFO, "DTLS ciphersuite: "DTLS_PROTO_INDICATOR);
			ret =
			    cstp_printf(ws, "X-DTLS-CipherSuite: "DTLS_PROTO_INDICATOR"\r\n");
		} else if (ws->req.selected_ciphersuite) {
			oclog(ws, LOG_INFO, "X-DTLS-Session-ID: %s", ws->buffer);

			ret =
			    cstp_printf(ws, "X-DTLS-Session-ID: %s\r\n",
				       ws->buffer);
			SEND_ERR(ret);

			oclog(ws, LOG_INFO, "DTLS ciphersuite: %s",
			      ws->req.selected_ciphersuite->oc_name);
			ret =
			    cstp_printf(ws, "X-DTLS%s-CipherSuite: %s\r\n",
				        (ws->req.selected_ciphersuite->dtls12_mode!=0)?"12":"",
				        ws->req.selected_ciphersuite->oc_name);
			SEND_ERR(ret);

			/* only send the X-DTLS-MTU in the legacy protocol, as there
			 * the DTLS ciphersuite/version is negotiated and we cannot predict
			 * the actual tunnel size */
			ret =
			    cstp_printf(ws, "X-DTLS-MTU: %u\r\n", DATA_MTU(ws, ws->link_mtu));
			SEND_ERR(ret);
			oclog(ws, LOG_INFO, "DTLS data MTU %u", DATA_MTU(ws, ws->link_mtu));
		}
		SEND_ERR(ret);

	}

	/* hack for openconnect. It uses only a single MTU value */
	ret = cstp_printf(ws, "X-CSTP-Base-MTU: %u\r\n", ws->link_mtu);
	SEND_ERR(ret);
	oclog(ws, LOG_INFO, "Link MTU is %u bytes", ws->link_mtu);

	ret = cstp_printf(ws, "X-CSTP-MTU: %u\r\n", DATA_MTU(ws, ws->link_mtu));
	SEND_ERR(ret);

	if (ws->buffer_size < ws->link_mtu+16) {
		oclog(ws, LOG_ERR,
		      "buffer size is smaller than MTU (%u < %u)",
		      ws->buffer_size, ws->link_mtu);
		goto exit;
	}

	data_mtu_send(ws, DATA_MTU(ws, ws->link_mtu));

	if (WSCONFIG(ws)->banner) {
		ret =
		    cstp_printf(ws, "X-CSTP-Banner: %s\r\n",
			       WSCONFIG(ws)->banner);
		SEND_ERR(ret);
	}

	/* send any compression methods */
	if (ws->dtls_selected_comp) {
		oclog(ws, LOG_INFO, "selected DTLS compression method %s\n", ws->dtls_selected_comp->name);
		ret =
		    cstp_printf(ws, "X-DTLS-Content-Encoding: %s\r\n",
			        ws->dtls_selected_comp->name);
		SEND_ERR(ret);
	}

	if (ws->cstp_selected_comp) {
		oclog(ws, LOG_INFO, "selected CSTP compression method %s\n", ws->cstp_selected_comp->name);
		ret =
		    cstp_printf(ws, "X-CSTP-Content-Encoding: %s\r\n",
			        ws->cstp_selected_comp->name);
		SEND_ERR(ret);
	}

	ret = cstp_puts(ws, "\r\n");
	SEND_ERR(ret);

	ret = cstp_uncork(ws);
	SEND_ERR(ret);

	/* start dead peer detection */
	gettime(&tnow);
	ws->last_msg_tcp = ws->last_msg_udp = ws->last_nc_msg = tnow.tv_sec;

	bandwidth_init(&ws->b_rx, ws->user_config->rx_per_sec);
	bandwidth_init(&ws->b_tx, ws->user_config->tx_per_sec);

	sigprocmask(SIG_BLOCK, &blockset, NULL);

	/* worker main loop  */
	for (;;) {
		if (terminate != 0) {
 terminate:
			ws->buffer[0] = 'S';
			ws->buffer[1] = 'T';
			ws->buffer[2] = 'F';
			ws->buffer[3] = 1;
			ws->buffer[4] = 0;
			ws->buffer[5] = 0;
			ws->buffer[6] = AC_PKT_DISCONN;
			ws->buffer[7] = 0;

			oclog(ws, LOG_TRANSFER_DEBUG,
			      "sending disconnect message in TLS channel");
			cstp_send(ws, ws->buffer, 8);
			exit_worker_reason(ws, terminate_reason);
		}

		if (ws->session != NULL)
			tls_pending = gnutls_record_check_pending(ws->session);
		else
			tls_pending = 0;

		if (ws->udp_state > UP_WAIT_FD) {
			dtls_pending = dtls_pull_buffer_non_empty(&ws->dtls_tptr);
			if (ws->dtls_session != NULL)
				dtls_pending +=
				    gnutls_record_check_pending(ws->dtls_session);
		} else {
			dtls_pending = 0;
		}

		pfd[0].revents = 0;
		pfd[1].revents = 0;
		pfd[2].revents = 0;
		pfd[3].revents = 0;

		if (tls_pending == 0 && dtls_pending == 0) {
			pfd[0].fd = ws->conn_fd;
			pfd[0].events = POLLIN;

			pfd[1].fd = ws->cmd_fd;
			pfd[1].events = POLLIN;

			pfd[2].fd = ws->tun_fd;
			pfd[2].events = POLLIN;

			pfd_size = 3;

			if (ws->udp_state > UP_WAIT_FD) {
				pfd[3].fd = ws->dtls_tptr.fd;
				pfd[3].events = POLLIN;
				pfd_size++;
			}

#ifdef HAVE_PPOLL
			tv.tv_nsec = 0;
			tv.tv_sec = 10;
			ret = ppoll(pfd, pfd_size, &tv, &emptyset);
#else
			sigprocmask(SIG_UNBLOCK, &blockset, NULL);
			ret = poll(pfd, pfd_size, 10*1000);
			sigprocmask(SIG_BLOCK, &blockset, NULL);
#endif
			if (ret == -1) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				terminate_reason = REASON_ERROR;
				goto exit;
			}

			if ((pfd[0].revents | pfd[1].revents |
			     pfd[2].revents | pfd[3].revents) & POLLERR) {
				terminate_reason = REASON_ERROR;
				goto exit;
			}
		}
		gettime(&tnow);

		if (periodic_check(ws, &tnow, ws->user_config->dpd) < 0) {
			terminate_reason = REASON_ERROR;
			goto exit;
		}

		/* send pending data from tun device */
		if (pfd[2].revents & (POLLIN|POLLHUP)) {
			ret = tun_mainloop(ws, &tnow);
			if (ret < 0) {
				terminate_reason = REASON_ERROR;
				goto exit;
			}
		}

		/* read pending data from TCP channel */
		if ((pfd[0].revents & (POLLIN|POLLHUP)) || tls_pending != 0) {
			ret = tls_mainloop(ws, &tnow);
			if (ret < 0) {
				terminate_reason = REASON_ERROR;
				goto exit;
			}
		}

		/* read data from UDP channel */
		if (ws->udp_state > UP_WAIT_FD &&
		    ((pfd[3].revents & (POLLIN|POLLHUP)) || dtls_pending != 0)) {

			ret = dtls_mainloop(ws, &tnow);
			if (ret < 0) {
				terminate_reason = REASON_ERROR;
				goto exit;
			}

#if defined(CAPTURE_LATENCY_SUPPORT)
			if (ws->dtls_tptr.rx_time.tv_sec != 0) {
				capture_latency_sample(ws, &ws->dtls_tptr.rx_time);
				ws->dtls_tptr.rx_time.tv_sec = 0;
				ws->dtls_tptr.rx_time.tv_nsec = 0;
			}
#endif
		}

		/* read commands from command fd */
		if (pfd[1].revents & (POLLIN|POLLHUP)) {
			ret = handle_commands_from_main(ws);
			if (ret == ERR_NO_CMD_FD) {
				terminate_reason = REASON_ERROR;
				goto terminate;
			}

			if (ret < 0) {
				terminate_reason = REASON_ERROR;
				goto exit;
			}
		}
	}

	return 0;

 exit:
	cstp_close(ws);
	/*gnutls_deinit(ws->session); */
	if (ws->udp_state == UP_ACTIVE && ws->dtls_session) {
		dtls_close(ws);
		/*gnutls_deinit(ws->dtls_session); */
	}

	exit_worker_reason(ws, terminate_reason);

 send_error:
	oclog(ws, LOG_DEBUG, "error sending data\n");
	exit_worker(ws);

	return -1;
}

static int parse_data(struct worker_st *ws, uint8_t *buf, size_t buf_size,
		      time_t now, unsigned is_dtls)
{
	int ret, e;
	uint8_t *plain;
	ssize_t plain_size;
	unsigned head;

	if (is_dtls == 0) { /* CSTP */
		plain = buf + 8;
		plain_size = buf_size - 8;
		head = buf[6];
	} else {
		plain = buf + 1;
		plain_size = buf_size - 1;
		head = buf[0];
	}

	switch (head) {
	case AC_PKT_DPD_RESP:
		oclog(ws, LOG_TRANSFER_DEBUG, "received DPD response");
		break;
	case AC_PKT_KEEPALIVE:
		oclog(ws, LOG_TRANSFER_DEBUG, "received keepalive");
		break;
	case AC_PKT_DPD_OUT:
		if (is_dtls == 0) {
			buf[6] = AC_PKT_DPD_RESP;
			ret = cstp_send(ws, buf, buf_size);

			oclog(ws, LOG_TRANSFER_DEBUG,
			      "received TLS DPD; sent response (%d bytes)",
			      ret);

			if (ret < 0) {
				oclog(ws, LOG_ERR, "could not send data: %d", ret);
				return -1;
			}
		} else {
			/* Use DPD for MTU discovery in DTLS */
			buf[0] = AC_PKT_DPD_RESP;

			if (buf_size-CSTP_DTLS_OVERHEAD > DATA_MTU(ws, ws->link_mtu)) {
				/* peer is doing MTU discovery */
				data_mtu_set(ws, buf_size-CSTP_DTLS_OVERHEAD);
			}

			ret = dtls_send(ws, buf, buf_size);
			if (ret == GNUTLS_E_LARGE_PACKET) {
				oclog(ws, LOG_TRANSFER_DEBUG,
				      "could not send DPD of %d bytes", (int)buf_size);
				mtu_not_ok(ws);
				ret = dtls_send(ws, buf, 1);
			}

			oclog(ws, LOG_TRANSFER_DEBUG,
			      "received DTLS DPD; sent response (%d bytes)",
			      ret);

			if (ret < 0) {
				oclog(ws, LOG_ERR, "could not send TLS data: %s",
				      gnutls_strerror(ret));
				return -1;
			}
		}

		break;
	case AC_PKT_DISCONN:
		oclog(ws, LOG_INFO, "received BYE packet; exiting");
		/* In openconnect the BYE packet indicates an explicit
		 * user disconnect. In anyconnect clients it may indicate
		 * an intention to reconnect (e.g., because network was
		 * changed). We separate the error codes to ensure we do
		 * do not interpret the intention incorrectly (see #281). */
		if (plain_size > 0 && plain[0] == 0xb0) {
			exit_worker_reason(ws, REASON_USER_DISCONNECT);
		} else {
			if (plain_size > 0) {
				oclog(ws, LOG_DEBUG, "bye packet with payload: %u/%.2x", (unsigned)plain_size, plain[0]);
				return -1;
			}

			exit_worker_reason(ws, REASON_TEMP_DISCONNECT);
		}
		break;
	case AC_PKT_COMPRESSED:
		/* decompress */
		if (is_dtls == 0) { /* CSTP */
			if (ws->cstp_selected_comp == NULL) {
				oclog(ws, LOG_ERR, "received compression data but no compression was negotiated");
				return -1;
			}

			plain_size = ws->cstp_selected_comp->decompress(ws->decomp, sizeof(ws->decomp), plain, plain_size);
			oclog(ws, LOG_DEBUG, "decompressed %d to %d\n", (int)buf_size-8, (int)plain_size);
		} else { /* DTLS */
			if (ws->dtls_selected_comp == NULL) {
				oclog(ws, LOG_ERR, "received compression data but no compression was negotiated");
				return -1;
			}

			plain_size = ws->dtls_selected_comp->decompress(ws->decomp, sizeof(ws->decomp), plain, plain_size);
			oclog(ws, LOG_DEBUG, "decompressed %d to %d\n", (int)buf_size-1, (int)plain_size);
		}

		if (plain_size <= 0) {
			oclog(ws, LOG_ERR, "decompression error %d", (int)plain_size);
			return -1;
		}
		plain = ws->decomp;
		/* fall through */
	case AC_PKT_DATA:
		oclog(ws, LOG_TRANSFER_DEBUG, "writing %d byte(s) to TUN",
		      (int)plain_size);
		ret = tun_write(ws->tun_fd, plain, plain_size);
		if (ret == -1) {
			e = errno;
			oclog(ws, LOG_ERR, "could not write data to tun: %s",
			      strerror(e));
			return -1;
		}
		ws->tun_bytes_in += plain_size;
		ws->last_nc_msg = now;

		break;
	default:
		oclog(ws, LOG_DEBUG, "received unknown packet %u/size: %u",
		      (unsigned)head, (unsigned)buf_size);
	}

	return 0;
}

static int parse_cstp_data(struct worker_st *ws,
			   uint8_t * buf, size_t buf_size, time_t now)
{
	int pktlen, ret;

	if (buf_size < 8) {
		oclog(ws, LOG_INFO,
		      "can't read CSTP header (only %d bytes are available)",
		      (int)buf_size);
		return -1;
	}

	if (buf[0] != 'S' || buf[1] != 'T' ||
	    buf[2] != 'F' || buf[3] != 1 || buf[7]) {
		oclog(ws, LOG_INFO, "can't recognise CSTP header");
		return -1;
	}

	pktlen = (buf[4] << 8) + buf[5];
	if (buf_size != 8 + pktlen) {
		oclog(ws, LOG_INFO, "unexpected CSTP length (have %u, should be %d)",
		      (unsigned)pktlen, (unsigned)buf_size-8);
		return -1;
	}

	if (buf[6] == AC_PKT_DATA && ws->udp_state == UP_ACTIVE) {
		/* if we received a data packet in the CSTP channel we assume that
		 * our peer wants to switch to it as the communication channel */
		ws->udp_state = UP_INACTIVE;
	}

	ret = parse_data(ws, buf, buf_size, now, 0);
	/* whatever we received treat it as DPD response.
	 * it indicates that the channel is alive */
	ws->last_msg_tcp = now;

	return ret;
}

static int parse_dtls_data(struct worker_st *ws,
			   uint8_t * buf, size_t buf_size, time_t now)
{
	int ret;

	if (buf_size < 1) {
		oclog(ws, LOG_INFO,
		      "can't read DTLS header (only %d bytes are available)",
		      (int)buf_size);
		return -1;
	}

	ret =
	    parse_data(ws, buf, buf_size, now, 1);
	ws->last_msg_udp = now;
	return ret;
}
