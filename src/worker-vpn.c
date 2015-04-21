/*
 * Copyright (C) 2013, 2014 Nikos Mavrogiannopoulos
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
#include <sys/types.h>
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

#include <vpn.h>
#include "ipc.pb-c.h"
#include <cookies.h>
#include <worker.h>
#include <tlslib.h>

#include <http_parser.h>

#if GNUTLS_VERSION_NUMBER >= 0x030305
# define ZERO_COPY
#endif

#define MIN_MTU(ws) (((ws)->vinfo.ipv6!=NULL)?1281:257)

#define PERIODIC_CHECK_TIME 30

/* The number of DPD packets a client skips before he's kicked */
#define DPD_TRIES 2
#define DPD_MAX_TRIES 3

/* HTTP requests prior to disconnection */
#define MAX_HTTP_REQUESTS 16

#define CSTP_DTLS_OVERHEAD 1
#define CSTP_OVERHEAD 8

struct worker_st *global_ws = NULL;

static int terminate = 0;
static int parse_cstp_data(struct worker_st *ws, uint8_t * buf, size_t buf_size,
			   time_t);
static int parse_dtls_data(struct worker_st *ws, uint8_t * buf, size_t buf_size,
			   time_t);
void exit_worker(worker_st * ws);

#define REASON_ANY 0
#define REASON_USER_DISCONNECT 1
static void exit_worker_reason(worker_st * ws, unsigned reason);

static int connect_handler(worker_st * ws);

static void handle_alarm(int signo)
{
	if (global_ws)
		exit_worker(global_ws);

	exit(1);
}

static void handle_term(int signo)
{
	terminate = 1;
	alarm(2);		/* force exit by SIGALRM */
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
	fd_set rfds;
	struct timeval tv;
	int ret;
	dtls_transport_ptr *p = ptr;
	int fd = p->fd;

	if (dtls_pull_buffer_non_empty(ptr)) {
		return 1;
	}

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = ms * 1000;

	while (tv.tv_usec >= 1000000) {
		tv.tv_usec -= 1000000;
		tv.tv_sec++;
	}

	ret = select(fd + 1, &rfds, NULL, NULL, &tv);
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

static int setup_dtls_connection(struct worker_st *ws)
{
	int ret;
	gnutls_session_t session;
	gnutls_datum_t master =
	    { ws->master_secret, sizeof(ws->master_secret) };
	gnutls_datum_t sid = { ws->session_id, sizeof(ws->session_id) };

	if (ws->req.selected_ciphersuite == NULL) {
		oclog(ws, LOG_ERR, "no DTLS ciphersuite negotiated");
		return -1;
	}

	oclog(ws, LOG_DEBUG, "setting up DTLS connection");
	/* DTLS cookie verified.
	 * Initialize session.
	 */
	ret = gnutls_init(&session, GNUTLS_SERVER|GNUTLS_DATAGRAM|GNUTLS_NONBLOCK);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not initialize TLS session: %s",
		      gnutls_strerror(ret));
		return -1;
	}

	ret =
	    gnutls_priority_set_direct(session,
				       ws->req.
				       selected_ciphersuite->gnutls_name, NULL);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS priority: %s",
		      gnutls_strerror(ret));
		goto fail;
	}

	ret = gnutls_session_set_premaster(session, GNUTLS_SERVER,
					   ws->req.
					   selected_ciphersuite->gnutls_version,
					   GNUTLS_KX_RSA,
					   ws->req.
					   selected_ciphersuite->gnutls_cipher,
					   ws->req.
					   selected_ciphersuite->gnutls_mac,
					   GNUTLS_COMP_NULL, &master, &sid);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS premaster: %s",
		      gnutls_strerror(ret));
		goto fail;
	}

	ret =
	    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				   ws->creds->xcred);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS credentials: %s",
		      gnutls_strerror(ret));
		goto fail;
	}

	gnutls_transport_set_push_function(session, dtls_push);
	gnutls_transport_set_pull_function(session, dtls_pull);
	gnutls_transport_set_pull_timeout_function(session, dtls_pull_timeout);
	gnutls_transport_set_ptr(session, &ws->dtls_tptr);

	gnutls_session_set_ptr(session, ws);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);

	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	ws->udp_state = UP_HANDSHAKE;

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
	if (ws->config->max_ban_score == 0)
		return;

	/* In final call, no score added, we simply send */
	if (final == 0) {
		ws->ban_points += points;
		/* do not use IPC for small values */
		if (points < ws->config->ban_points_wrong_password)
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

	if (final != 0)
		return;

	ret = recv_msg(ws, ws->cmd_fd, CMD_BAN_IP_REPLY,
		       (void *)&reply, (unpack_func) ban_ip_reply_msg__unpack);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error receiving BAN IP reply message");
		return;
	}

	if (reply->reply != AUTH__REP__OK) {
		/* we have exceeded the maximum score */
		exit(1);
	}

	ban_ip_reply_msg__free_unpacked(reply, &pa);

	return;
}

void send_stats_to_secmod(worker_st * ws, time_t now, unsigned invalidate_cookie)
{
	CliStatsMsg msg = CLI_STATS_MSG__INIT;
	int sd, ret, e;

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

		if (invalidate_cookie) {
			msg.has_invalidate_cookie = 1;
			msg.invalidate_cookie = 1;
		}

		msg.remote_ip = human_addr2((void *)&ws->remote_addr, ws->remote_addr_len,
		       		     buf, sizeof(buf), 0);

		msg.ipv4 = ws->vinfo.ipv4;
		msg.ipv6 = ws->vinfo.ipv6;

		ret = send_msg_to_secmod(ws, sd, SM_CMD_CLI_STATS, &msg,
				 (pack_size_func)cli_stats_msg__get_packed_size,
				 (pack_func) cli_stats_msg__pack);
		close(sd);

		if (ret >= 0) {
			oclog(ws, LOG_DEBUG,
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

static void exit_worker_reason(worker_st * ws, unsigned reason)
{
	/* send statistics to parent */
	if (ws->auth_state == S_AUTH_COMPLETE) {
		send_stats_to_secmod(ws, time(0), (reason==REASON_USER_DISCONNECT)?1:0);
	}

	if (ws->ban_points > 0)
		ws_add_score_to_ip(ws, 0, 1);

	talloc_free(ws->main_pool);
	closelog();
	exit(1);
}

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
	unsigned char buf[2048];
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
	if (ws->config->auth_timeout)
		alarm(ws->config->auth_timeout);

	/* do not allow this process to be traced. That
	 * prevents worker processes tracing each other. */
	if (ws->config->debug == 0)
		pr_set_undumpable("worker");
	if (ws->config->isolate != 0) {
		ret = disable_system_calls(ws);
		if (ret < 0) {
			oclog(ws, LOG_INFO,
			      "could not disable system calls, kernel might not support seccomp");
		}
	}
	ws->session_start_time = time(0);

	oclog(ws, LOG_DEBUG, "accepted connection");
	if (ws->remote_addr_len == sizeof(struct sockaddr_in))
		ws->proto = AF_INET;
	else
		ws->proto = AF_INET6;

	if (ws->conn_type != SOCK_TYPE_UNIX) {
		/* initialize the session */
		ret = gnutls_init(&session, GNUTLS_SERVER);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_priority_set(session, ws->creds->cprio);
		GNUTLS_FATAL_ERR(ret);

		ret =
		    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
					   ws->creds->xcred);
		GNUTLS_FATAL_ERR(ret);

		gnutls_certificate_server_set_request(session, ws->config->cert_req);

		gnutls_transport_set_ptr(session,
				 (gnutls_transport_ptr_t) (long)ws->conn_fd);
		set_resume_db_funcs(session);
		gnutls_session_set_ptr(session, ws);
		gnutls_db_set_ptr(session, ws);
		gnutls_db_set_cache_expiration(session, TLS_SESSION_EXPIRATION_TIME(ws->config));

		gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
		do {
			ret = gnutls_handshake(session);
		} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
		GNUTLS_S_FATAL_ERR(session, ret);

		oclog(ws, LOG_DEBUG, "TLS handshake completed");
	} else {
		oclog(ws, LOG_DEBUG, "Accepted unix connection");
	}

	memset(&settings, 0, sizeof(settings));

	ws->selected_auth = &ws->perm_config->auth[0];
	if (ws->cert_auth_ok)
		ws_switch_auth_to(ws, AUTH_TYPE_CERTIFICATE);

	settings.on_url = http_url_cb;
	settings.on_header_field = http_header_field_cb;
	settings.on_header_value = http_header_value_cb;
	settings.on_headers_complete = http_header_complete_cb;
	settings.on_message_complete = http_message_complete_cb;
	settings.on_body = http_body_cb;
	http_req_init(ws);

	human_addr2((void*)&ws->remote_addr, ws->remote_addr_len, ws->remote_ip_str, sizeof(ws->remote_ip_str), 0);

	ws->session = session;
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
		nrecvd = cstp_recv(ws, buf, sizeof(buf));
		if (nrecvd <= 0) {
			if (nrecvd == 0)
				goto finish;
			if (nrecvd != GNUTLS_E_PREMATURE_TERMINATION)
				oclog(ws, LOG_ERR,
				      "error receiving client data");
			exit_worker(ws);
		}

		nparsed =
		    http_parser_execute(&parser, &settings, (void *)buf,
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
			cstp_puts(ws, "HTTP/1.1 404 Not found\r\n\r\n");
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
			nrecvd = cstp_recv(ws, buf, sizeof(buf));
			FATAL_ERR(ws, nrecvd);

			nparsed =
			    http_parser_execute(&parser, &settings, (void *)buf,
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
			cstp_puts(ws, "HTTP/1.1 404 Not found\r\n\r\n");
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
		cstp_printf(ws, "HTTP/1.%u 404 Nah, go away\r\n\r\n",
			   parser.http_minor);
	}

 finish:
	cstp_close(ws);
}

static
void mtu_send(worker_st * ws, unsigned mtu)
{
	TunMtuMsg msg = TUN_MTU_MSG__INIT;

	msg.mtu = mtu;
	send_msg_to_main(ws, CMD_TUN_MTU, &msg,
			 (pack_size_func) tun_mtu_msg__get_packed_size,
			 (pack_func) tun_mtu_msg__pack);

	oclog(ws, LOG_DEBUG, "setting MTU to %u", msg.mtu);
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

	if (ws->req.user_agent[0] != 0) {
		msg.user_agent = ws->req.user_agent;
	}

	send_msg_to_main(ws, CMD_SESSION_INFO, &msg,
			 (pack_size_func) session_info_msg__get_packed_size,
			 (pack_func) session_info_msg__pack);

	gnutls_free(msg.tls_ciphersuite);
	gnutls_free(msg.dtls_ciphersuite);
}

/* mtu_set: Sets the MTU for the session
 *
 * @ws: a worker structure
 * @mtu: the "plaintext" data MTU
 */
static
void mtu_set(worker_st * ws, unsigned mtu)
{
	ws->conn_mtu = mtu;

	if (ws->dtls_session)
		gnutls_dtls_set_data_mtu(ws->dtls_session,
					 ws->conn_mtu + CSTP_DTLS_OVERHEAD);

	mtu_send(ws, ws->conn_mtu);
}

/* sets the current value of mtu as bad,
 * and returns an estimation of good.
 *
 * Returns -1 on failure.
 */
static
int mtu_not_ok(worker_st * ws)
{
	unsigned min = MIN_MTU(ws);

	ws->last_bad_mtu = ws->conn_mtu;

	if (ws->last_good_mtu == min) {
		oclog(ws, LOG_INFO,
		      "could not calculate a sufficient MTU. Disabling DTLS.");
		dtls_close(ws);
		ws->udp_state = UP_DISABLED;
		return -1;
	}

	if (ws->last_good_mtu >= ws->conn_mtu) {
		ws->last_good_mtu = MAX(((2 * (ws->conn_mtu)) / 3), min);
	}

	mtu_set(ws, ws->last_good_mtu);
	oclog(ws, LOG_DEBUG, "MTU %u is too large, switching to %u",
	      ws->last_bad_mtu, ws->conn_mtu);

	return 0;
}

/* mtu_set: initiates MTU discovery
 *
 * @ws: a worker structure
 * @mtu: the current "plaintext" data MTU
 */
static void mtu_discovery_init(worker_st * ws, unsigned mtu)
{
	ws->last_good_mtu = mtu;
	ws->last_bad_mtu = mtu;
}

static
void mtu_ok(worker_st * ws)
{
	unsigned int c;

	if (ws->last_bad_mtu == (ws->conn_mtu) + 1 ||
	    ws->last_bad_mtu == (ws->conn_mtu))
		return;

	ws->last_good_mtu = ws->conn_mtu;
	c = (ws->conn_mtu + ws->last_bad_mtu) / 2;

	mtu_set(ws, c);
	return;
}

static
int periodic_check(worker_st * ws, unsigned mtu_overhead, time_t now,
		   unsigned dpd)
{
	socklen_t sl;
	int max, e, ret;

	if (now - ws->last_periodic_check < PERIODIC_CHECK_TIME)
		return 0;

	if (ws->config->idle_timeout > 0) {
		if (now - ws->last_nc_msg > ws->config->idle_timeout) {
			oclog(ws, LOG_ERR,
			      "idle timeout reached for process (%d secs)",
			      (int)(now - ws->last_nc_msg));
			terminate = 1;
			goto cleanup;
		}

	}

	if (ws->config->stats_report_time > 0 &&
	    now - ws->last_stats_msg >= ws->config->stats_report_time &&
	    ws->sid_set) {
		send_stats_to_secmod(ws, now, 0);
	}

	/* check DPD. Otherwise exit */
	if (ws->udp_state == UP_ACTIVE &&
	    now - ws->last_msg_udp > DPD_TRIES * dpd && dpd > 0) {
		oclog(ws, LOG_ERR,
		      "have not received any UDP message or DPD for long (%d secs, DPD is %d)",
		      (int)(now - ws->last_msg_udp), dpd);

		ws->buffer[0] = AC_PKT_DPD_OUT;
		ret = dtls_send(ws, ws->buffer, 1);
		GNUTLS_FATAL_ERR_CMD(ret, exit_worker(ws));

		if (now - ws->last_msg_udp > DPD_MAX_TRIES * dpd) {
			oclog(ws, LOG_ERR,
			      "have not received UDP message or DPD for very long; disabling UDP port");
			ws->udp_state = UP_INACTIVE;
		}
	}
	if (dpd > 0 && now - ws->last_msg_tcp > DPD_TRIES * dpd) {
		oclog(ws, LOG_ERR,
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
		FATAL_ERR_CMD(ws, ret, exit_worker(ws));

		if (now - ws->last_msg_tcp > DPD_MAX_TRIES * dpd) {
			oclog(ws, LOG_ERR,
			      "have not received TCP DPD for very long; tearing down connection");
			return -1;
		}
	}

	if (ws->conn_type != SOCK_TYPE_UNIX) {
		sl = sizeof(max);
		ret = getsockopt(ws->conn_fd, IPPROTO_TCP, TCP_MAXSEG, &max, &sl);
		if (ret == -1) {
			e = errno;
			oclog(ws, LOG_INFO, "error in getting TCP_MAXSEG: %s",
			      strerror(e));
		} else {
			max -= 13;
			/*oclog(ws, LOG_DEBUG, "TCP MSS is %u", max); */
			if (max > 0 && max - mtu_overhead < ws->conn_mtu) {
				oclog(ws, LOG_DEBUG, "reducing MTU due to TCP MSS to %u",
				      max - mtu_overhead);
				mtu_set(ws, MIN(ws->conn_mtu, max - mtu_overhead));
			}
		}
	}

 cleanup:
	ws->last_periodic_check = now;

	return 0;
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
		t = ws->config->net_priority - 1;
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
#ifdef ZERO_COPY
	gnutls_packet_t packet = NULL;
#endif

	switch (ws->udp_state) {
	case UP_ACTIVE:
	case UP_INACTIVE:
#if GNUTLS_VERSION_NUMBER <= 0x030210
		/* work-around an infinite loop caused by gnutls_record_recv()
		 * always succeeding by counting every error as a discarded packet.
		 */
		ret = gnutls_record_get_discarded(ws->dtls_session);
		if (ret > 1000) {
			ws->udp_state = UP_DISABLED;
			break;
		}
#endif

#ifdef ZERO_COPY
		ret = gnutls_record_recv_packet(ws->dtls_session, &packet);
		if (ret > 0) {
			gnutls_packet_get(packet, &data, NULL);
		} else {
			data.size = 0;
		}
#else
		ret =
		    gnutls_record_recv(ws->dtls_session, ws->buffer, ws->buffer_size);
		data.data = ws->buffer;
		data.size = ret;
#endif
		oclog(ws, LOG_TRANSFER_DEBUG,
		      "received %d byte(s) (DTLS)", ret);

		GNUTLS_FATAL_ERR_CMD(ret, exit_worker(ws));

		if (ret == GNUTLS_E_REHANDSHAKE) {

			if (ws->last_dtls_rehandshake > 0 &&
			    tnow->tv_sec - ws->last_dtls_rehandshake <
			    ws->config->rekey_time / 2) {
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

			GNUTLS_FATAL_ERR_CMD(ret, exit_worker(ws));
			oclog(ws, LOG_DEBUG, "DTLS rehandshake completed");

			ws->last_dtls_rehandshake = tnow->tv_sec;
		} else if (ret >= 1) {
			ws->udp_state = UP_ACTIVE;

			if (bandwidth_update
			    (&ws->b_rx, data.size - 1, ws->conn_mtu, tnow) != 0) {
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

		gnutls_dtls_set_mtu(ws->dtls_session,
				    ws->conn_mtu + ws->crypto_overhead);
		mtu_discovery_init(ws, ws->conn_mtu);
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
			unsigned mtu;

			/* gnutls_dtls_get_data_mtu() already subtracts the crypto overhead */
			mtu =
			    gnutls_dtls_get_data_mtu(ws->dtls_session) -
			    CSTP_DTLS_OVERHEAD;

			/* openconnect doesn't like if we send more bytes
			 * than the initially agreed MTU */
			if (mtu > ws->conn_mtu)
				mtu = ws->conn_mtu;

			ws->udp_state = UP_ACTIVE;
			mtu_discovery_init(ws, mtu);
			mtu_set(ws, mtu);
			oclog(ws, LOG_DEBUG,
			      "DTLS handshake completed (plaintext MTU: %u)\n",
			      ws->conn_mtu);
			session_info_send(ws);
		}

		break;
	default:
		break;
	}

	ret = 0;
 cleanup:
#ifdef ZERO_COPY
 	if (packet)
	 	gnutls_packet_deinit(packet);
#endif
	return ret;
}

static int tls_mainloop(struct worker_st *ws, struct timespec *tnow)
{
	int ret;
	gnutls_datum_t data;
#ifdef ZERO_COPY
	gnutls_packet_t packet = NULL;

	if (ws->session != NULL) {
		ret = gnutls_record_recv_packet(ws->session, &packet);
		if (ret > 0) {
			gnutls_packet_get(packet, &data, NULL);
		}
	} else {
		ret = recv(ws->conn_fd, ws->buffer, ws->buffer_size, 0);
		data.data = ws->buffer;
		data.size = ret;
	}
#else
	ret = cstp_recv_nb(ws, ws->buffer, ws->buffer_size);
	data.data = ws->buffer;
	data.size = ret;
#endif
	FATAL_ERR_CMD(ws, ret, exit_worker(ws));

	if (ret == 0) {		/* disconnect */
		oclog(ws, LOG_DEBUG, "client disconnected");
		ret = -1;
		goto cleanup;
	} else if (ret >= 8) {
		oclog(ws, LOG_TRANSFER_DEBUG, "received %d byte(s) (TLS)", data.size);

		if (bandwidth_update(&ws->b_rx, data.size - 8, ws->conn_mtu, tnow) != 0) {
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
		    ws->config->rekey_time / 2) {
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
		GNUTLS_FATAL_ERR_CMD(ret, exit_worker(ws));

		ws->last_tls_rehandshake = tnow->tv_sec;
		oclog(ws, LOG_INFO, "TLS rehandshake completed");
	}

	ret = 0;
 cleanup:
#ifdef ZERO_COPY
 	if (packet)
	 	gnutls_packet_deinit(packet);
#endif
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

	l = tun_read(ws->tun_fd, ws->buffer + 8, ws->conn_mtu);
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

	if (ws->udp_state == UP_ACTIVE && ws->dtls_selected_comp != NULL && l > ws->config->no_compress_limit) {
		/* otherwise don't compress */
		ret = ws->dtls_selected_comp->compress(ws->decomp+8, sizeof(ws->decomp)-8, ws->buffer+8, l);
		oclog(ws, LOG_DEBUG, "compressed %d to %d\n", (int)l, ret);
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
	} else if (ws->cstp_selected_comp != NULL && l > ws->config->no_compress_limit) {
		/* otherwise don't compress */
		ret = ws->cstp_selected_comp->compress(ws->decomp+8, sizeof(ws->decomp)-8, ws->buffer+8, l);
		oclog(ws, LOG_DEBUG, "compressed %d to %d\n", (int)l, ret);
		if (ret > 0 && ret < l) {
			cstp_to_send.data = ws->decomp;
			cstp_to_send.size = ret;
			cstp_type = AC_PKT_COMPRESSED;
		}
	}

	/* only transmit if allowed */
	if (bandwidth_update(&ws->b_tx, dtls_to_send.size, ws->conn_mtu, tnow)
	    != 0) {
		tls_retry = 0;

		oclog(ws, LOG_TRANSFER_DEBUG, "sending %d byte(s)\n", l);

		if (ws->udp_state == UP_ACTIVE) {

			ws->tun_bytes_out += dtls_to_send.size;

			dtls_to_send.data[7] = dtls_type;
			ret = dtls_send(ws, dtls_to_send.data + 7, dtls_to_send.size + 1);
			GNUTLS_FATAL_ERR_CMD(ret, exit_worker(ws));

			if (ret == GNUTLS_E_LARGE_PACKET) {
				mtu_not_ok(ws);

				oclog(ws, LOG_TRANSFER_DEBUG,
				      "retrying (TLS) %d\n", l);
				tls_retry = 1;
			} else if (ret >= ws->conn_mtu &&
				   ws->config->try_mtu != 0) {
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
			FATAL_ERR_CMD(ws, ret, exit_worker(ws));
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

	str_init(&str, ws);

	ret = str_append_str(&str, txt);
	if (ret < 0)
		return NULL;

	ret = str_replace_str(&str, "%{U}", ws->username);
	if (ret < 0) {
		str_clear(&str);
		return NULL;
	}

	ret = str_replace_str(&str, "%{G}", ws->groupname);
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
		oclog(ws, LOG_DEBUG, "%s route %s", txt, routes[i]);

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
	fd_set rfds;
	int e, max, ret, t;
	char *p;
#ifdef HAVE_PSELECT
	struct timespec tv;
#else
	struct timeval tv;
#endif
	unsigned tls_pending, dtls_pending = 0, i;
	struct timespec tnow;
	unsigned proto_overhead = 0, ip6;
	socklen_t sl;
	sigset_t emptyset, blockset;

	sigemptyset(&blockset);
	sigemptyset(&emptyset);
	sigaddset(&blockset, SIGTERM);

	ws->buffer_size = sizeof(ws->buffer);

	/* we must be in S_AUTH_COOKIE state */
	if (ws->auth_state != S_AUTH_COOKIE || ws->cookie_set == 0) {
		oclog(ws, LOG_WARNING, "no cookie found");
		cstp_puts(ws,
			 "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		cstp_fatal_close(ws, GNUTLS_A_ACCESS_DENIED);
		exit_worker(ws);
	}

	/* we have authenticated against sec-mod, we need to complete
	 * our authentication by forwarding our cookie to main. */
	ret = auth_cookie(ws, ws->cookie, ws->cookie_size);
	if (ret < 0) {
		oclog(ws, LOG_WARNING, "failed cookie authentication attempt");
		if (ret == ERR_AUTH_FAIL) {
			cstp_puts(ws,
				 "HTTP/1.1 401 Unauthorized\r\n\r\n");
			cstp_puts(ws,
				 "X-Reason: Cookie is not acceptable\r\n\r\n");
		} else {
			cstp_puts(ws,
				 "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		}
		cstp_fatal_close(ws, GNUTLS_A_ACCESS_DENIED);
		exit_worker(ws);
	}
	ws->auth_state = S_AUTH_COMPLETE;

	if (strcmp(req->url, "/CSCOSSLC/tunnel") != 0) {
		oclog(ws, LOG_INFO, "bad connect request: '%s'\n", req->url);
		cstp_puts(ws, "HTTP/1.1 404 Nah, go away\r\n\r\n");
		cstp_fatal_close(ws, GNUTLS_A_ACCESS_DENIED);
		exit_worker(ws);
	}

	if (ws->config->network.name[0] == 0) {
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

	/* Connected. Turn of the alarm */
	if (ws->config->auth_timeout)
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
		ws->config->dpd = ws->config->mobile_dpd;
		ws->config->idle_timeout = ws->config->mobile_idle_timeout;
	}

	oclog(ws, LOG_DEBUG, "suggesting DPD of %d secs", ws->config->dpd);
	if (ws->config->dpd > 0) {
		ret =
		    cstp_printf(ws, "X-CSTP-DPD: %u\r\n",
			       ws->config->dpd);
		SEND_ERR(ret);
	}

	if (ws->config->default_domain) {
		ret =
		    cstp_printf(ws, "X-CSTP-Default-Domain: %s\r\n",
			       ws->config->default_domain);
		SEND_ERR(ret);
	}

	ws->udp_state = UP_DISABLED;
	if (ws->perm_config->udp_port != 0 && req->master_secret_set != 0 && ws->req.selected_ciphersuite != NULL) {
		memcpy(ws->master_secret, req->master_secret, TLS_MASTER_SIZE);
		ws->udp_state = UP_WAIT_FD;
	} else {
		oclog(ws, LOG_DEBUG, "disabling UDP (DTLS) connection");
	}

	/* calculate base MTU */
	if (ws->config->default_mtu > 0) {
		ws->vinfo.mtu = ws->config->default_mtu;
	}

	if (req->base_mtu > 0) {
		oclog(ws, LOG_DEBUG, "peer's base MTU is %u", req->base_mtu);
		ws->vinfo.mtu = MIN(ws->vinfo.mtu, req->base_mtu);
	}

	if (ws->conn_type != SOCK_TYPE_UNIX) {
		sl = sizeof(max);
		ret = getsockopt(ws->conn_fd, IPPROTO_TCP, TCP_MAXSEG, &max, &sl);
		if (ret == -1) {
			e = errno;
			oclog(ws, LOG_INFO, "error in getting TCP_MAXSEG: %s",
			      strerror(e));
		} else {
			max -= 13;
			oclog(ws, LOG_DEBUG, "TCP MSS is %u", max);
			if (max > 0 && max < ws->vinfo.mtu) {
				oclog(ws, LOG_DEBUG,
				      "reducing MTU due to TCP MSS to %u", max);
				ws->vinfo.mtu = max;
			}
		}
	}

	ret = cstp_printf(ws, "X-CSTP-Base-MTU: %u\r\n", ws->vinfo.mtu);
	SEND_ERR(ret);
	oclog(ws, LOG_DEBUG, "CSTP Base MTU is %u bytes", ws->vinfo.mtu);

	/* calculate TLS channel MTU */
	if (ws->session == NULL) {
		/* wild guess */
		ws->crypto_overhead = CSTP_OVERHEAD +
			tls_get_overhead(GNUTLS_TLS1_0, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1);
	} else {
		ws->crypto_overhead = CSTP_OVERHEAD +
		    tls_get_overhead(gnutls_protocol_get_version(ws->session),
				     gnutls_cipher_get(ws->session),
				     gnutls_mac_get(ws->session));
	}

	/* plaintext MTU is the device MTU minus the overhead
	 * of the CSTP protocol. */
	ws->conn_mtu = ws->vinfo.mtu - ws->crypto_overhead;
	if (ws->conn_mtu < 1280 && ws->vinfo.ipv6 && req->no_ipv6 == 0) {
		oclog(ws, LOG_INFO, "Connection MTU (%d) is not sufficient for IPv6 (1280)", ws->conn_mtu);
		req->no_ipv6 = 1;
	}

	/* Send IP addresses */
	if (ws->vinfo.ipv4 && req->no_ipv4 == 0) {
		oclog(ws, LOG_DEBUG, "sending IPv4 %s", ws->vinfo.ipv4);
		ret =
		    cstp_printf(ws, "X-CSTP-Address: %s\r\n",
			       ws->vinfo.ipv4);
		SEND_ERR(ret);

		if (ws->vinfo.ipv4_netmask) {
			ret =
			    cstp_printf(ws, "X-CSTP-Netmask: %s\r\n",
				       ws->vinfo.ipv4_netmask);
			SEND_ERR(ret);
		}
	}

	if (ws->vinfo.ipv6 && req->no_ipv6 == 0 && ws->vinfo.ipv6_prefix != 0) {
		oclog(ws, LOG_DEBUG, "sending IPv6 %s/%u", ws->vinfo.ipv6, ws->vinfo.ipv6_prefix);
		if (ws->full_ipv6 && ws->vinfo.ipv6_prefix) {
			ret =
			    cstp_printf(ws,
				       "X-CSTP-Address-IP6: %s/%u\r\n",
				       ws->vinfo.ipv6, ws->vinfo.ipv6_prefix);
			SEND_ERR(ret);
		} else {
			const char *net;

			ret =
			    cstp_printf(ws, "X-CSTP-Address: %s\r\n",
				       ws->vinfo.ipv6);
			SEND_ERR(ret);

			net = ws->vinfo.ipv6_network;
			if (net == NULL)
				net = ws->vinfo.ipv6;

			ret =
			    cstp_printf(ws, "X-CSTP-Netmask: %s/%u\r\n",
				        net, ws->vinfo.ipv6_prefix);
			SEND_ERR(ret);
		}
	}

	/* While anyconnect clients can handle the assignment
	 * of an IPv6 address, they cannot handle routes or DNS
	 * in IPv6. So we disable IPv6 after an IP is assigned. */
	if (ws->full_ipv6 == 0 || req->user_agent_type != AGENT_OPENCONNECT)
		req->no_ipv6 = 1;

	for (i = 0; i < ws->vinfo.dns_size; i++) {
		if (strchr(ws->vinfo.dns[i], ':') != 0)
			ip6 = 1;
		else
			ip6 = 0;

		if (req->no_ipv6 != 0 && ip6 != 0)
			continue;
		if (req->no_ipv4 != 0 && ip6 == 0)
			continue;

		ret =
		    cstp_printf(ws, "X-CSTP-DNS: %s\r\n",
			       ws->vinfo.dns[i]);
		SEND_ERR(ret);
	}

	for (i = 0; i < ws->vinfo.nbns_size; i++) {
		if (strchr(ws->vinfo.nbns[i], ':') != 0)
			ip6 = 1;
		else
			ip6 = 0;

		if (req->no_ipv6 != 0 && ip6 != 0)
			continue;
		if (req->no_ipv4 != 0 && ip6 == 0)
			continue;

		ret =
		    cstp_printf(ws, "X-CSTP-NBNS: %s\r\n",
			       ws->vinfo.nbns[i]);
		SEND_ERR(ret);
	}

	for (i = 0; i < ws->config->split_dns_size; i++) {
		if (strchr(ws->config->split_dns[i], ':') != 0)
			ip6 = 1;
		else
			ip6 = 0;

		if (req->no_ipv6 != 0 && ip6 != 0)
			continue;
		if (req->no_ipv4 != 0 && ip6 == 0)
			continue;

		oclog(ws, LOG_DEBUG, "adding split DNS %s",
		      ws->config->split_dns[i]);
		ret =
		    cstp_printf(ws, "X-CSTP-Split-DNS: %s\r\n",
			       ws->config->split_dns[i]);
		SEND_ERR(ret);
	}

	if (ws->default_route == 0) {
		ret = send_routes(ws, req, ws->vinfo.routes, ws->vinfo.routes_size, 1);
		SEND_ERR(ret);

		ret = send_routes(ws, req, ws->routes, ws->routes_size, 1);
		SEND_ERR(ret);
	}

	ret = send_routes(ws, req, ws->vinfo.no_routes, ws->vinfo.no_routes_size, 0);
	SEND_ERR(ret);

	ret = send_routes(ws, req, ws->no_routes, ws->no_routes_size, 0);
	SEND_ERR(ret);

	ret =
	    cstp_printf(ws, "X-CSTP-Keepalive: %u\r\n",
		       ws->config->keepalive);
	SEND_ERR(ret);

	if (ws->config->idle_timeout > 0) {
		ret =
		    cstp_printf(ws,
			       "X-CSTP-Idle-Timeout: %u\r\n",
			       (unsigned)ws->config->idle_timeout);
	} else {
		ret = cstp_puts(ws, "X-CSTP-Idle-Timeout: none\r\n");
	}
	SEND_ERR(ret);

	ret =
	    cstp_puts(ws,
		     "X-CSTP-Smartcard-Removal-Disconnect: true\r\n");
	SEND_ERR(ret);

	if (ws->config->is_dyndns != 0) {
		ret =
		    cstp_puts(ws,
			     "X-CSTP-DynDNS: true\r\n");
		SEND_ERR(ret);
	}

	if (ws->config->rekey_time > 0) {
		unsigned method;

		ret =
		    cstp_printf(ws, "X-CSTP-Rekey-Time: %u\r\n",
			       (unsigned)(ws->config->rekey_time));
		SEND_ERR(ret);

		/* if the peer isn't patched for safe renegotiation, always
		 * require him to open a new tunnel. */
		if (ws->session != NULL && gnutls_safe_renegotiation_status(ws->session) != 0)
			method = ws->config->rekey_method;
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

	if (ws->config->proxy_url != NULL) {
		char *url = replace_vals(ws, ws->config->proxy_url);
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
		       "X-CSTP-Tunnel-All-DNS: false\r\n"
		       "X-CSTP-License: accept\r\n");
	SEND_ERR(ret);

	for (i = 0; i < ws->config->custom_header_size; i++) {
		char *h = replace_vals(ws, ws->config->custom_header[i]);

		if (h) {
			oclog(ws, LOG_DEBUG, "adding custom header '%s'", h);
			ret =
			    cstp_printf(ws, "%s\r\n", h);
			SEND_ERR(ret);
			talloc_free(h);
		}
	}


	/* set TCP socket options */
	if (ws->config->output_buffer > 0) {
		t = ws->conn_mtu * ws->config->output_buffer;
		ret =
		    setsockopt(ws->conn_fd, SOL_SOCKET, SO_SNDBUF, &t,
			       sizeof(t));
		if (ret == -1)
			oclog(ws, LOG_DEBUG,
			      "setsockopt(TCP, SO_SNDBUF) to %u, failed.", t);
	}

	set_non_block(ws->conn_fd);
	set_net_priority(ws, ws->conn_fd, ws->config->net_priority);

	if (ws->udp_state != UP_DISABLED) {

		p = (char *)ws->buffer;
		for (i = 0; i < sizeof(ws->session_id); i++) {
			sprintf(p, "%.2x", (unsigned int)ws->session_id[i]);
			p += 2;
		}
		ret =
		    cstp_printf(ws, "X-DTLS-Session-ID: %s\r\n",
			       ws->buffer);
		SEND_ERR(ret);

		if (ws->config->dpd > 0) {
			ret =
			    cstp_printf(ws, "X-DTLS-DPD: %u\r\n",
				       ws->config->dpd);
			SEND_ERR(ret);
		}

		ret =
		    cstp_printf(ws, "X-DTLS-Port: %u\r\n",
			       ws->perm_config->udp_port);
		SEND_ERR(ret);

		if (ws->config->rekey_time > 0) {
			ret =
			    cstp_printf(ws, "X-DTLS-Rekey-Time: %u\r\n",
				       (unsigned)(ws->config->rekey_time + 10));
			SEND_ERR(ret);

			/* This is our private extension */
			if (ws->config->rekey_method == REKEY_METHOD_SSL) {
				ret =
				    cstp_puts(ws,
					     "X-DTLS-Rekey-Method: ssl\r\n");
				SEND_ERR(ret);
			}
		}

		ret =
		    cstp_printf(ws, "X-DTLS-Keepalive: %u\r\n",
			       ws->config->keepalive);
		SEND_ERR(ret);

		oclog(ws, LOG_DEBUG, "DTLS ciphersuite: %s",
		      ws->req.selected_ciphersuite->oc_name);
		ret =
		    cstp_printf(ws, "X-DTLS-CipherSuite: %s\r\n",
			       ws->req.selected_ciphersuite->oc_name);
		SEND_ERR(ret);

		/* assume that if IPv6 is used over TCP then the same would be used over UDP */
		if (ws->proto == AF_INET)
			proto_overhead = 20;	/* ip */
		else
			proto_overhead = 40;	/* ipv6 */
		proto_overhead += 8;	/* udp */

		/* crypto overhead for DTLS */
		ws->crypto_overhead =
		    tls_get_overhead(ws->req.
				     selected_ciphersuite->gnutls_version,
				     ws->req.
				     selected_ciphersuite->gnutls_cipher,
				     ws->req.selected_ciphersuite->gnutls_mac);
		ws->crypto_overhead += CSTP_DTLS_OVERHEAD;

		oclog(ws, LOG_DEBUG,
		      "DTLS overhead is %u",
		      proto_overhead + ws->crypto_overhead);

		/* plaintext MTU is the device MTU minus the overhead
		 * of the DTLS (+AnyConnect header) protocol.
		 */
		ws->conn_mtu =
		    MIN(ws->conn_mtu,
			ws->vinfo.mtu - proto_overhead - ws->crypto_overhead);

		ret =
		    cstp_printf(ws, "X-DTLS-MTU: %u\r\n", ws->conn_mtu);
		SEND_ERR(ret);
		oclog(ws, LOG_DEBUG, "suggesting DTLS MTU %u", ws->conn_mtu);

		if (ws->config->output_buffer > 0) {
			t = MIN(2048, ws->conn_mtu * ws->config->output_buffer);
			setsockopt(ws->dtls_tptr.fd, SOL_SOCKET, SO_SNDBUF, &t,
				   sizeof(t));
			if (ret == -1)
				oclog(ws, LOG_DEBUG,
				      "setsockopt(UDP, SO_SNDBUF) to %u, failed.",
				      t);
		}

		set_net_priority(ws, ws->dtls_tptr.fd, ws->config->net_priority);
	}

	/* hack for openconnect. It uses only a single MTU value */
	ret = cstp_printf(ws, "X-CSTP-MTU: %u\r\n", ws->conn_mtu);
	SEND_ERR(ret);

	if (ws->buffer_size <= ws->conn_mtu + CSTP_OVERHEAD) {
		oclog(ws, LOG_ERR,
		      "buffer size is smaller than MTU (%u < %u)",
		      ws->buffer_size, ws->conn_mtu);
		goto exit;
	}

	mtu_send(ws, ws->conn_mtu);

	if (ws->config->banner) {
		ret =
		    cstp_printf(ws, "X-CSTP-Banner: %s\r\n",
			       ws->config->banner);
		SEND_ERR(ret);
	}

	/* send any compression methods */
	if (ws->dtls_selected_comp) {
		oclog(ws, LOG_DEBUG, "selected DTLS compression method %s\n", ws->dtls_selected_comp->name);
		ret =
		    cstp_printf(ws, "X-DTLS-Content-Encoding: %s\r\n",
			        ws->dtls_selected_comp->name);
		SEND_ERR(ret);
	}

	if (ws->cstp_selected_comp) {
		oclog(ws, LOG_DEBUG, "selected CSTP compression method %s\n", ws->cstp_selected_comp->name);
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

	bandwidth_init(&ws->b_rx, ws->config->rx_per_sec);
	bandwidth_init(&ws->b_tx, ws->config->tx_per_sec);

	session_info_send(ws);
	sigprocmask(SIG_BLOCK, &blockset, NULL);

	/* worker main loop  */
	for (;;) {
		FD_ZERO(&rfds);

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
			ret = cstp_send(ws, ws->buffer, 8);
			FATAL_ERR_CMD(ws, ret, exit_worker(ws));
			goto exit;
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

		if (tls_pending == 0 && dtls_pending == 0) {
			FD_SET(ws->conn_fd, &rfds);
			FD_SET(ws->cmd_fd, &rfds);
			FD_SET(ws->tun_fd, &rfds);
			max = MAX(ws->cmd_fd, ws->conn_fd);
			max = MAX(max, ws->tun_fd);

			if (ws->udp_state > UP_WAIT_FD) {
				FD_SET(ws->dtls_tptr.fd, &rfds);
				max = MAX(max, ws->dtls_tptr.fd);
			}

#ifdef HAVE_PSELECT
			tv.tv_nsec = 0;
			tv.tv_sec = 10;
			ret =
			    pselect(max + 1, &rfds, NULL, NULL, &tv, &emptyset);
#else
			tv.tv_usec = 0;
			tv.tv_sec = 10;
			sigprocmask(SIG_UNBLOCK, &blockset, NULL);
			ret = select(max + 1, &rfds, NULL, NULL, &tv);
			sigprocmask(SIG_BLOCK, &blockset, NULL);
#endif
			if (ret == -1) {
				if (errno == EINTR)
					continue;
				goto exit;
			}
		}
		gettime(&tnow);

		if (periodic_check
		    (ws, proto_overhead + ws->crypto_overhead, tnow.tv_sec,
		     ws->config->dpd) < 0)
			goto exit;

		/* send pending data from tun device */
		if (FD_ISSET(ws->tun_fd, &rfds)) {
			ret = tun_mainloop(ws, &tnow);
			if (ret < 0)
				goto exit;
		}

		/* read pending data from TCP channel */
		if (FD_ISSET(ws->conn_fd, &rfds) || tls_pending != 0) {
			ret = tls_mainloop(ws, &tnow);
			if (ret < 0)
				goto exit;
		}

		/* read data from UDP channel */
		if (ws->udp_state > UP_WAIT_FD &&
		    (FD_ISSET(ws->dtls_tptr.fd, &rfds) || dtls_pending != 0)) {

			ret = dtls_mainloop(ws, &tnow);
			if (ret < 0)
				goto exit;
		}

		/* read commands from command fd */
		if (FD_ISSET(ws->cmd_fd, &rfds)) {
			ret = handle_worker_commands(ws);
			if (ret == ERR_NO_CMD_FD) {
				goto terminate;
			}

			if (ret < 0) {
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

	exit_worker(ws);

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

			ret = dtls_send(ws, buf, buf_size);
			if (ret == GNUTLS_E_LARGE_PACKET) {
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
		oclog(ws, LOG_DEBUG, "received BYE packet; exiting");
		exit_worker_reason(ws, REASON_USER_DISCONNECT);
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

	return head;
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
