/*
 * Copyright (C) 2012, 2013 David Woodhouse
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
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#include <vpn.h>
#include "ipc.h"
#include <cookies.h>
#include <worker.h>
#include <tlslib.h>

#include <http-parser/http_parser.h>

/* after that time (secs) of inactivity in the UDP part, connection switches to 
 * TCP (if activity occurs there).
 */
#define UDP_SWITCH_TIME 15

/* The number of DPD packets a client skips before he's kicked */
#define DPD_TRIES 2
#define DPD_MAX_TRIES 3

/* HTTP requests prior to disconnection */
#define MAX_HTTP_REQUESTS 8

static int terminate = 0;
static int parse_cstp_data(struct worker_st* ws, uint8_t* buf, size_t buf_size);
static int parse_dtls_data(struct worker_st* ws, 
				uint8_t* buf, size_t buf_size);

static void handle_alarm(int signo)
{
	exit(1);
}

static void handle_term(int signo)
{
	terminate = 1;
	alarm(2); /* force exit by SIGALRM */
}

static int connect_handler(worker_st *ws);

typedef int (*url_handler_fn)(worker_st*);
struct known_urls_st {
	const char* url;
	url_handler_fn get_handler;
	url_handler_fn post_handler;
};

struct known_urls_st known_urls[] = {
		{"/", get_auth_handler, post_new_auth_handler},
		{"/auth", get_auth_handler, post_old_auth_handler},
		{NULL, NULL}
};

static url_handler_fn get_url_handler(const char* url)
{
struct known_urls_st *p;

	p = known_urls;
	do {
		if (p->url != NULL && strcmp(p->url, url)==0)
			return p->get_handler;
		p++;
	} while(p->url != NULL);
	
	return NULL;
}

static url_handler_fn post_url_handler(const char* url)
{
struct known_urls_st *p;

	p = known_urls;
	do {
		if (p->url != NULL && strcmp(p->url, url)==0)
			return p->post_handler;
		p++;
	} while(p->url != NULL);
	
	return NULL;
}

int url_cb(http_parser* parser, const char *at, size_t length)
{
	struct worker_st *ws = parser->data;
	struct req_data_st *req = &ws->req;
	
	if (length >= sizeof(req->url)) {
		req->url[0] = 0;
		return 1;
	}

	memcpy(req->url, at, length);
	req->url[length] = 0;

	return 0;
}

#define STR_HDR_COOKIE "Cookie"
#define STR_HDR_MS "X-DTLS-Master-Secret"
#define STR_HDR_DMTU "X-DTLS-MTU"
#define STR_HDR_CMTU "X-CSTP-MTU"
#define STR_HDR_HOST "X-CSTP-Hostname"
int header_field_cb(http_parser* parser, const char *at, size_t length)
{
	struct worker_st *ws = parser->data;
	struct req_data_st *req = &ws->req;

	if (length == sizeof(STR_HDR_COOKIE)-1 && strncmp(at, STR_HDR_COOKIE, length) == 0) {
		req->next_header = HEADER_COOKIE;
	} else if (length == sizeof(STR_HDR_MS)-1 && strncmp(at, STR_HDR_MS, length) == 0) {
		req->next_header = HEADER_MASTER_SECRET;
	} else if (length == sizeof(STR_HDR_DMTU)-1 && strncmp(at, STR_HDR_DMTU, length) == 0) {
		req->next_header = HEADER_DTLS_MTU;
	} else if (length == sizeof(STR_HDR_CMTU)-1 && strncmp(at, STR_HDR_CMTU, length) == 0) {
		req->next_header = HEADER_CSTP_MTU;
	} else if (length == sizeof(STR_HDR_HOST)-1 && strncmp(at, STR_HDR_HOST, length) == 0) {
		req->next_header = HEADER_HOSTNAME;
	} else {
		req->next_header = 0;
	}
	
	if (length < sizeof(req->dbg_txt)) {
		memcpy(req->dbg_txt, at, length);
		req->dbg_txt[length] = 0;
	} else {
		oclog(ws, LOG_ERR, "oversized HTTP header %.*s\n", (int)length, at);
		req->dbg_txt[0] = 0;
	}
	
	return 0;
}

int header_value_cb(http_parser* parser, const char *at, size_t length)
{
	struct worker_st *ws = parser->data;
	struct req_data_st *req = &ws->req;
	char *p;
	size_t nlen;

	if (length > 0) {
		oclog(ws, LOG_DEBUG, "HTTP: %s: %.*s", req->dbg_txt, (int)length, at);

		switch (req->next_header) {
			case HEADER_MASTER_SECRET:
				if (length < TLS_MASTER_SIZE*2) {
					req->master_secret_set = 0;
					return 0;
				}
				
				length = TLS_MASTER_SIZE*2;

				nlen = sizeof(req->master_secret);

				gnutls_hex2bin(at, length, req->master_secret, &nlen);
				req->master_secret_set = 1;
				break;
			case HEADER_HOSTNAME:
				if (length >- MAX_HOSTNAME_SIZE) {
					req->hostname[0] = 0;
					return 0;
				}
				memcpy(req->hostname, at, length);
				req->hostname[length] = 0;

				break;
			case HEADER_CSTP_MTU:
				req->cstp_mtu = atoi(at);
				break;
			case HEADER_DTLS_MTU:
				req->dtls_mtu = atoi(at);
				break;
			case HEADER_COOKIE:
				p = memmem(at, length, "webvpn=", 7);
				if (p == NULL || length <= 7) {
					req->cookie_set = 0;
					return 0;
				}
				p += 7;
				length -= 7;
				
				if (length < COOKIE_SIZE*2) {
					req->cookie_set = 0;
					return 0;
				}
				length = COOKIE_SIZE*2;

				nlen = sizeof(req->cookie);
				gnutls_hex2bin(p, length, req->cookie, &nlen);

				if (nlen < COOKIE_SIZE) {
					req->cookie_set = 0;
					return 0;
				}
				req->cookie_set = 1;
				break;
		}
	}
	
	return 0;
}

int header_complete_cb(http_parser* parser)
{
	struct worker_st *ws = parser->data;
	struct req_data_st *req = &ws->req;

	req->headers_complete = 1;
	return 0;
}

int message_complete_cb(http_parser* parser)
{
	struct worker_st *ws = parser->data;
	struct req_data_st *req = &ws->req;

	req->message_complete = 1;
	return 0;
}

int body_cb(http_parser* parser, const char *at, size_t length)
{
	struct worker_st *ws = parser->data;
	struct req_data_st *req = &ws->req;
	char* tmp;
	
	tmp = malloc(length+1);

	if (tmp == NULL)
		return 1;
		
	memcpy(tmp, at, length);
	tmp[length] = 0;

	req->body = tmp;
	return 0;
}

#define GNUTLS_CIPHERSUITE "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:%COMPAT:%DISABLE_SAFE_RENEGOTIATION"
#define OPENSSL_CIPHERSUITE "AES128-SHA"

static int setup_dtls_connection(struct worker_st *ws)
{
int ret;
gnutls_session_t session;
gnutls_datum_t master = { ws->master_secret, sizeof(ws->master_secret) };
gnutls_datum_t sid = { ws->session_id, sizeof(ws->session_id) };

	/* DTLS cookie verified.
	 * Initialize session.
	 */
	ret = gnutls_init(&session, GNUTLS_SERVER|GNUTLS_DATAGRAM);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not initialize TLS session: %s", gnutls_strerror(ret));
		return -1;
	}

	ret = gnutls_priority_set_direct(session, GNUTLS_CIPHERSUITE, NULL);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS priority: %s", gnutls_strerror(ret));
		goto fail;
	}

	ret = gnutls_session_set_premaster(session, GNUTLS_SERVER,
		GNUTLS_DTLS0_9, GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_128_CBC,
		GNUTLS_MAC_SHA1, GNUTLS_COMP_NULL, &master, &sid);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS premaster: %s", gnutls_strerror(ret));
		goto fail;
	}
	
	ret =
	    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				   ws->creds->xcred);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS credentials: %s", gnutls_strerror(ret));
		goto fail;
	}

	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) (long)ws->udp_fd);
	gnutls_session_set_ptr(session, ws);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);

	ws->udp_state = UP_HANDSHAKE;

	ws->dtls_session = session;

	return 0;
fail:
	gnutls_deinit(session);
	return -1;
}

static
void exit_worker(worker_st *ws)
{
	closelog();
	exit(1);
}

void vpn_server(struct worker_st* ws)
{
	unsigned char buf[2048];
	int ret;
	ssize_t nparsed, nrecvd;
	gnutls_session_t session;
	http_parser parser;
	http_parser_settings settings;
	url_handler_fn fn;
	int requests_left = MAX_HTTP_REQUESTS;

	signal(SIGTERM, handle_term);
	signal(SIGINT, handle_term);
	signal(SIGHUP, SIG_IGN);
	signal(SIGALRM, handle_alarm);

	if (ws->config->auth_timeout)
		alarm(ws->config->auth_timeout);
		
	ret = disable_system_calls(ws);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not disable system calls (seccomp error)");
		exit_worker(ws);
	}

	oclog(ws, LOG_INFO, "accepted connection");
	if (ws->remote_addr_len == sizeof(struct sockaddr_in))
		ws->proto = AF_INET;
	else
		ws->proto = AF_INET6;

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
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) (long)ws->conn_fd);
	set_resume_db_funcs(session);
	gnutls_session_set_ptr(session, ws);
	gnutls_db_set_ptr (session, ws);
	gnutls_db_set_cache_expiration(session, TLS_SESSION_EXPIRATION_TIME);

	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	GNUTLS_FATAL_ERR(ret);

	memset(&settings, 0, sizeof(settings));

	settings.on_url = url_cb;
	settings.on_header_field = header_field_cb;
	settings.on_header_value = header_value_cb;
	settings.on_headers_complete = header_complete_cb;
	settings.on_message_complete = message_complete_cb;
	settings.on_body = body_cb;

	ws->session = session;
	ws->parser = &parser;

restart:
	if (requests_left-- <= 0) {
		oclog(ws, LOG_INFO, "maximum number of HTTP requests reached"); 
		exit_worker(ws);
	}

	http_parser_init(&parser, HTTP_REQUEST);
	parser.data = ws;

	/* parse as we go */
	ws->req.headers_complete = 0;
	ws->req.message_complete = 0;
	do {
		nrecvd = tls_recv(session, buf, sizeof(buf));
		if (nrecvd <= 0) {
			oclog(ws, LOG_INFO, "error receiving client data"); 
			exit_worker(ws);
		}
	
		nparsed = http_parser_execute(&parser, &settings, (void*)buf, nrecvd);
		if (nparsed == 0) {
			oclog(ws, LOG_INFO, "error parsing HTTP request"); 
			exit_worker(ws);
		}
	} while(ws->req.headers_complete == 0);

	if (parser.method == HTTP_GET) {
		fn = get_url_handler(ws->req.url);
		if (fn == NULL) {
			oclog(ws, LOG_INFO, "unexpected URL %s", ws->req.url); 
			tls_puts(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
			goto finish;
		}
		
		ret = fn(ws);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else if (parser.method == HTTP_POST) {
		/* continue reading */
		while(ws->req.message_complete == 0) {
			nrecvd = tls_recv(session, buf, sizeof(buf));
			GNUTLS_FATAL_ERR(nrecvd);
		
			nparsed = http_parser_execute(&parser, &settings, (void*)buf, nrecvd);
			if (nparsed == 0) {
				oclog(ws, LOG_INFO, "error parsing HTTP request"); 
				exit_worker(ws);
			}
		}

		fn = post_url_handler(ws->req.url);
		if (fn == NULL) {
			oclog(ws, LOG_INFO, "unexpected POST URL %s", ws->req.url); 
			tls_puts(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
			goto finish;
		}

		ret = fn(ws);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else if (parser.method == HTTP_CONNECT) {
		ret = connect_handler(ws);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else {
		oclog(ws, LOG_INFO, "unexpected method %s", http_method_str(parser.method)); 
		tls_puts(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
	}

finish:
	tls_close(session);
}

/* sets the provided value of mtu as bad,
 * and returns an estimation of good.
 *
 * Returns -1 on failure.
 */
static
int mtu_not_ok(worker_st* ws)
{
	ws->last_bad_mtu = ws->dtls_mtu;

	if (ws->last_good_mtu >= ws->dtls_mtu) {
		ws->last_good_mtu = (ws->dtls_mtu)/2;
	
		if (ws->last_good_mtu < 128) {
			oclog(ws, LOG_INFO, "could not calculate a valid MTU. Disabling DTLS.");
			ws->udp_state = UP_DISABLED;
			return -1;
		}
	}

	ws->dtls_mtu = ws->last_good_mtu;
	gnutls_dtls_set_data_mtu (ws->dtls_session, ws->dtls_mtu);

	oclog(ws, LOG_DEBUG, "MTU %u is too large, switching to %u", ws->last_bad_mtu, ws->dtls_mtu);

	send_tun_mtu(ws, ws->dtls_mtu-1);

	return 0;
}

static void mtu_discovery_init(worker_st *ws)
{
	ws->last_good_mtu = ws->dtls_mtu;
	ws->last_bad_mtu = ws->dtls_mtu;
}

static
void mtu_ok(worker_st* ws)
{
unsigned int c;

	if (ws->last_bad_mtu == (ws->dtls_mtu)+1 ||
		ws->last_bad_mtu == (ws->dtls_mtu))
		return;
	
	ws->last_good_mtu = ws->dtls_mtu;
	c = (ws->dtls_mtu + ws->last_bad_mtu)/2;

	ws->dtls_mtu = c;
	gnutls_dtls_set_data_mtu (ws->dtls_session, c);
	send_tun_mtu(ws, c-1);

	oclog(ws, LOG_DEBUG, "trying MTU %u", c);

	return;
}


#define SEND_ERR(x) if (x<0) goto send_error
static int connect_handler(worker_st *ws)
{
struct req_data_st *req = &ws->req;
fd_set rfds;
int l, e, max, ret;
struct vpn_st vinfo;
unsigned tls_retry;
char *p;
struct timeval tv;
unsigned tls_pending, dtls_pending = 0, i;
time_t udp_recv_time = 0, now;
unsigned mtu_overhead, tls_mtu = 0;

	ws->buffer_size = 16*1024;
	ws->buffer = malloc(ws->buffer_size);
	if (ws->buffer == NULL) {
		oclog(ws, LOG_INFO, "memory error");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		tls_close(ws->session);
		exit_worker(ws);
	}

	if (req->cookie_set == 0) {
		oclog(ws, LOG_INFO, "connect request without authentication");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
		exit_worker(ws);
	}

	if (ws->auth_ok == 0) {
		/* authentication didn't occur in this session. Use the
		 * cookie */
		ret = auth_cookie(ws, req->cookie, sizeof(req->cookie));
		if (ret < 0) {
			oclog(ws, LOG_INFO, "failed cookie authentication attempt");
			tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
			tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
			exit_worker(ws);
		}
	}

	/* turn of the alarm */
	if (ws->config->auth_timeout)
		alarm(0);

	if (strcmp(req->url, "/CSCOSSLC/tunnel") != 0) {
		oclog(ws, LOG_INFO, "bad connect request: '%s'\n", req->url);
		tls_puts(ws->session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
		tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
		exit_worker(ws);
	}
	
	if (ws->config->network.name == NULL) {
		oclog(ws, LOG_ERR, "no networks are configured; rejecting client");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n");
		tls_puts(ws->session, "X-Reason: Server configuration error\r\n\r\n");
		return -1;
	}

	ret = get_rt_vpn_info(ws, &vinfo, (char*)ws->buffer, ws->buffer_size);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "no networks are configured; rejecting client");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n");
		tls_puts(ws->session, "X-Reason: Server configuration error\r\n\r\n");
		return -1;
	}
	
	tls_cork(ws->session);
	ret = tls_puts(ws->session, "HTTP/1.1 200 CONNECTED\r\n");
	SEND_ERR(ret);

	ret = tls_puts(ws->session, "X-CSTP-Version: 1\r\n");
	SEND_ERR(ret);

	ret = tls_printf(ws->session, "X-CSTP-DPD: %u\r\n", ws->config->dpd);
	SEND_ERR(ret);

	ws->udp_state = UP_DISABLED;
	if (req->master_secret_set != 0) {
		memcpy(ws->master_secret, req->master_secret, TLS_MASTER_SIZE);
		ws->udp_state = UP_WAIT_FD;
	}
	

	if (vinfo.ipv4) {
		oclog(ws, LOG_DEBUG, "sending IPv4 %s", vinfo.ipv4);
		ret = tls_printf(ws->session, "X-CSTP-Address: %s\r\n", vinfo.ipv4);
		SEND_ERR(ret);

		if (vinfo.ipv4_netmask) {
			ret = tls_printf(ws->session, "X-CSTP-Netmask: %s\r\n", vinfo.ipv4_netmask);
			SEND_ERR(ret);
		}
		if (vinfo.ipv4_dns) {
			ret = tls_printf(ws->session, "X-CSTP-DNS: %s\r\n", vinfo.ipv4_dns);
			SEND_ERR(ret);
		}
	}
	
	if (vinfo.ipv6) {
		oclog(ws, LOG_DEBUG, "sending IPv6 %s", vinfo.ipv6);
		ret = tls_printf(ws->session, "X-CSTP-Address: %s\r\n", vinfo.ipv6);
		SEND_ERR(ret);

		if (vinfo.ipv6_netmask) {
			ret = tls_printf(ws->session, "X-CSTP-Netmask: %s\r\n", vinfo.ipv6_netmask);
			SEND_ERR(ret);
		}
		if (vinfo.ipv6_dns) {
			ret = tls_printf(ws->session, "X-CSTP-DNS: %s\r\n", vinfo.ipv6_dns);
			SEND_ERR(ret);
		}
	}

	for (i=0;i<vinfo.routes_size;i++) {
		oclog(ws, LOG_DEBUG, "adding route %s", vinfo.routes[i]);
		ret = tls_printf(ws->session,
			"X-CSTP-Split-Include: %s\r\n", vinfo.routes[i]);
		SEND_ERR(ret);
	}
	ret = tls_printf(ws->session, "X-CSTP-Keepalive: %u\r\n", ws->config->keepalive);
	SEND_ERR(ret);

	tls_mtu = vinfo.mtu - 8;
	if (req->cstp_mtu > 0) {
		tls_mtu = MIN(tls_mtu, req->cstp_mtu);
		oclog(ws, LOG_DEBUG, "peer CSTP MTU is %u", req->cstp_mtu);
	}
	tls_mtu = MIN(ws->buffer_size-8, tls_mtu);

	ret = tls_printf(ws->session, "X-CSTP-MTU: %u\r\n", tls_mtu);
	SEND_ERR(ret);

	if (ws->udp_state != UP_DISABLED) {
		p = (char*)ws->buffer;
		for (i=0;i<sizeof(ws->session_id);i++) {
			sprintf(p, "%.2x", (unsigned int)ws->session_id[i]);
			p+=2;
		}
		ret = tls_printf(ws->session, "X-DTLS-Session-ID: %s\r\n", ws->buffer);
		SEND_ERR(ret);

		ret = tls_printf(ws->session, "X-DTLS-DPD: %u\r\n", ws->config->dpd);
		SEND_ERR(ret);

		ret = tls_printf(ws->session, "X-DTLS-Port: %u\r\n", ws->config->udp_port);
		SEND_ERR(ret);

		ret = tls_printf(ws->session, "X-DTLS-Rekey-Time: %u\r\n", (unsigned)(2*ws->config->cookie_validity)/3);
		SEND_ERR(ret);

		ret = tls_printf(ws->session, "X-DTLS-Keepalive: %u\r\n", ws->config->keepalive);
		SEND_ERR(ret);

		ret = tls_puts(ws->session, "X-DTLS-CipherSuite: "OPENSSL_CIPHERSUITE"\r\n");
		SEND_ERR(ret);

		/* assume that if IPv6 is used over TCP then the same would be used over UDP */
		if (ws->proto == AF_INET)
			mtu_overhead = 20+1; /* ip */
		else
			mtu_overhead = 40+1; /* ipv6 */
		mtu_overhead += 8; /* udp */
		ws->dtls_mtu = vinfo.mtu - mtu_overhead;

		if (req->dtls_mtu > 0) {
			ws->dtls_mtu = MIN(req->dtls_mtu, ws->dtls_mtu);
			oclog(ws, LOG_DEBUG, "peer DTLS MTU is %u", req->dtls_mtu);
		}

		ws->dtls_mtu = MIN(ws->buffer_size-1, ws->dtls_mtu);
		tls_printf(ws->session, "X-DTLS-MTU: %u\r\n", ws->dtls_mtu);
	}

	if (ws->dtls_mtu == 0)
		send_tun_mtu(ws, tls_mtu);
	else
		send_tun_mtu(ws, ws->dtls_mtu-1);

	ret = tls_puts(ws->session, "X-CSTP-Banner: Welcome\r\n");
	SEND_ERR(ret);

	ret = tls_puts(ws->session, "\r\n");
	SEND_ERR(ret);

	ret = tls_uncork(ws->session);
	SEND_ERR(ret);

	/* start dead peer detection */
	ws->last_dpd_tcp = ws->last_dpd_udp = time(0);

	/* main loop  */
	for(;;) {
		FD_ZERO(&rfds);
		
		FD_SET(ws->conn_fd, &rfds);
		FD_SET(ws->cmd_fd, &rfds);
		FD_SET(ws->tun_fd, &rfds);
		max = MAX(ws->cmd_fd,ws->conn_fd);
		max = MAX(max,ws->tun_fd);

		if (ws->udp_state > UP_WAIT_FD) {
			FD_SET(ws->udp_fd, &rfds);
			max = MAX(max,ws->udp_fd);
		}

		if (terminate != 0) {
			if (ws->udp_state == UP_ACTIVE) {
				ws->buffer[0] = AC_PKT_TERM_SERVER;
				
				oclog(ws, LOG_DEBUG, "sending disconnect message in DTLS channel");

				ret = tls_send(ws->dtls_session, ws->buffer, 1);
				GNUTLS_FATAL_ERR(ret);
			}

			ws->buffer[0] = 'S';
			ws->buffer[1] = 'T';
			ws->buffer[2] = 'F';
			ws->buffer[3] = 1;
			ws->buffer[4] = 0;
			ws->buffer[5] = 0;
			ws->buffer[6] = AC_PKT_TERM_SERVER;
			ws->buffer[7] = 0;

			oclog(ws, LOG_DEBUG, "sending disconnect message in TLS channel");
			ret = tls_send(ws->session, ws->buffer, 8);
			GNUTLS_FATAL_ERR(ret);

			goto exit;
		}

		tls_pending = gnutls_record_check_pending(ws->session);
		
		if (ws->dtls_session != NULL)
			dtls_pending = gnutls_record_check_pending(ws->dtls_session);
		if (tls_pending == 0 && dtls_pending == 0) {
			tv.tv_usec = 0;
			tv.tv_sec = 10;
			ret = select(max + 1, &rfds, NULL, NULL, &tv);
			if (ret == -1) {
				if (errno == EINTR)
					continue;
				goto exit;
			}
			
			if (ret == 0) {
				now = time(0);
				/* check DPD. Otherwise exit */
				if (ws->udp_state == UP_ACTIVE && now-ws->last_dpd_udp > DPD_TRIES*ws->config->dpd) {
					oclog(ws, LOG_ERR, "have not received UDP DPD for long (%d secs)", (int)(now-ws->last_dpd_udp));
				
					ws->buffer[0] = AC_PKT_DPD_OUT;
					tls_send(ws->dtls_session, ws->buffer, 1);
				
					if (now-ws->last_dpd_udp > DPD_MAX_TRIES*ws->config->dpd) {
						oclog(ws, LOG_ERR, "have not received UDP DPD for very long; disabling UDP port");
						ws->udp_state = UP_INACTIVE;
					}
				}
				if (now-ws->last_dpd_tcp > DPD_TRIES*ws->config->dpd) {
					oclog(ws, LOG_ERR, "have not received TCP DPD for long (%d secs)", (int)(now-ws->last_dpd_tcp));
					ws->buffer[0] = AC_PKT_DPD_OUT;
					tls_send(ws->session, ws->buffer, 1);

					if (now-ws->last_dpd_tcp > DPD_MAX_TRIES*ws->config->dpd) {
						oclog(ws, LOG_ERR, "have not received TCP DPD for very long; tearing down connection");
						goto exit;
					}
				}
			}
		}
		
		if (FD_ISSET(ws->tun_fd, &rfds)) {
				
			if (ws->udp_state == UP_ACTIVE) {
				l = ws->dtls_mtu-1;
			} else {
				l = tls_mtu;
			}

			l = read(ws->tun_fd, ws->buffer + 8, l);
			if (l < 0) {
				e = errno;
				
				if (e != EAGAIN && e != EINTR) {
					oclog(ws, LOG_ERR, "received corrupt data from tun (%d): %s", l, strerror(e));
					goto exit;
				}
				continue;
			}
			
			if (l == 0) { /* disconnect */
				oclog(ws, LOG_INFO, "TUN device returned zero");
				goto exit;
			}

			tls_retry = 0;
			oclog(ws, LOG_DEBUG, "sending %d byte(s)\n", l);
			if (ws->udp_state == UP_ACTIVE) {
				ws->buffer[7] = AC_PKT_DATA;

				ret = tls_send(ws->dtls_session, ws->buffer + 7, l+1);
				GNUTLS_FATAL_ERR(ret);

				if (ret == GNUTLS_E_LARGE_PACKET) {
					mtu_not_ok(ws);

					oclog(ws, LOG_DEBUG, "retrying (TLS) %d\n", l);
					tls_retry = 1;
				}
			}

			if (ws->udp_state != UP_ACTIVE || tls_retry != 0) {
				ws->buffer[0] = 'S';
				ws->buffer[1] = 'T';
				ws->buffer[2] = 'F';
				ws->buffer[3] = 1;
				ws->buffer[4] = l >> 8;
				ws->buffer[5] = l & 0xff;
				ws->buffer[6] = AC_PKT_DATA;
				ws->buffer[7] = 0;

				ret = tls_send(ws->session, ws->buffer, l + 8);
				GNUTLS_FATAL_ERR(ret);
			}

		}

		if (FD_ISSET(ws->conn_fd, &rfds) || tls_pending != 0) {
			ret = gnutls_record_recv(ws->session, ws->buffer, ws->buffer_size);
			oclog(ws, LOG_DEBUG, "received %d byte(s) (TLS)", ret);

			GNUTLS_FATAL_ERR(ret);

			if (ret == 0) { /* disconnect */
				oclog(ws, LOG_INFO, "client disconnected");
				goto exit_nomsg;
			}
			
			if (ret > 0) {
				l = ret;

				ret = parse_cstp_data(ws, ws->buffer, l);
				if (ret < 0) {
					oclog(ws, LOG_INFO, "error parsing CSTP data");
					goto exit;
				}

				if (ret == AC_PKT_DATA && ws->udp_state == UP_ACTIVE) { 
					/* client switched to TLS for some reason */
					if (time(0) - udp_recv_time > UDP_SWITCH_TIME)
						ws->udp_state = UP_INACTIVE;
				}
			}
		}

		if (ws->udp_state > UP_WAIT_FD && (FD_ISSET(ws->udp_fd, &rfds) || dtls_pending != 0)) {

			switch (ws->udp_state) {
				case UP_ACTIVE:
				case UP_INACTIVE:
					ret = gnutls_record_recv(ws->dtls_session, ws->buffer, ws->buffer_size);
					oclog(ws, LOG_DEBUG, "received %d byte(s) (DTLS)", ret);

					GNUTLS_FATAL_ERR(ret);

					if (ret > 0) {
						l = ret;
						ws->udp_state = UP_ACTIVE;

						ret = parse_dtls_data(ws, ws->buffer, l);
						if (ret < 0) {
							oclog(ws, LOG_INFO, "error parsing CSTP data");
							goto exit;
						}
					
					} else
						oclog(ws, LOG_DEBUG, "no data received (%d)", ret);

					udp_recv_time = time(0);
					break;
				case UP_SETUP:
					ret = setup_dtls_connection(ws);
					if (ret < 0)
						goto exit;
					
					gnutls_dtls_set_mtu (ws->dtls_session, ws->dtls_mtu);
					mtu_discovery_init(ws);

					break;
				case UP_HANDSHAKE:
hsk_restart:
					ret = gnutls_handshake(ws->dtls_session);
					if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
						oclog(ws, LOG_ERR, "error in DTLS handshake: %s\n", gnutls_strerror(ret));
						ws->udp_state = UP_DISABLED;
						break;
					}

					if (ret == GNUTLS_E_LARGE_PACKET) {
						/* adjust mtu */
						mtu_not_ok(ws);
						if (ret == 0) {
							goto hsk_restart;
						}

					}

					if (ret == 0) {
						ws->udp_state = UP_ACTIVE;
						ws->dtls_mtu = gnutls_dtls_get_data_mtu(ws->dtls_session);
						mtu_discovery_init(ws);
						oclog(ws, LOG_DEBUG, "DTLS handshake completed (MTU: %u)\n", ws->dtls_mtu);
					}
					
					break;
				default:
					break;
			}
		}

		if (FD_ISSET(ws->cmd_fd, &rfds)) {
			ret = handle_worker_commands(ws);
			if (ret < 0) {
				goto exit;
			}
		}


	}

	return 0;

exit:
	tls_close(ws->session);
	/*gnutls_deinit(ws->session);*/
	if (ws->udp_state == UP_ACTIVE && ws->dtls_session) {
		tls_close(ws->dtls_session);
		/*gnutls_deinit(ws->dtls_session);*/
	}
exit_nomsg:
	exit_worker(ws);

send_error:
	oclog(ws, LOG_DEBUG, "error sending data\n");
	exit_worker(ws);
	
	return -1;
}


static int parse_data(struct worker_st* ws, 
			gnutls_session_t ts, /* the interface of recv */
			uint8_t head,
			uint8_t* buf, size_t buf_size)
{
int ret, e, l;
time_t now = time(0);

	/* whatever we received treat it as DPD response.
	 * it indicates that the channel is alive */
	if (ws->session == ts) {
		ws->last_dpd_tcp = now;
	} else {
		ws->last_dpd_udp = now;
	}

	switch (head) {
		case AC_PKT_DPD_RESP:
			oclog(ws, LOG_DEBUG, "received DPD response");

			break;
		case AC_PKT_KEEPALIVE:
			oclog(ws, LOG_DEBUG, "received keepalive");
			break;
		case AC_PKT_DPD_OUT:
			now = time(0);

			if (ws->session == ts) {
				ret = tls_send(ts, "STF\x01\x00\x00\x04\x00", 8);

				oclog(ws, LOG_DEBUG, "received TLS DPD; sent response (%d bytes)", ret);
			} else {
				/* Use DPD for MTU discovery in DTLS */
				ws->buffer[0] = AC_PKT_DPD_RESP;
				
				if (ws->config->try_mtu == 0 || ws->dpd_mtu_trial == 0) {
					l = 1;
					if (now-ws->last_dpd_udp <= ws->config->dpd/2)
						mtu_not_ok(ws);

					ws->dpd_mtu_trial++;
				} else {
					l = ws->dtls_mtu;
					ws->dpd_mtu_trial = 0;
				}
				ret = tls_send(ts, ws->buffer, l);

				if (ret == GNUTLS_E_LARGE_PACKET) {
					mtu_not_ok(ws);
					tls_send(ts, ws->buffer, 1);
					ret = 1;
				} else if (ws->config->try_mtu != 0 && ret > 0 && ws->dpd_mtu_trial > 0) {
					mtu_ok(ws);
				}

				oclog(ws, LOG_DEBUG, "received DTLS DPD; sent response (%d bytes)", ret);
			}

			if (ret < 0) {
				oclog(ws, LOG_ERR, "could not send TLS data: %s", gnutls_strerror(ret));
				return -1;
			}
			break;
		case AC_PKT_DISCONN:
			oclog(ws, LOG_INFO, "received BYE packet; exiting");
			exit_worker(ws);
			break;
		case AC_PKT_DATA:
			oclog(ws, LOG_DEBUG, "writing %d byte(s) to TUN", (int)buf_size);
			ret = tun_write(ws->tun_fd, buf, buf_size);
			if (ret == -1) {
				e = errno;
				oclog(ws, LOG_ERR, "could not write data to tun: %s", strerror(e));
				return -1;
			}

			break;
		default:
			oclog(ws, LOG_DEBUG, "received unknown packet %u", (unsigned)head);
	}
	
	return head;
}

static int parse_cstp_data(struct worker_st* ws, 
				uint8_t* buf, size_t buf_size)
{
int pktlen;

	if (buf_size < 8) {
		oclog(ws, LOG_INFO, "can't read CSTP header (only %d bytes are available)\n", (int)buf_size);
		return -1;
	}

	if (buf[0] != 'S' || buf[1] != 'T' ||
	    buf[2] != 'F' || buf[3] != 1 || buf[7]) {
		oclog(ws, LOG_INFO, "can't recognise CSTP header\n");
		return -1;
	}

	pktlen = (buf[4] << 8) + buf[5];
	if (buf_size != 8 + pktlen) {
		oclog(ws, LOG_INFO, "unexpected CSTP length\n");
		return -1;
	}

	return parse_data(ws, ws->session, buf[6], buf+8, pktlen);
}

static int parse_dtls_data(struct worker_st* ws, 
				uint8_t* buf, size_t buf_size)
{
	if (buf_size < 1) {
		oclog(ws, LOG_INFO, "can't read DTLS header (only %d bytes are available)\n", (int)buf_size);
		return -1;
	}

	return parse_data(ws, ws->dtls_session, buf[0], buf+1, buf_size-1);
}
