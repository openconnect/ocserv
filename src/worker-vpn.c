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
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <system.h>
#include <time.h>
#include <common.h>

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
#define PERIODIC_CHECK_TIME 30

/* The number of DPD packets a client skips before he's kicked */
#define DPD_TRIES 2
#define DPD_MAX_TRIES 3

/* HTTP requests prior to disconnection */
#define MAX_HTTP_REQUESTS 16

static int terminate = 0;
static int parse_cstp_data(struct worker_st* ws, uint8_t* buf, size_t buf_size, time_t);
static int parse_dtls_data(struct worker_st* ws, 
				uint8_t* buf, size_t buf_size, time_t);

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

typedef int (*url_handler_fn)(worker_st*, unsigned http_ver);
struct known_urls_st {
	const char* url;
	unsigned url_size;
	unsigned partial_match;
	url_handler_fn get_handler;
	url_handler_fn post_handler;
};


#define LL(x,y,z) {x, sizeof(x)-1, 0, y, z}
#define LL_DIR(x,y,z) {x, sizeof(x)-1, 1, y, z}
const static struct known_urls_st known_urls[] = {
		LL("/", get_auth_handler, post_auth_handler),
		LL("/auth", get_auth_handler, post_auth_handler),
#ifdef ANYCONNECT_CLIENT_COMPAT
		LL("/1/index.html", get_empty_handler, NULL),
		LL("/2/index.html", get_empty_handler, NULL),
		LL("/2/Linux", get_empty_handler, NULL),
		LL("/2/VPNManifest.xml", get_string_handler, NULL),
		LL("/2/binaries/update.txt", get_string_handler, NULL),
		LL("/profiles", get_config_handler, NULL),
		LL("/+CSCOT+/translation-table", get_string_handler, NULL),
#endif
		{NULL, 0, 0, NULL, NULL}
};

static url_handler_fn get_url_handler(const char* url)
{
const struct known_urls_st *p;
unsigned len = strlen(url);

	p = known_urls;
	do {
		if (p->url != NULL) {
		        if ((len == p->url_size && strcmp(p->url, url)==0) ||
				(len >= p->url_size && strncmp(p->url, url, p->url_size)==0 && 
				(p->partial_match != 0 || url[p->url_size] == '/' || url[p->url_size] == '?')))
				return p->get_handler;
		}
		p++;
	} while(p->url != NULL);
	
	return NULL;
}

static url_handler_fn post_url_handler(const char* url)
{
const struct known_urls_st *p;

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
	struct http_req_st *req = &ws->req;
	
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
#define STR_HDR_CS "X-DTLS-CipherSuite"
#define STR_HDR_DMTU "X-DTLS-MTU"
#define STR_HDR_CMTU "X-CSTP-MTU"
#define STR_HDR_ATYPE "X-CSTP-Address-Type"
#define STR_HDR_HOST "X-CSTP-Hostname"

static void value_check(struct worker_st *ws, struct http_req_st *req)
{
unsigned length;
size_t nlen;
uint8_t* p;
char * token;
char * str;

	if (req->value.length <= 0)
		return;

	oclog(ws, LOG_DEBUG, "HTTP: %.*s: %.*s", (int)req->header.length, req->header.data,  
		(int)req->value.length, req->value.data);

	switch (req->next_header) {
		case HEADER_MASTER_SECRET:
			if (req->value.length < TLS_MASTER_SIZE*2) {
				req->master_secret_set = 0;
				return;
			}
			
			length = TLS_MASTER_SIZE*2;

			nlen = sizeof(req->master_secret);
			gnutls_hex2bin((void*)req->value.data, length, req->master_secret, &nlen);

			req->master_secret_set = 1;
			break;
		case HEADER_HOSTNAME:
			if (req->value.length+1 > MAX_HOSTNAME_SIZE) {
				req->hostname[0] = 0;
				return;
			}
			memcpy(req->hostname, req->value.data, req->value.length);
			req->hostname[req->value.length] = 0;
			break;

		case HEADER_DTLS_CIPHERSUITE:
			str = (char*)req->value.data;
			while ((token = strtok(str, ":")) != NULL) {
#if GNUTLS_VERSION_NUMBER >= 0x030201
				if (strcmp(token, "X-ESTREAM-SALSA20-UMAC96") == 0) {
				        req->selected_ciphersuite = "X-ESTREAM-SALSA20-UMAC96";
				        req->gnutls_ciphersuite = "NONE:+VERS-DTLS0.9:+COMP-NULL:+ESTREAM-SALSA20-256:+UMAC-96:+RSA:%COMPAT:%DISABLE_SAFE_RENEGOTIATION";
				        req->gnutls_cipher = GNUTLS_CIPHER_ESTREAM_SALSA20_256;
				        req->gnutls_mac = GNUTLS_MAC_UMAC_96;
				        break;
				} else if (strcmp(token, "X-SALSA20-UMAC96") == 0) {
				        req->gnutls_ciphersuite = "NONE:+VERS-DTLS0.9:+COMP-NULL:+SALSA20-256:+UMAC-96:+RSA:%COMPAT:%DISABLE_SAFE_RENEGOTIATION";
				        req->selected_ciphersuite = "X-SALSA20-UMAC96";
				        req->gnutls_cipher = GNUTLS_CIPHER_SALSA20_256;
				        req->gnutls_mac = GNUTLS_MAC_UMAC_96;
				        break;
	                        } else
#endif
				if (strcmp(token, "AES128-SHA") == 0) {
				        req->gnutls_ciphersuite = "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:%COMPAT:%DISABLE_SAFE_RENEGOTIATION";
				        req->selected_ciphersuite = "AES128-SHA";
				        req->gnutls_cipher = GNUTLS_CIPHER_AES_128_CBC;
				        req->gnutls_mac = GNUTLS_MAC_SHA1;
				        break;
				} else if (strcmp(token, "DES-CBC3-SHA") == 0) {
				        req->gnutls_ciphersuite = "NONE:+VERS-DTLS0.9:+COMP-NULL:+3DES-CBC:+SHA1:+RSA:%COMPAT:%DISABLE_SAFE_RENEGOTIATION";
				        req->selected_ciphersuite = "DES-CBC3-SHA";
				        req->gnutls_cipher = GNUTLS_CIPHER_3DES_CBC;
				        req->gnutls_mac = GNUTLS_MAC_SHA1;
				        break;
	                        }
				str = NULL;
			}

			break;

		case HEADER_CSTP_MTU:
			req->cstp_mtu = atoi((char*)req->value.data);
			break;
		case HEADER_CSTP_ATYPE:
			if (memmem(req->value.data, req->value.length, "IPv4", 4) == NULL)
				req->no_ipv4 = 1;
			if (memmem(req->value.data, req->value.length, "IPv6", 4) == NULL)
				req->no_ipv6 = 1;
			break;
		case HEADER_DTLS_MTU:
			req->dtls_mtu = atoi((char*)req->value.data);
			break;
		case HEADER_COOKIE:
			length = req->value.length;
			p = memmem(req->value.data, length, "webvpn=", 7);
			if (p == NULL || length <= 7) {
				req->cookie_set = 0;
				return;
			}
			p += 7;
			length -= 7;
				
			if (length < COOKIE_SIZE*2) {
				req->cookie_set = 0;
				return;
			}
			length = COOKIE_SIZE*2;
			nlen = sizeof(req->cookie);
			gnutls_hex2bin((void*)p, length, req->cookie, &nlen);

			if (nlen < COOKIE_SIZE) {
				req->cookie_set = 0;
				return;
			}
			req->cookie_set = 1;
			break;
	}
}

int header_field_cb(http_parser* parser, const char *at, size_t length)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;
	int ret;

	if (req->header_state != HTTP_HEADER_RECV) {
		/* handle value */
		if (req->header_state == HTTP_HEADER_VALUE_RECV)
			value_check(ws, req);
		req->header_state = HTTP_HEADER_RECV;
		str_reset(&req->header);
	}

	ret = str_append_data(&req->header, at, length);
	if (ret < 0)
		return ret;

	return 0;
}

static void header_check(struct http_req_st *req)
{
	if (req->header.length == sizeof(STR_HDR_COOKIE)-1 && 
	        strncmp((char*)req->header.data, STR_HDR_COOKIE, req->header.length) == 0) {
		req->next_header = HEADER_COOKIE;
	} else if (req->header.length == sizeof(STR_HDR_MS)-1 && 
	        strncmp((char*)req->header.data, STR_HDR_MS, req->header.length) == 0) {
		req->next_header = HEADER_MASTER_SECRET;
	} else if (req->header.length == sizeof(STR_HDR_DMTU)-1 && 
	        strncmp((char*)req->header.data, STR_HDR_DMTU, req->header.length) == 0) {
		req->next_header = HEADER_DTLS_MTU;
	} else if (req->header.length == sizeof(STR_HDR_CMTU)-1 && 
	        strncmp((char*)req->header.data, STR_HDR_CMTU, req->header.length) == 0) {
		req->next_header = HEADER_CSTP_MTU;
	} else if (req->header.length == sizeof(STR_HDR_HOST)-1 && 
	        strncmp((char*)req->header.data, STR_HDR_HOST, req->header.length) == 0) {
		req->next_header = HEADER_HOSTNAME;
	} else if (req->header.length == sizeof(STR_HDR_CS)-1 && 
	        strncmp((char*)req->header.data, STR_HDR_CS, req->header.length) == 0) {
		req->next_header = HEADER_DTLS_CIPHERSUITE;
	} else if (req->header.length == sizeof(STR_HDR_ATYPE)-1 && 
	        strncmp((char*)req->header.data, STR_HDR_ATYPE, req->header.length) == 0) {
		req->next_header = HEADER_CSTP_ATYPE;
	} else {
		req->next_header = 0;
	}
}

int header_value_cb(http_parser* parser, const char *at, size_t length)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;
	int ret;

	if (req->header_state != HTTP_HEADER_VALUE_RECV) {
		/* handle header */
		header_check(req);
		req->header_state = HTTP_HEADER_VALUE_RECV;
		str_reset(&req->value);
	}

	ret = str_append_data(&req->value, at, length);
	if (ret < 0)
		return ret;

	return 0;
}

int header_complete_cb(http_parser* parser)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;

	/* handle header value */
	value_check(ws, req);

	req->headers_complete = 1;
	return 0;
}

int message_complete_cb(http_parser* parser)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;

	req->message_complete = 1;
	return 0;
}

int body_cb(http_parser* parser, const char *at, size_t length)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;
	char* tmp;
	
	tmp = realloc(req->body, req->body_length+length+1);
	if (tmp == NULL)
		return 1;
		
	memcpy(&tmp[req->body_length], at, length);
	req->body_length += length;
	tmp[req->body_length] = 0;

	req->body = tmp;
	return 0;
}

static int setup_dtls_connection(struct worker_st *ws)
{
int ret;
gnutls_session_t session;
gnutls_datum_t master = { ws->master_secret, sizeof(ws->master_secret) };
gnutls_datum_t sid = { ws->session_id, sizeof(ws->session_id) };

        if (ws->req.gnutls_ciphersuite == NULL) {
		oclog(ws, LOG_ERR, "no DTLS ciphersuite negotiated");
		return -1;
        }

	oclog(ws, LOG_INFO, "setting up DTLS connection");
	/* DTLS cookie verified.
	 * Initialize session.
	 */
	ret = gnutls_init(&session, GNUTLS_SERVER|GNUTLS_DATAGRAM);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not initialize TLS session: %s", gnutls_strerror(ret));
		return -1;
	}

	ret = gnutls_priority_set_direct(session, ws->req.gnutls_ciphersuite, NULL);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "could not set TLS priority: %s", gnutls_strerror(ret));
		goto fail;
	}

	ret = gnutls_session_set_premaster(session, GNUTLS_SERVER,
		GNUTLS_DTLS0_9, GNUTLS_KX_RSA, ws->req.gnutls_cipher,
		ws->req.gnutls_mac, GNUTLS_COMP_NULL, &master, &sid);
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

	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	ws->udp_state = UP_HANDSHAKE;

	ws->dtls_session = session;

	return 0;
fail:
	gnutls_deinit(session);
	return -1;
}

static void http_req_init(worker_st * ws)
{
	str_init(&ws->req.header);
	str_init(&ws->req.value);
}

static void http_req_reset(worker_st * ws)
{
	ws->req.headers_complete = 0;
	ws->req.message_complete = 0;
	ws->req.body_length = 0;
	ws->req.url[0] = 0;
	
	ws->req.header_state = HTTP_HEADER_INIT;
	str_reset(&ws->req.header);
	str_reset(&ws->req.value);
}

static void http_req_deinit(worker_st * ws)
{
	http_req_reset(ws);
	str_clear(&ws->req.header);
	str_clear(&ws->req.value);
	free(ws->req.body);
	ws->req.body = NULL;
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

	ocsignal(SIGTERM, handle_term);
	ocsignal(SIGINT, handle_term);
	ocsignal(SIGHUP, SIG_IGN);
	ocsignal(SIGALRM, handle_alarm);

	if (ws->config->auth_timeout)
		alarm(ws->config->auth_timeout);
		
	ret = disable_system_calls(ws);
	if (ret < 0) {
		oclog(ws, LOG_INFO, "could not disable system calls, kernel might not support seccomp");
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

	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	GNUTLS_S_FATAL_ERR(session, ret);

	oclog(ws, LOG_DEBUG, "TLS handshake completed");

	memset(&settings, 0, sizeof(settings));

	settings.on_url = url_cb;
	settings.on_header_field = header_field_cb;
	settings.on_header_value = header_value_cb;
	settings.on_headers_complete = header_complete_cb;
	settings.on_message_complete = message_complete_cb;
	settings.on_body = body_cb;
	http_req_init(ws);

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
		nrecvd = tls_recv(session, buf, sizeof(buf));
		if (nrecvd <= 0) {
			if (nrecvd == 0)
			        goto finish;
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
		oclog(ws, LOG_DEBUG, "HTTP GET %s", ws->req.url); 
		fn = get_url_handler(ws->req.url);
		if (fn == NULL) {
			oclog(ws, LOG_INFO, "unexpected URL %s", ws->req.url);
			tls_puts(session, "HTTP/1.1 404 Not found\r\n\r\n");
			goto finish;
                }		
		ret = fn(ws, parser.http_minor);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else if (parser.method == HTTP_POST) {
		/* continue reading */
		oclog(ws, LOG_DEBUG, "HTTP POST %s", ws->req.url); 
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
			tls_puts(session, "HTTP/1.1 404 Not found\r\n\r\n");
			goto finish;
		}

		ret = fn(ws, parser.http_minor);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else if (parser.method == HTTP_CONNECT) {
		oclog(ws, LOG_DEBUG, "HTTP CONNECT %s", ws->req.url); 
		ret = connect_handler(ws);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else {
		oclog(ws, LOG_INFO, "unexpected HTTP method %s", http_method_str(parser.method)); 
		tls_printf(session, "HTTP/1.%u 404 Nah, go away\r\n\r\n", parser.http_minor);
	}

finish:
	tls_close(session);
}

static
void mtu_set(worker_st* ws, unsigned mtu)
{
	ws->conn_mtu = mtu;
	
	if (ws->dtls_session)
		gnutls_dtls_set_data_mtu (ws->dtls_session, mtu);
	send_tun_mtu(ws, mtu - 1); /* for DTLS header */
	oclog(ws, LOG_INFO, "setting MTU to %u", ws->conn_mtu);
}

/* sets the current value of mtu as bad,
 * and returns an estimation of good.
 *
 * Returns -1 on failure.
 */
static
int mtu_not_ok(worker_st* ws)
{
	ws->last_bad_mtu = ws->conn_mtu;

	if (ws->last_good_mtu >= ws->conn_mtu) {
		ws->last_good_mtu = (2*(ws->conn_mtu))/3;
	
		if (ws->last_good_mtu < 128) {
			oclog(ws, LOG_INFO, "could not calculate a valid MTU. Disabling DTLS.");
			ws->udp_state = UP_DISABLED;
			return -1;
		}
	}

	mtu_set(ws, ws->last_good_mtu);
	oclog(ws, LOG_INFO, "MTU %u is too large, switching to %u", ws->last_bad_mtu, ws->conn_mtu);

	return 0;
}

static void mtu_discovery_init(worker_st *ws, unsigned mtu)
{
	ws->last_good_mtu = mtu;
	ws->last_bad_mtu = mtu;
}

static
void mtu_ok(worker_st* ws)
{
unsigned int c;

	if (ws->last_bad_mtu == (ws->conn_mtu)+1 ||
		ws->last_bad_mtu == (ws->conn_mtu))
		return;
	
	ws->last_good_mtu = ws->conn_mtu;
	c = (ws->conn_mtu + ws->last_bad_mtu)/2;

	mtu_set(ws, c);
	return;
}

static 
int periodic_check(worker_st *ws, unsigned mtu_overhead, time_t now)
{
socklen_t sl;
int max, e, ret;

	if (now - ws->last_periodic_check < PERIODIC_CHECK_TIME)
		return 0;

	/* check DPD. Otherwise exit */
	if (ws->udp_state == UP_ACTIVE && now-ws->last_msg_udp > DPD_TRIES*ws->config->dpd) {
		oclog(ws, LOG_ERR, "have not received UDP any message or DPD for long (%d secs)", (int)(now-ws->last_msg_udp));
				
		ws->buffer[0] = AC_PKT_DPD_OUT;
		tls_send(ws->dtls_session, ws->buffer, 1);
				
		if (now-ws->last_msg_udp > DPD_MAX_TRIES*ws->config->dpd) {
			oclog(ws, LOG_ERR, "have not received UDP message or DPD for very long; disabling UDP port");
			ws->udp_state = UP_INACTIVE;
		}
	}
	if (now-ws->last_msg_tcp > DPD_TRIES*ws->config->dpd) {
		oclog(ws, LOG_ERR, "have not received TCP DPD for long (%d secs)", (int)(now-ws->last_msg_tcp));
		ws->buffer[0] = AC_PKT_DPD_OUT;
		tls_send(ws->session, ws->buffer, 1);

		if (now-ws->last_msg_tcp > DPD_MAX_TRIES*ws->config->dpd) {
			oclog(ws, LOG_ERR, "have not received TCP DPD for very long; tearing down connection");
			return -1;
		}
	}

	sl = sizeof(max);
	ret = getsockopt(ws->conn_fd, IPPROTO_TCP, TCP_MAXSEG, &max, &sl);
	if (ret == -1) {
		e = errno;
		oclog(ws, LOG_INFO, "error in getting TCP_MAXSEG: %s", strerror(e));
	} else {
		max -= 13;
		oclog(ws, LOG_DEBUG, "TCP MSS is %u", max);
		if (max > 0 && max-mtu_overhead < ws->conn_mtu) {
			oclog(ws, LOG_INFO, "reducing MTU due to TCP MSS to %u", max-mtu_overhead);
			mtu_set(ws, MIN(ws->conn_mtu, max-mtu_overhead));
		}
	}


	ws->last_periodic_check = now;
	
	return 0;
}

#define CSTP_DTLS_OVERHEAD 1
#define CSTP_OVERHEAD 8

#define SEND_ERR(x) if (x<0) goto send_error
static int connect_handler(worker_st *ws)
{
struct http_req_st *req = &ws->req;
fd_set rfds;
int l, e, max, ret, overhead;
struct vpn_st vinfo;
unsigned tls_retry;
char *p;
struct timeval tv;
unsigned tls_pending, dtls_pending = 0, i;
time_t udp_recv_time = 0, now;
unsigned mtu_overhead = 0;
socklen_t sl;

	ws->buffer_size = 16*1024;
	ws->buffer = malloc(ws->buffer_size);
	if (ws->buffer == NULL) {
		oclog(ws, LOG_INFO, "memory error");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		tls_close(ws->session);
		exit_worker(ws);
	}

        if (ws->auth_state != S_AUTH_COMPLETE && req->cookie_set == 0) {
		oclog(ws, LOG_INFO, "connect request without authentication");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
		exit_worker(ws);
	}

	if (ws->auth_state != S_AUTH_COMPLETE) {
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
	
	/* Connected. Turn of the alarm */
	if (ws->config->auth_timeout)
		alarm(0);
	http_req_deinit(ws);

	tls_cork(ws->session);
	ret = tls_puts(ws->session, "HTTP/1.1 200 CONNECTED\r\n");
	SEND_ERR(ret);

	ret = tls_puts(ws->session, "X-CSTP-Version: 1\r\n");
	SEND_ERR(ret);

	ret = tls_printf(ws->session, "X-CSTP-DPD: %u\r\n", ws->config->dpd);
	SEND_ERR(ret);

	if (ws->config->default_domain) {
        	ret = tls_printf(ws->session, "X-CSTP-Default-Domain: %s\r\n", ws->config->default_domain);
        	SEND_ERR(ret);
        }

	ws->udp_state = UP_DISABLED;
	if (req->master_secret_set != 0) {
		memcpy(ws->master_secret, req->master_secret, TLS_MASTER_SIZE);
		ws->udp_state = UP_WAIT_FD;
	} else {
		oclog(ws, LOG_DEBUG, "disabling UDP (DTLS) connection");
	}

	if (vinfo.ipv4 && req->no_ipv4 == 0) {
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
		if (vinfo.ipv4_nbns) {
			ret = tls_printf(ws->session, "X-CSTP-NBNS: %s\r\n", vinfo.ipv4_nbns);
			SEND_ERR(ret);
		}
	}
	
	if (vinfo.ipv6 && req->no_ipv6 == 0) {
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
		if (vinfo.ipv6_nbns) {
			ret = tls_printf(ws->session, "X-CSTP-NBNS: %s\r\n", vinfo.ipv6_nbns);
			SEND_ERR(ret);
		}
	}

	for (i=0;i<vinfo.routes_size;i++) {
		if (req->no_ipv6 != 0 && strchr(vinfo.routes[i], ':') != 0)
			continue;
		if (req->no_ipv4 != 0 && strchr(vinfo.routes[i], '.') != 0)
			continue;
		oclog(ws, LOG_DEBUG, "adding route %s", vinfo.routes[i]);
		ret = tls_printf(ws->session,
			"X-CSTP-Split-Include: %s\r\n", vinfo.routes[i]);
		SEND_ERR(ret);
	}
	ret = tls_printf(ws->session, "X-CSTP-Keepalive: %u\r\n", ws->config->keepalive);
	SEND_ERR(ret);

	ret = tls_puts(ws->session, "X-CSTP-Smartcard-Removal-Disconnect: true\r\n");
	SEND_ERR(ret);

	ret = tls_printf(ws->session, "X-CSTP-Rekey-Time: %u\r\n", (unsigned)(2*ws->config->cookie_validity)/3);
	SEND_ERR(ret);
	ret = tls_puts(ws->session, "X-CSTP-Rekey-Method: new-tunnel\r\n");
	SEND_ERR(ret);

	ret = tls_puts(ws->session, "X-CSTP-Session-Timeout: none\r\n"
		"X-CSTP-Idle-Timeout: none\r\n"
		"X-CSTP-Disconnected-Timeout: none\r\n"
		"X-CSTP-Keep: true\r\n"
		"X-CSTP-TCP-Keepalive: true\r\n"
		"X-CSTP-Tunnel-All-DNS: false\r\n"
		);
	SEND_ERR(ret);

	mtu_overhead = CSTP_OVERHEAD;
	ws->conn_mtu = vinfo.mtu - mtu_overhead;
	if (req->cstp_mtu > 0) {
		ws->conn_mtu = MIN(ws->conn_mtu, req->cstp_mtu);
		oclog(ws, LOG_DEBUG, "peer CSTP MTU is %u", req->cstp_mtu);
	}

	sl = sizeof(max);
	ret = getsockopt(ws->conn_fd, IPPROTO_TCP, TCP_MAXSEG, &max, &sl);
	if (ret == -1) {
		e = errno;
		oclog(ws, LOG_INFO, "error in getting TCP_MAXSEG: %s", strerror(e));
	} else {
		max -= 13;
		oclog(ws, LOG_INFO, "TCP MSS is %u", max);
		if (max > 0 && max-mtu_overhead < ws->conn_mtu) {
			oclog(ws, LOG_DEBUG, "reducing MTU due to TCP MSS to %u", max-mtu_overhead);
		}
		ws->conn_mtu = MIN(ws->conn_mtu, max-mtu_overhead);
	}

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

		oclog(ws, LOG_INFO, "DTLS ciphersuite: %s", ws->req.selected_ciphersuite);
		ret = tls_printf(ws->session, "X-DTLS-CipherSuite: %s\r\n", ws->req.selected_ciphersuite);
		SEND_ERR(ret);

		/* assume that if IPv6 is used over TCP then the same would be used over UDP */
		if (ws->proto == AF_INET)
			mtu_overhead = 20+CSTP_DTLS_OVERHEAD; /* ip */
		else
			mtu_overhead = 40+CSTP_DTLS_OVERHEAD; /* ipv6 */
		mtu_overhead += 8; /* udp */
		ws->conn_mtu = MIN(ws->conn_mtu, vinfo.mtu - mtu_overhead);

		if (req->dtls_mtu > 0) {
			ws->conn_mtu = MIN(req->dtls_mtu, ws->conn_mtu);
			oclog(ws, LOG_INFO, "reducing DTLS MTU to peer's DTLS MTU (%u)", req->dtls_mtu);
		}

		overhead = tls_get_overhead(GNUTLS_DTLS0_9, ws->req.gnutls_cipher, ws->req.gnutls_mac);
		tls_printf(ws->session, "X-DTLS-MTU: %u\r\n", ws->conn_mtu-overhead);
	}
	
	if (ws->buffer_size <= ws->conn_mtu+mtu_overhead) {
		oclog(ws, LOG_WARNING, "buffer size is smaller than MTU (%u < %u); adjusting", ws->buffer_size, ws->conn_mtu);
		ws->buffer_size = ws->conn_mtu+mtu_overhead;
		ws->buffer = realloc(ws->buffer, ws->buffer_size);
		if (ws->buffer == NULL)
			goto exit;
	}

	overhead = tls_get_overhead(gnutls_protocol_get_version(ws->session), gnutls_cipher_get(ws->session), gnutls_mac_get(ws->session));
	ret = tls_printf(ws->session, "X-CSTP-MTU: %u\r\n", ws->conn_mtu-overhead);
	SEND_ERR(ret);

	oclog(ws, LOG_INFO, "selected MTU is %u", ws->conn_mtu);
	send_tun_mtu(ws, ws->conn_mtu);

	if (ws->config->banner) {
		ret = tls_printf(ws->session, "X-CSTP-Banner: %s\r\n", ws->config->banner);
		SEND_ERR(ret);
	}

	ret = tls_puts(ws->session, "\r\n");
	SEND_ERR(ret);

	ret = tls_uncork(ws->session);
	SEND_ERR(ret);

	/* start dead peer detection */
	ws->last_msg_tcp = ws->last_msg_udp = time(0);

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
		}
		now = time(0);
		if (periodic_check(ws, mtu_overhead, now) < 0)
			goto exit;
		
		if (FD_ISSET(ws->tun_fd, &rfds)) {
			l = read(ws->tun_fd, ws->buffer + 8, ws->conn_mtu - 1);
			if (l < 0) {
				e = errno;
				
				if (e != EAGAIN && e != EINTR) {
					oclog(ws, LOG_ERR, "received corrupt data from tun (%d): %s", l, strerror(e));
					goto exit;
				}
				continue;
			}
			
			if (l == 0) {
				oclog(ws, LOG_INFO, "TUN device returned zero");
				continue;
			}

			tls_retry = 0;
			oclog(ws, LOG_DEBUG, "sending %d byte(s)\n", l);
			if (ws->udp_state == UP_ACTIVE) {
				ws->buffer[7] = AC_PKT_DATA;

				ret = tls_send(ws->dtls_session, ws->buffer + 7, l + 1);
				GNUTLS_FATAL_ERR(ret);

				if (ret == GNUTLS_E_LARGE_PACKET) {
					mtu_not_ok(ws);

					oclog(ws, LOG_DEBUG, "retrying (TLS) %d\n", l);
					tls_retry = 1;
				} else if (ret >= ws->conn_mtu && ws->config->try_mtu != 0) {
					mtu_ok(ws);
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

				ret = parse_cstp_data(ws, ws->buffer, l, now);
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

						ret = parse_dtls_data(ws, ws->buffer, l, now);
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
					
					gnutls_dtls_set_mtu (ws->dtls_session, ws->conn_mtu);
					mtu_discovery_init(ws, ws->conn_mtu);

					break;
				case UP_HANDSHAKE:
hsk_restart:
					ret = gnutls_handshake(ws->dtls_session);
					if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
						if (ret == GNUTLS_E_FATAL_ALERT_RECEIVED)
							oclog(ws, LOG_ERR, "error in DTLS handshake: %s: %s\n", gnutls_strerror(ret), gnutls_alert_get_name(gnutls_alert_get(ws->dtls_session)));
						else
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
						unsigned mtu = gnutls_dtls_get_data_mtu(ws->dtls_session);
						ws->udp_state = UP_ACTIVE;
						mtu_discovery_init(ws, mtu);
						mtu_set(ws, mtu);
						oclog(ws, LOG_INFO, "DTLS handshake completed (MTU: %u)\n", ws->conn_mtu);
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
			uint8_t* buf, size_t buf_size, time_t now)
{
int ret, e;

	switch (head) {
		case AC_PKT_DPD_RESP:
			oclog(ws, LOG_DEBUG, "received DPD response");
			break;
		case AC_PKT_KEEPALIVE:
			oclog(ws, LOG_DEBUG, "received keepalive");
			break;
		case AC_PKT_DPD_OUT:
			if (ws->session == ts) {
				ret = tls_send(ts, "STF\x01\x00\x00\x04\x00", 8);

				oclog(ws, LOG_DEBUG, "received TLS DPD; sent response (%d bytes)", ret);
			} else {
				/* Use DPD for MTU discovery in DTLS */
				ws->buffer[0] = AC_PKT_DPD_RESP;
				
				ret = tls_send(ts, ws->buffer, 1);
				if (ret == GNUTLS_E_LARGE_PACKET) {
					mtu_not_ok(ws);
					ret = tls_send(ts, ws->buffer, 1);
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
			ret = force_write(ws->tun_fd, buf, buf_size);
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
				uint8_t* buf, size_t buf_size, time_t now)
{
int pktlen, ret;

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

	ret = parse_data(ws, ws->session, buf[6], buf+8, pktlen, now);
	/* whatever we received treat it as DPD response.
	 * it indicates that the channel is alive */
	ws->last_msg_tcp = now;
	
	return ret;
}

static int parse_dtls_data(struct worker_st* ws, 
				uint8_t* buf, size_t buf_size, time_t now)
{
int ret;

	if (buf_size < 1) {
		oclog(ws, LOG_INFO, "can't read DTLS header (only %d bytes are available)\n", (int)buf_size);
		return -1;
	}

	ret = parse_data(ws, ws->dtls_session, buf[0], buf+1, buf_size-1, now);
	ws->last_msg_udp = now;
	return ret;
}
