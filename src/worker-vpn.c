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
#include <base64.h>
#include <c-strcase.h>
#include <c-ctype.h>
#include <worker-bandwidth.h>

#include <vpn.h>
#include "ipc.pb-c.h"
#include <cookies.h>
#include <worker.h>
#include <tlslib.h>

#include <http_parser.h>

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
static void exit_worker(worker_st * ws);

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

static int connect_handler(worker_st * ws);

typedef int (*url_handler_fn) (worker_st *, unsigned http_ver);
struct known_urls_st {
	const char *url;
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
	LL("/1/Linux", get_empty_handler, NULL),
	LL("/1/Linux_64", get_empty_handler, NULL),
	LL("/1/Windows", get_empty_handler, NULL),
	LL("/1/Darwin_i386", get_empty_handler, NULL),
	LL("/1/binaries/vpndownloader.sh", get_dl_handler, NULL),
	LL("/1/VPNManifest.xml", get_string_handler, NULL),
	LL("/1/binaries/update.txt", get_string_handler, NULL),

	LL_DIR("/profiles", get_config_handler, NULL),
	LL("/+CSCOT+/", get_string_handler, NULL),
	LL("/logout", get_empty_handler, NULL),
#endif
	{NULL, 0, 0, NULL, NULL}
};

static url_handler_fn get_url_handler(const char *url)
{
	const struct known_urls_st *p;
	unsigned len = strlen(url);

	p = known_urls;
	do {
		if (p->url != NULL) {
			if ((len == p->url_size && strcmp(p->url, url) == 0) ||
			    (len >= p->url_size
			     && strncmp(p->url, url, p->url_size) == 0
			     && (p->partial_match != 0
				 || url[p->url_size] == '/'
				 || url[p->url_size] == '?')))
				return p->get_handler;
		}
		p++;
	} while (p->url != NULL);

	return NULL;
}

static url_handler_fn post_url_handler(const char *url)
{
	const struct known_urls_st *p;

	p = known_urls;
	do {
		if (p->url != NULL && strcmp(p->url, url) == 0)
			return p->post_handler;
		p++;
	} while (p->url != NULL);

	return NULL;
}

int url_cb(http_parser * parser, const char *at, size_t length)
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

#define CS_AES128_GCM "OC-DTLS1_2-AES128-GCM"
#define CS_AES256_GCM "OC-DTLS1_2-AES256-GCM"

/* Consider switching to gperf when this table grows significantly.
 */
static const dtls_ciphersuite_st ciphersuites[] = {
#if GNUTLS_VERSION_NUMBER >= 0x030207
	{
	 .oc_name = CS_AES128_GCM,
	 .gnutls_name =
	 "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL",
	 .gnutls_version = GNUTLS_DTLS1_2,
	 .gnutls_mac = GNUTLS_MAC_AEAD,
	 .gnutls_cipher = GNUTLS_CIPHER_AES_128_GCM,
	 .server_prio = 90},
	{
	 .oc_name = CS_AES256_GCM,
	 .gnutls_name =
	 "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL",
	 .gnutls_version = GNUTLS_DTLS1_2,
	 .gnutls_mac = GNUTLS_MAC_AEAD,
	 .gnutls_cipher = GNUTLS_CIPHER_AES_256_GCM,
	 .server_prio = 80,
	 },
#endif
	{
	 .oc_name = "AES128-SHA",
	 .gnutls_name =
	 "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:%COMPAT",
	 .gnutls_version = GNUTLS_DTLS0_9,
	 .gnutls_mac = GNUTLS_MAC_SHA1,
	 .gnutls_cipher = GNUTLS_CIPHER_AES_128_CBC,
	 .server_prio = 50,
	 },
	{
	 .oc_name = "DES-CBC3-SHA",
	 .gnutls_name =
	 "NONE:+VERS-DTLS0.9:+COMP-NULL:+3DES-CBC:+SHA1:+RSA:%COMPAT",
	 .gnutls_version = GNUTLS_DTLS0_9,
	 .gnutls_mac = GNUTLS_MAC_SHA1,
	 .gnutls_cipher = GNUTLS_CIPHER_3DES_CBC,
	 .server_prio = 1,
	 },
};

static void value_check(struct worker_st *ws, struct http_req_st *req)
{
	unsigned tmplen, i;
	int ret;
	size_t nlen, value_length;
	char *token, *value;
	char *str, *p;
	const dtls_ciphersuite_st *cand = NULL;
	gnutls_cipher_algorithm_t want_cipher;
	gnutls_mac_algorithm_t want_mac;

	if (req->value.length <= 0)
		return;

	oclog(ws, LOG_HTTP_DEBUG, "HTTP: %.*s: %.*s", (int)req->header.length,
	      req->header.data, (int)req->value.length, req->value.data);

	value = talloc_size(ws, req->value.length + 1);
	if (value == NULL)
		return;

	/* make sure the value is null terminated */
	value_length = req->value.length;
	memcpy(value, req->value.data, value_length);
	value[value_length] = 0;

	switch (req->next_header) {
	case HEADER_MASTER_SECRET:
		if (value_length < TLS_MASTER_SIZE * 2) {
			req->master_secret_set = 0;
			goto cleanup;
		}

		tmplen = TLS_MASTER_SIZE * 2;

		nlen = sizeof(req->master_secret);
		gnutls_hex2bin((void *)value, tmplen,
			       req->master_secret, &nlen);

		req->master_secret_set = 1;
		break;
	case HEADER_HOSTNAME:
		if (value_length + 1 > MAX_HOSTNAME_SIZE) {
			req->hostname[0] = 0;
			goto cleanup;
		}
		memcpy(req->hostname, value, value_length);
		req->hostname[value_length] = 0;
		break;
	case HEADER_DEVICE_TYPE:
		req->is_mobile = 1;
		break;
	case HEADER_USER_AGENT:
		if (value_length + 1 > MAX_AGENT_NAME) {
			memcpy(req->user_agent, value, MAX_AGENT_NAME-1);
			req->user_agent[MAX_AGENT_NAME-1] = 0;
		} else {
			memcpy(req->user_agent, value, value_length);
			req->user_agent[value_length] = 0;
		}

		oclog(ws, LOG_DEBUG,
		      "User-agent: '%s'", req->user_agent);

		if (strncasecmp(req->user_agent, "Open Any", 8) == 0) {
			if (strncmp(req->user_agent, "Open AnyConnect VPN Agent v3", 28) == 0)
				req->user_agent_type = AGENT_OPENCONNECT_V3;
			else
				req->user_agent_type = AGENT_OPENCONNECT;
		}
		break;

	case HEADER_DTLS_CIPHERSUITE:
		if (ws->session != NULL) {
			want_mac = gnutls_mac_get(ws->session);
			want_cipher = gnutls_cipher_get(ws->session);
		} else {
			want_mac = -1;
			want_cipher = -1;
		}

		req->selected_ciphersuite = NULL;

		str = (char *)value;
		while ((token = strtok(str, ":")) != NULL) {
			for (i = 0;
			     i < sizeof(ciphersuites) / sizeof(ciphersuites[0]);
			     i++) {
				if (strcmp(token, ciphersuites[i].oc_name) == 0) {
					if (cand == NULL ||
					    cand->server_prio <
					    ciphersuites[i].server_prio) {
						cand =
						    &ciphersuites[i];

						/* if our candidate matches the TLS session
						 * ciphersuite, we are finished */
						if (want_cipher != -1) {
							if (want_cipher == cand->gnutls_cipher &&
							    want_mac == cand->gnutls_mac)
							    break;
						}
					}
				}
			}
			str = NULL;
		}
	        req->selected_ciphersuite = cand;

		break;

	case HEADER_CSTP_BASE_MTU:
		req->base_mtu = atoi((char *)value);
		break;
	case HEADER_CSTP_ATYPE:
		if (memmem(value, value_length, "IPv4", 4) == NULL)
			req->no_ipv4 = 1;
		if (memmem(value, value_length, "IPv6", 4) == NULL)
			req->no_ipv6 = 1;
		break;
	case HEADER_FULL_IPV6:
		if (memmem(value, value_length, "true", 4) != NULL)
			ws->full_ipv6 = 1;
		break;
	case HEADER_COOKIE:

		str = (char *)value;
		while ((token = strtok(str, ";")) != NULL) {
			p = token;
			while (c_isspace(*p)) {
				p++;
			}
			tmplen = strlen(p);

			if (strncmp(p, "webvpn=", 7) == 0) {
				tmplen -= 7;
				p += 7;

				while (tmplen > 1 && c_isspace(p[tmplen - 1])) {
					tmplen--;
				}

				nlen = tmplen;
				ws->cookie = talloc_size(ws, nlen);
				if (ws->cookie == NULL)
					return;

				ret =
				    base64_decode((char *)p, tmplen,
						  (char *)ws->cookie, &nlen);
				if (ret == 0) {
					oclog(ws, LOG_DEBUG,
					      "could not decode cookie: %.*s",
					      tmplen, p);
					ws->cookie_set = 0;
				} else {
					ws->cookie_size = nlen;
					ws->auth_state = S_AUTH_COOKIE;
					ws->cookie_set = 1;
				}
			} else if (strncmp(p, "webvpncontext=", 14) == 0) {
				p += 14;
				tmplen -= 14;

				while (tmplen > 1 && c_isspace(p[tmplen - 1])) {
					tmplen--;
				}

				nlen = sizeof(ws->sid);
				ret =
				    base64_decode((char *)p, tmplen,
						  (char *)ws->sid, &nlen);
				if (ret == 0 || nlen != sizeof(ws->sid)) {
					oclog(ws, LOG_DEBUG,
					      "could not decode sid: %.*s",
					      tmplen, p);
					ws->sid_set = 0;
				} else {
					ws->sid_set = 1;
					oclog(ws, LOG_DEBUG,
					      "received sid: %.*s", tmplen, p);
				}
			}

			str = NULL;
		}
		break;
	}

 cleanup:
	talloc_free(value);
}

int header_field_cb(http_parser * parser, const char *at, size_t length)
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
	/* FIXME: move this mess to a table */
	if (req->header.length == sizeof(STR_HDR_COOKIE) - 1 &&
	    strncmp((char *)req->header.data, STR_HDR_COOKIE,
		    req->header.length) == 0) {
		req->next_header = HEADER_COOKIE;
	} else if (req->header.length == sizeof(STR_HDR_MS) - 1 &&
		   strncmp((char *)req->header.data, STR_HDR_MS,
			   req->header.length) == 0) {
		req->next_header = HEADER_MASTER_SECRET;
	} else if (req->header.length == sizeof(STR_HDR_CMTU) - 1 &&
		   strncmp((char *)req->header.data, STR_HDR_CMTU,
			   req->header.length) == 0) {
		req->next_header = HEADER_CSTP_BASE_MTU;
	} else if (req->header.length == sizeof(STR_HDR_HOST) - 1 &&
		   strncmp((char *)req->header.data, STR_HDR_HOST,
			   req->header.length) == 0) {
		req->next_header = HEADER_HOSTNAME;
	} else if (req->header.length == sizeof(STR_HDR_CS) - 1 &&
		   strncmp((char *)req->header.data, STR_HDR_CS,
			   req->header.length) == 0) {
		req->next_header = HEADER_DTLS_CIPHERSUITE;
	} else if (req->header.length == sizeof(STR_HDR_DEVICE_TYPE) - 1 &&
		   strncmp((char *)req->header.data, STR_HDR_DEVICE_TYPE,
			   req->header.length) == 0) {
		req->next_header = HEADER_DEVICE_TYPE;
	} else if (req->header.length == sizeof(STR_HDR_ATYPE) - 1 &&
		   strncmp((char *)req->header.data, STR_HDR_ATYPE,
			   req->header.length) == 0) {
		req->next_header = HEADER_CSTP_ATYPE;
	} else if (req->header.length == sizeof(STR_HDR_CONNECTION) - 1 &&
		   strncmp((char *)req->header.data, STR_HDR_CONNECTION,
			   req->header.length) == 0) {
		req->next_header = HEADER_CONNECTION;
	} else if (req->header.length == sizeof(STR_HDR_USER_AGENT) - 1 &&
		   strncmp((char *)req->header.data, STR_HDR_USER_AGENT,
			   req->header.length) == 0) {
		req->next_header = HEADER_USER_AGENT;
	} else if (req->header.length == sizeof(STR_HDR_FULL_IPV6) - 1 &&
		   strncmp((char *)req->header.data, STR_HDR_FULL_IPV6,
			   req->header.length) == 0) {
		req->next_header = HEADER_FULL_IPV6;
	} else {
		req->next_header = 0;
	}
}

int header_value_cb(http_parser * parser, const char *at, size_t length)
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

int header_complete_cb(http_parser * parser)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;

	/* handle header value */
	value_check(ws, req);

	req->headers_complete = 1;
	return 0;
}

int message_complete_cb(http_parser * parser)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;

	req->message_complete = 1;
	return 0;
}

int body_cb(http_parser * parser, const char *at, size_t length)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;
	char *tmp;

	tmp = talloc_realloc_size(ws, req->body, req->body_length + length + 1);
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

	gnutls_transport_set_ptr(session,
				 (gnutls_transport_ptr_t) (long)ws->udp_fd);
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
	str_init(&ws->req.header, ws);
	str_init(&ws->req.value, ws);
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
	talloc_free(ws->req.body);
	ws->req.body = NULL;
}

static
void exit_worker(worker_st * ws)
{
	/* send statistics to parent */
	if (ws->auth_state == S_AUTH_COMPLETE) {
		CliStatsMsg msg = CLI_STATS_MSG__INIT;

		msg.bytes_in = ws->tun_bytes_in;
		msg.bytes_out = ws->tun_bytes_out;

		send_msg_to_main(ws, CMD_CLI_STATS, &msg,
				 (pack_size_func)
				 cli_stats_msg__get_packed_size,
				 (pack_func) cli_stats_msg__pack);

		oclog(ws, LOG_DEBUG,
		      "sending stats (in: %lu, out: %lu) to main",
		      (unsigned long)msg.bytes_in,
		      (unsigned long)msg.bytes_out);
	}
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

	if (ws->config->seccomp != 0) {
		ret = disable_system_calls(ws);
		if (ret < 0) {
			oclog(ws, LOG_INFO,
			      "could not disable system calls, kernel might not support seccomp");
		}
	}

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
		fn = get_url_handler(ws->req.url);
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
				      "error parsing HTTP request");
				exit_worker(ws);
			}
		}

		fn = post_url_handler(ws->req.url);
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
	}

	if (ws->udp_state != UP_DISABLED && ws->dtls_session) {
		msg.dtls_ciphersuite =
		    gnutls_session_get_desc(ws->dtls_session);
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
	int ret, l;

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
		ret =
		    gnutls_record_recv(ws->dtls_session, ws->buffer, ws->buffer_size);
		oclog(ws, LOG_TRANSFER_DEBUG,
		      "received %d byte(s) (DTLS)", ret);

		GNUTLS_FATAL_ERR_CMD(ret, exit_worker(ws));

		if (ret == GNUTLS_E_REHANDSHAKE) {

			if (ws->last_dtls_rehandshake > 0 &&
			    tnow->tv_sec - ws->last_dtls_rehandshake <
			    ws->config->rekey_time / 2) {
				oclog(ws, LOG_INFO,
				      "client requested DTLS rehandshake too soon");
				return -1;
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
		} else if (ret > 0) {
			l = ret;
			ws->udp_state = UP_ACTIVE;

			if (bandwidth_update
			    (&ws->b_rx, l - 1, ws->conn_mtu, tnow) != 0) {
				ret =
				    parse_dtls_data(ws, ws->buffer, l,
						    tnow->tv_sec);
				if (ret < 0) {
					oclog(ws, LOG_INFO,
					      "error parsing CSTP data");
					return ret;
				}
			}
		} else
			oclog(ws, LOG_TRANSFER_DEBUG,
			      "no data received (%d)", ret);

		ws->udp_recv_time = tnow->tv_sec;
		break;
	case UP_SETUP:
		ret = setup_dtls_connection(ws);
		if (ret < 0)
			return -1;

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

	return 0;
}

static int tls_mainloop(struct worker_st *ws, struct timespec *tnow)
{
	int ret, l;

	ret = cstp_recv_nb(ws, ws->buffer, ws->buffer_size);
	FATAL_ERR_CMD(ws, ret, exit_worker(ws));

	if (ret == 0) {		/* disconnect */
		oclog(ws, LOG_DEBUG, "client disconnected");
		return -1;
	} else if (ret > 0) {
		l = ret;
		oclog(ws, LOG_TRANSFER_DEBUG, "received %d byte(s) (TLS)", l);

		if (bandwidth_update(&ws->b_rx, l - 8, ws->conn_mtu, tnow) != 0) {
			ret = parse_cstp_data(ws, ws->buffer, l, tnow->tv_sec);
			if (ret < 0) {
				oclog(ws, LOG_ERR, "error parsing CSTP data");
				return ret;
			}

			if (ret == AC_PKT_DATA && ws->udp_state == UP_ACTIVE) {
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
			return -1;
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

	return 0;
}

static int tun_mainloop(struct worker_st *ws, struct timespec *tnow)
{
	int ret, l, e;
	unsigned tls_retry;

	l = read(ws->tun_fd, ws->buffer + 8, ws->conn_mtu);
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

	/* only transmit if allowed */
	if (bandwidth_update(&ws->b_tx, l, ws->conn_mtu, tnow)
	    != 0) {
		tls_retry = 0;

		ws->tun_bytes_out += l;
		oclog(ws, LOG_TRANSFER_DEBUG, "sending %d byte(s)\n", l);
		if (ws->udp_state == UP_ACTIVE) {

			ws->buffer[7] = AC_PKT_DATA;

			ret = dtls_send(ws, ws->buffer + 7, l + 1);
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
			ws->buffer[0] = 'S';
			ws->buffer[1] = 'T';
			ws->buffer[2] = 'F';
			ws->buffer[3] = 1;
			ws->buffer[4] = l >> 8;
			ws->buffer[5] = l & 0xff;
			ws->buffer[6] = AC_PKT_DATA;
			ws->buffer[7] = 0;

			ret = cstp_send(ws, ws->buffer, l + 8);
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

	ret = cstp_puts(ws, "X-Server-Version: "PACKAGE_STRING"\r\n");
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
	if (ws->config->udp_port != 0 && req->master_secret_set != 0) {
		memcpy(ws->master_secret, req->master_secret, TLS_MASTER_SIZE);
		ws->udp_state = UP_WAIT_FD;
	} else {
		oclog(ws, LOG_DEBUG, "disabling UDP (DTLS) connection");
	}

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

	/* If we are in CISCO client compatibility mode, do not send
	 * any IPv6 information, unless the client can really handle it.
	 */
	if (ws->full_ipv6 == 0 && ws->config->cisco_client_compat != 0 &&
	    req->user_agent_type != AGENT_OPENCONNECT) {
		req->no_ipv6 = 1;
	}

	if (ws->vinfo.ipv6 && req->no_ipv6 == 0) {
		oclog(ws, LOG_DEBUG, "sending IPv6 %s", ws->vinfo.ipv6);
		if (ws->full_ipv6 && ws->vinfo.ipv6_prefix) {
			ret =
			    cstp_printf(ws,
				       "X-CSTP-Address-IP6: %s/%u\r\n",
				       ws->vinfo.ipv6, ws->vinfo.ipv6_prefix);
			SEND_ERR(ret);
		} else {
			ret =
			    cstp_printf(ws, "X-CSTP-Address: %s\r\n",
				       ws->vinfo.ipv6);
			SEND_ERR(ret);
		}

		if (ws->vinfo.ipv6_network && ws->vinfo.ipv6_prefix != 0) {
			ret =
			    cstp_printf(ws,
				       "X-CSTP-Netmask: %s/%u\r\n",
					       ws->vinfo.ipv6_network, ws->vinfo.ipv6_prefix);
			SEND_ERR(ret);
		}
	}

	for (i = 0; i < ws->vinfo.dns_size; i++) {
		if (req->no_ipv6 != 0 && strchr(ws->vinfo.dns[i], ':') != 0)
			continue;
		if (req->no_ipv4 != 0 && strchr(ws->vinfo.dns[i], '.') != 0)
			continue;

		ret =
		    cstp_printf(ws, "X-CSTP-DNS: %s\r\n",
			       ws->vinfo.dns[i]);
		SEND_ERR(ret);
	}

	for (i = 0; i < ws->vinfo.nbns_size; i++) {
		if (req->no_ipv6 != 0 && strchr(ws->vinfo.nbns[i], ':') != 0)
			continue;
		if (req->no_ipv4 != 0 && strchr(ws->vinfo.nbns[i], '.') != 0)
			continue;

		ret =
		    cstp_printf(ws, "X-CSTP-NBNS: %s\r\n",
			       ws->vinfo.nbns[i]);
		SEND_ERR(ret);
	}

	for (i = 0; i < ws->config->split_dns_size; i++) {
		oclog(ws, LOG_DEBUG, "adding split DNS %s",
		      ws->config->split_dns[i]);
		ret =
		    cstp_printf(ws, "X-CSTP-Split-DNS: %s\r\n",
			       ws->config->split_dns[i]);
		SEND_ERR(ret);
	}

	if (ws->default_route == 0) {
		for (i = 0; i < ws->vinfo.routes_size; i++) {
			if (strchr(ws->vinfo.routes[i], ':') != 0)
				ip6 = 1;
			else
				ip6 = 0;

			if (req->no_ipv6 != 0 && ip6 != 0)
				continue;
			if (req->no_ipv4 != 0 && ip6 == 0)
				continue;
			oclog(ws, LOG_DEBUG, "adding route %s", ws->vinfo.routes[i]);

			if (ip6 != 0 && ws->full_ipv6) {
				ret = cstp_printf(ws,
					 "X-CSTP-Split-Include-IP6: %s\r\n",
					 ws->vinfo.routes[i]);
			} else {
				ret = cstp_printf(ws,
					 "X-CSTP-Split-Include: %s\r\n",
					 ws->vinfo.routes[i]);
			}
			SEND_ERR(ret);
		}

		for (i = 0; i < ws->routes_size; i++) {
			if (strchr(ws->routes[i], ':') != 0)
				ip6 = 1;
			else
				ip6 = 0;

			if (req->no_ipv6 != 0 && ip6 != 0)
				continue;
			if (req->no_ipv4 != 0 && ip6 == 0)
				continue;
			oclog(ws, LOG_DEBUG, "adding private route %s", ws->routes[i]);

			if (ip6 != 0 && ws->full_ipv6) {
				ret = cstp_printf(ws,
					 "X-CSTP-Split-Include-IP6: %s\r\n",
					 ws->routes[i]);
			} else {
				ret = cstp_printf(ws,
					 "X-CSTP-Split-Include: %s\r\n",
					 ws->routes[i]);
			}
			SEND_ERR(ret);
		}
	}

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

	/* calculate base MTU */
	if (ws->config->default_mtu > 0) {
		ws->vinfo.mtu = ws->config->default_mtu;
	}

	if (req->base_mtu > 0) {
		oclog(ws, LOG_DEBUG, "peer's base MTU is %u", req->base_mtu);
		ws->vinfo.mtu = MIN(ws->vinfo.mtu, req->base_mtu);
	}

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
			       ws->config->udp_port);
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
			setsockopt(ws->udp_fd, SOL_SOCKET, SO_SNDBUF, &t,
				   sizeof(t));
			if (ret == -1)
				oclog(ws, LOG_DEBUG,
				      "setsockopt(UDP, SO_SNDBUF) to %u, failed.",
				      t);
		}

		set_net_priority(ws, ws->udp_fd, ws->config->net_priority);
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

		FD_SET(ws->conn_fd, &rfds);
		FD_SET(ws->cmd_fd, &rfds);
		FD_SET(ws->tun_fd, &rfds);
		max = MAX(ws->cmd_fd, ws->conn_fd);
		max = MAX(max, ws->tun_fd);

		if (ws->udp_state > UP_WAIT_FD) {
			FD_SET(ws->udp_fd, &rfds);
			max = MAX(max, ws->udp_fd);
		}

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

		if (ws->dtls_session != NULL && ws->udp_state > UP_WAIT_FD) {
			dtls_pending =
			    gnutls_record_check_pending(ws->dtls_session);
		} else {
			dtls_pending = 0;
		}

		if (tls_pending == 0 && dtls_pending == 0) {
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
		if (ws->udp_state > UP_WAIT_FD
		    && (FD_ISSET(ws->udp_fd, &rfds) || dtls_pending != 0)) {

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

static int parse_data(struct worker_st *ws, gnutls_session_t ts,	/* the interface of recv */
		      uint8_t head, uint8_t * buf, size_t buf_size, time_t now)
{
	int ret, e;

	switch (head) {
	case AC_PKT_DPD_RESP:
		oclog(ws, LOG_TRANSFER_DEBUG, "received DPD response");
		break;
	case AC_PKT_KEEPALIVE:
		oclog(ws, LOG_TRANSFER_DEBUG, "received keepalive");
		break;
	case AC_PKT_DPD_OUT:
		if (ws->session == ts) {
			ret = cstp_send(ws, "STF\x01\x00\x00\x04\x00", 8);

			oclog(ws, LOG_TRANSFER_DEBUG,
			      "received TLS DPD; sent response (%d bytes)",
			      ret);

			if (ret < 0) {
				oclog(ws, LOG_ERR, "could not send data: %d", ret);
				return -1;
			}
		} else {
			/* Use DPD for MTU discovery in DTLS */
			ws->buffer[0] = AC_PKT_DPD_RESP;

			ret = dtls_send(ws, ws->buffer, 1);
			if (ret == GNUTLS_E_LARGE_PACKET) {
				mtu_not_ok(ws);
				ret = dtls_send(ws, ws->buffer, 1);
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
		exit_worker(ws);
		break;
	case AC_PKT_DATA:
		oclog(ws, LOG_TRANSFER_DEBUG, "writing %d byte(s) to TUN",
		      (int)buf_size);
		ret = force_write(ws->tun_fd, buf, buf_size);
		if (ret == -1) {
			e = errno;
			oclog(ws, LOG_ERR, "could not write data to tun: %s",
			      strerror(e));
			return -1;
		}
		ws->tun_bytes_in += buf_size;
		ws->last_nc_msg = now;

		break;
	default:
		oclog(ws, LOG_DEBUG, "received unknown packet %u",
		      (unsigned)head);
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
		oclog(ws, LOG_INFO, "unexpected CSTP length");
		return -1;
	}

	ret = parse_data(ws, ws->session, buf[6], buf + 8, pktlen, now);
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
	    parse_data(ws, ws->dtls_session, buf[0], buf + 1, buf_size - 1,
		       now);
	ws->last_msg_udp = now;
	return ret;
}
