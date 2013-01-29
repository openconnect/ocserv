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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <vpn.h>
#include <http_auth.h>
#include <cookies.h>
#include <tlslib.h>

#include <http-parser/http_parser.h>

/* HTTP requests prior to disconnection */
#define MAX_HTTP_REQUESTS 8

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
	struct req_data_st *req = parser->data;
	
	if (length >= sizeof(req->url)) {
		req->url[0] = 0;
		return 1;
	}

	memcpy(req->url, at, length);
	req->url[length] = 0;

	//fprintf(stderr, "request %s %s\n", http_method_str(parser->method), req->url);

	return 0;
}

int header_field_cb(http_parser* parser, const char *at, size_t length)
{
	struct req_data_st *req = parser->data;

	if (strncmp(at, "Cookie", length) == 0) {
		req->next_header = HEADER_COOKIE;
	} else {
		req->next_header = 0;
	}
	
	return 0;
}

int header_value_cb(http_parser* parser, const char *at, size_t length)
{
struct req_data_st *req = parser->data;
char *p;
size_t nlen;

	if (length > 0)
		switch (req->next_header) {
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
				req->cookie_set = 1;
				break;
		}
	
	return 0;
}

int header_complete_cb(http_parser* parser)
{
	struct req_data_st *req = parser->data;

	req->headers_complete = 1;
	return 0;
}

int message_complete_cb(http_parser* parser)
{
	struct req_data_st *req = parser->data;

	req->message_complete = 1;
	return 0;
}

int body_cb(http_parser* parser, const char *at, size_t length)
{
struct req_data_st *req = parser->data;
char* tmp = malloc(length+1);

	if (tmp == NULL)
		return 1;
		
	memcpy(tmp, at, length);
	tmp[length] = 0;

	req->body = tmp;
	return 0;
}

void vpn_server(struct worker_st* ws, struct tls_st *creds)
{
	unsigned char buf[2048];
	int ret;
	ssize_t nparsed, nrecvd;
	gnutls_session_t session;
	http_parser parser;
	http_parser_settings settings;
	struct req_data_st req;
	url_handler_fn fn;
	int requests_left = MAX_HTTP_REQUESTS;

	syslog(LOG_INFO, "Accepted connection from %s", 
		human_addr((void*)&ws->remote_addr, ws->remote_addr_len,
		    buf, sizeof(buf)));

	/* initialize the session */
	ret = gnutls_init(&session, GNUTLS_SERVER);
	GNUTLS_FATAL_ERR(ret);

	ret = gnutls_priority_set(session, creds->cprio);
	GNUTLS_FATAL_ERR(ret);

	ret =
	    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				   creds->xcred);
	GNUTLS_FATAL_ERR(ret);

	gnutls_certificate_server_set_request(session, ws->config->cert_req);
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) (long)ws->conn_fd);

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
		oclog(ws, LOG_INFO, "Maximum number of HTTP requests reached."); 
		exit(1);
	}

	http_parser_init(&parser, HTTP_REQUEST);
	memset(&req, 0, sizeof(req));
	parser.data = &req;

	/* parse as we go */
	do {
		nrecvd = tls_recv(session, buf, sizeof(buf));
		GNUTLS_FATAL_ERR(nrecvd);
	
		nparsed = http_parser_execute(&parser, &settings, (void*)buf, nrecvd);
		if (nparsed == 0) {
			oclog(ws, LOG_INFO, "Error parsing HTTP request"); 
			exit(1);
		}
	} while(req.headers_complete == 0);

	if (parser.method == HTTP_GET) {
		fn = get_url_handler(req.url);
		if (fn == NULL) {
			oclog(ws, LOG_INFO, "Unexpected URL %s", req.url); 
			tls_puts(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
			goto finish;
		}
		
		ret = fn(ws);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else if (parser.method == HTTP_POST) {
		/* continue reading */
		while(req.message_complete == 0) {
			nrecvd = tls_recv(session, buf, sizeof(buf));
			GNUTLS_FATAL_ERR(nrecvd);
		
			nparsed = http_parser_execute(&parser, &settings, (void*)buf, nrecvd);
			if (nparsed == 0) {
				oclog(ws, LOG_INFO, "Error parsing HTTP request"); 
				exit(1);
			}
		}

		fn = post_url_handler(req.url);
		if (fn == NULL) {
			oclog(ws, LOG_INFO, "Unexpected POST URL %s", req.url); 
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
		oclog(ws, LOG_INFO, "Unexpected method %s", http_method_str(parser.method)); 
		tls_puts(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
	}

finish:
	tls_close(session);
}

static int get_remote_ip(int fd, int family,
		         struct vpn_st* vinfo, char** buffer, size_t* buffer_size)
{
unsigned char *ptr;
const char* p;
struct ifreq ifr;
unsigned int i;
int ret;

	/* get netmask */
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = family;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);

	/* local: SIOCGIFADDR */
	ret = ioctl(fd, SIOCGIFDSTADDR, &ifr);
	if (ret != 0) {
		goto fail;
	}

	if (family == AF_INET) {
		ptr = (void*)&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	} else if (family == AF_INET6) {
		ptr = (void*)&((struct sockaddr_in6 *)&ifr.ifr_addr)->sin6_addr;
	} else {
		return -1;
	}

	p = inet_ntop(family, (void*)ptr, *buffer, *buffer_size);
	if (p == NULL) {
		goto fail;
	}

	ret = strlen(p) + 1;
	*buffer += ret;
	*buffer_size -= ret;

	if (family == AF_INET) {
		if (strcmp(p, "0.0.0.0")==0)
			p = NULL;
		vinfo->ipv4 = p;
	} else {
		if (strcmp(p, "::")==0)
			p = NULL;
		vinfo->ipv6 = p;
	}

	return 0;
fail:
	return -1;
}

/* Returns information based on an VPN network stored in worker_st but
 * using real time information for many fields. Nothing is allocated,
 * the provided buffer is used.
 * 
 * Returns 0 on success.
 */
static int get_rt_vpn_info(worker_st * ws,
                        struct vpn_st* vinfo, char* buffer, size_t buffer_size)
{
unsigned int i;
int fd, ret;
struct ifreq ifr;
const char* p;

	memset(vinfo, 0, sizeof(*vinfo));
	vinfo->name = ws->tun_name;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;
        
        ret = get_remote_ip(fd, AF_INET6, vinfo, &buffer, &buffer_size);
        if (ret < 0)
                oclog(ws, LOG_INFO, "Cannot obtain IPv6 IP for %s\n", vinfo->name);

        ret = get_remote_ip(fd, AF_INET, vinfo, &buffer, &buffer_size);
        if (ret < 0)
                oclog(ws, LOG_INFO, "Cannot obtain IPv4 IP for %s\n", vinfo->name);
        
        if (vinfo->ipv4 == NULL && vinfo->ipv6 == NULL) {
                ret = -1;
                goto fail;
        }

	vinfo->ipv4_dns = ws->config->network.ipv4_dns;
	vinfo->ipv6_dns = ws->config->network.ipv6_dns;
	vinfo->routes_size = ws->config->network.routes_size;
	memcpy(vinfo->routes, ws->config->network.routes, sizeof(vinfo->routes));

	vinfo->ipv4_netmask = ws->config->network.ipv4_netmask;
	vinfo->ipv6_netmask = ws->config->network.ipv6_netmask;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_addr.sa_family = AF_INET;
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", vinfo->name);
	ret = ioctl(fd, SIOCGIFMTU, (caddr_t)&ifr);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "Cannot obtain MTU for %s. Assuming 1500.", vinfo->name);
		vinfo->mtu = 1500;
	} else {
		vinfo->mtu = ifr.ifr_mtu;
	}

	ret = 0;
fail:
	close(fd);
	return ret;
}

static int connect_handler(worker_st *ws)
{
int ret;
struct req_data_st *req = ws->parser->data;
char buf[256];
fd_set rfds;
int l, pktlen;
int tls_fd, max;
unsigned i;
struct stored_cookie_st sc;
unsigned int tun_nr = 0;
struct vpn_st vinfo;
char* buffer;
unsigned int buffer_size;

	if (req->cookie_set == 0) {
		oclog(ws, LOG_INFO, "Connect request without authentication");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}

	ret = retrieve_cookie(ws, req->cookie, sizeof(req->cookie), &sc);
	if (ret < 0) {
		oclog(ws, LOG_INFO, "Connect request without authentication");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}

	if (strcmp(req->url, "/CSCOSSLC/tunnel") != 0) {
		oclog(ws, LOG_INFO, "Bad connect request: '%s'\n", req->url);
		tls_puts(ws->session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
		tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}
	
	if (ws->config->network.name == NULL) {
		oclog(ws, LOG_ERR, "No networks are configured. Rejecting client.");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n");
		tls_puts(ws->session, "X-Reason: Server configuration error\r\n\r\n");
		return -1;
	}

	oclog(ws, LOG_INFO, "Connected\n");

	buffer_size = 2048;
	buffer = malloc(buffer_size);
	if (buffer == NULL) {
		oclog(ws, LOG_ERR, "Memory error. Rejecting client.");
		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		return -1;
	}

	ret = get_rt_vpn_info(ws, &vinfo, buffer, buffer_size);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "Network interfaces are not configured. Rejecting client.");

		tls_puts(ws->session, "HTTP/1.1 503 Service Unavailable\r\n");
		tls_puts(ws->session, "X-Reason: Server configuration error\r\n\r\n");
		return -1;
	}

	tls_puts(ws->session, "HTTP/1.1 200 CONNECTED\r\n");

	oclog(ws, LOG_DEBUG, "sending mtu %d", vinfo.mtu);
	tls_printf(ws->session, "X-CSTP-MTU: %u\r\n", vinfo.mtu);
	tls_puts(ws->session, "X-CSTP-DPD: 60\r\n");

	if (vinfo.ipv4) {
		oclog(ws, LOG_DEBUG, "sending IPv4 %s", vinfo.ipv4);
		tls_printf(ws->session, "X-CSTP-Address: %s\r\n", vinfo.ipv4);

		if (vinfo.ipv4_netmask)
			tls_printf(ws->session, "X-CSTP-Netmask: %s\r\n", vinfo.ipv4_netmask);
		if (vinfo.ipv4_dns)
			tls_printf(ws->session, "X-CSTP-DNS: %s\r\n", vinfo.ipv4_dns);
	}
	
	if (vinfo.ipv6) {
		oclog(ws, LOG_DEBUG, "sending IPv6 %s", vinfo.ipv6);
		tls_printf(ws->session, "X-CSTP-Address: %s\r\n", vinfo.ipv6);

		if (vinfo.ipv6_netmask)
			tls_printf(ws->session, "X-CSTP-Netmask: %s\r\n", vinfo.ipv6_netmask);
		if (vinfo.ipv6_dns)
			tls_printf(ws->session, "X-CSTP-DNS: %s\r\n", vinfo.ipv6_dns);
	}
	
	for (i=0;i<vinfo.routes_size;i++) {
		oclog(ws, LOG_DEBUG, "adding route %s", vinfo.routes[i]);
		tls_printf(ws->session,
			"X-CSTP-Split-Include: %s\r\n", vinfo.routes[i]);
	}
	tls_puts(ws->session, "X-CSTP-Banner: Hello there\r\n");
	tls_puts(ws->session, "\r\n");
	
	free(buffer);
	buffer = NULL;

	tls_fd = (long)gnutls_transport_get_ptr(ws->session);

	for(;;) {
		FD_ZERO(&rfds);
		
		FD_SET(tls_fd, &rfds);
		FD_SET(ws->cmd_fd, &rfds);
		FD_SET(ws->tun_fd, &rfds);
		max = MAX(ws->cmd_fd,tls_fd);
		max = MAX(max,ws->tun_fd);

		if (gnutls_record_check_pending(ws->session) == 0) {
			ret = select(max + 1, &rfds, NULL, NULL, NULL);
			if (ret <= 0)
				break;
		}

		if (FD_ISSET(ws->tun_fd, &rfds)) {
			int l = read(ws->tun_fd, buf + 8, sizeof(buf) - 8);
			buf[0] = 'S';
			buf[1] = 'T';
			buf[2] = 'F';
			buf[3] = 1;
			buf[4] = l >> 8;
			buf[5] = l & 0xff;
			buf[6] = 0;
			buf[7] = 0;

			ret = tls_send(ws->session, buf, l + 8);
			GNUTLS_FATAL_ERR(ret);
		}

		if (FD_ISSET(tls_fd, &rfds) || gnutls_record_check_pending(ws->session)) {
			l = tls_recv(ws->session, buf, sizeof(buf));
			GNUTLS_FATAL_ERR(l);

			if (l < 8) {
				oclog(ws, LOG_INFO,
				       "Can't read CSTP header\n");
				exit(1);
			}
			if (buf[0] != 'S' || buf[1] != 'T' ||
			    buf[2] != 'F' || buf[3] != 1 || buf[7]) {
				oclog(ws, LOG_INFO,
				       "Can't recognise CSTP header\n");
				exit(1);
			}
			pktlen = (buf[4] << 8) + buf[5];
			if (l != 8 + pktlen) {
				oclog(ws, LOG_INFO, "Unexpected length\n");
				exit(1);
			}
			switch (buf[6]) {
			case AC_PKT_DPD_RESP:
			case AC_PKT_KEEPALIVE:
				break;

			case AC_PKT_DPD_OUT:
				ret =
				    tls_send(ws->session, "STF\x1\x0\x0\x4\x0",
					     8);
				GNUTLS_FATAL_ERR(ret);
				break;

			case AC_PKT_DISCONN:
				oclog(ws, LOG_INFO, "Received BYE packet\n");
				break;

			case AC_PKT_DATA:
				write(ws->tun_fd, buf + 8, pktlen);
				break;
			}
		}



	}

	return 0;
}
