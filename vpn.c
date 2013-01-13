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

#include <gnutls/gnutls.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <common.h>
#include <vpn.h>
#include <auth.h>
#include <tlslib.h>

#include <http-parser/http_parser.h>

typedef int (*url_handler_fn)(server_st*);
struct known_urls_st {
	const char* url;
	url_handler_fn get_handler;
	url_handler_fn post_handler;
};

struct known_urls_st known_urls[] = {
		{"/", get_auth_handler, NULL},
		{"/auth.xml", get_auth_handler, post_auth_handler},
		{"/login.xml", get_login_handler, post_login_handler},
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


#if 0
#define CERTFILE "/tmp/test.pem"

static const char *const cookies[] = {
};

#define nr_cookies (sizeof(cookies) / sizeof(cookies[0]))

static int tls_gets(gnutls_session_t session, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while ((ret = tls_recv(session, buf + i, 1)) == 1) {
		if (buf[i] == '\n') {
			buf[i] = 0;
			if (i && buf[i - 1] == '\r') {
				buf[i - 1] = 0;
				i--;
			}
			return i;
		}
		i++;

		if (i >= len - 1) {
			buf[i] = 0;
			return i;
		}
	}
	buf[i] = 0;
	return i ? : ret;
}

static int hexnybble(char x)
{
	if (x >= '0' && x <= '9')
		return x - '0';

	if (x >= 'a' && x <= 'f')
		return 10 + x - 'a';

	if (x >= 'A' && x <= 'F')
		return 10 + x - 'A';

	return -1;
}
#endif


int url_cb(http_parser* parser, const char *at, size_t length)
{
	struct req_data_st *req = parser->data;
	
	if (length >= sizeof(req->url)) {
		req->url[0] = 0;
		return 1;
	}

	memcpy(req->url, at, length);
	req->url[length] = 0;

	fprintf(stderr, "request %s %s\n", http_method_str(parser->method), req->url);

	return 0;
}

int header_field_cb(http_parser* parser, const char *at, size_t length)
{
	struct req_data_st *req = parser->data;

	if (strncmp(at, "Cookie", length) == 0) {
		req->cookie_set = -1;
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

int header_value_cb(http_parser* parser, const char *at, size_t length)
{
struct req_data_st *req = parser->data;
char *p;
size_t nlen;
	
	if (req->cookie_set == -1) {
		p = strstr(at, "webvpn=");
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
	}
	
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


void vpn_server(struct cfg_st *config, struct tls_st *creds, int tunfd, int fd)
{
//	int tun_nr = -1;
//	struct ifreq ifr;
	unsigned char buf[2048];
//	int i;
	int ret;
	ssize_t nparsed, nrecvd;
	gnutls_session_t session;
	http_parser parser;
	http_parser_settings settings;
	struct sockaddr_storage remote_addr;
	socklen_t remote_addr_len;
	struct req_data_st req;
	server_st server;
	url_handler_fn fn;
	
	remote_addr_len = sizeof(remote_addr);
	ret = getpeername (fd, (void*)&remote_addr, &remote_addr_len);
	if (ret < 0)
		syslog(LOG_INFO, "Accepted connection from unknown"); 
	else
		syslog(LOG_INFO, "Accepted connection from %s", 
			human_addr((void*)&remote_addr, remote_addr_len,
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

	gnutls_certificate_server_set_request(session, config->cert_req);
	gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) (long)fd);

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

	server.config = config;
	server.session = session;
	server.parser = &parser;
	server.tunfd = tunfd;

restart:
	http_parser_init(&parser, HTTP_REQUEST);
	memset(&req, 0, sizeof(req));
	parser.data = &req;

	/* parse as we go */
	do {
		nrecvd = tls_recv(session, buf, sizeof(buf));
		GNUTLS_FATAL_ERR(nrecvd);
	
		nparsed = http_parser_execute(&parser, &settings, (void*)buf, nrecvd);
		if (nparsed == 0) {
			syslog(LOG_INFO, "Error parsing HTTP request"); 
			exit(1);
		}
	} while(req.headers_complete == 0);

	if (parser.method == HTTP_GET) {
		fn = get_url_handler(req.url);
		if (fn == NULL) {
			syslog(LOG_INFO, "Unexpected URL %s", req.url); 
			tls_print(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
			goto finish;
		}
		
		ret = fn(&server);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else if (parser.method == HTTP_POST) {
		/* continue reading */
		while(req.message_complete == 0) {
			nrecvd = tls_recv(session, buf, sizeof(buf));
			GNUTLS_FATAL_ERR(nrecvd);
		
			nparsed = http_parser_execute(&parser, &settings, (void*)buf, nrecvd);
			if (nparsed == 0) {
				syslog(LOG_INFO, "Error parsing HTTP request"); 
				exit(1);
			}
		}

		fn = post_url_handler(req.url);
		if (fn == NULL) {
			syslog(LOG_INFO, "Unexpected POST URL %s", req.url); 
			tls_print(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
			goto finish;
		}

		ret = fn(&server);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else if (parser.method == HTTP_CONNECT) {
		ret = connect_handler(&server);
		if (ret == 0 && (parser.http_major != 1 || parser.http_minor != 0))
			goto restart;

	} else {
		syslog(LOG_INFO, "Unexpected method %s", http_method_str(parser.method)); 
		tls_print(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
	}

finish:
	tls_close(session);
}



#if 0

      next:
	if (tls_gets(session, buf, sizeof(buf)) <= 0) {
		syslog(LOG_INFO, "Bad first line\n");
		exit(1);
	}

	if (!strcmp(buf, "GET / HTTP/1.1")) {
		syslog(LOG_INFO, "Initial login request\n");
		while ((i = tls_gets(session, buf, sizeof(buf))) > 0)
			syslog(LOG_INFO, "incoming hdr: '%s'\n", buf);
		if (i < 0)
			exit(1);
		tls_printf(session, "HTTP/1.1 200 OK\r\n");
		tls_printf(session, "Connection: close\r\n");
		tls_printf(session, "Content-Type: text/xml\r\n");
		tls_printf(session, "X-Transcend-Version: 1\r\n");
		tls_printf(session, "\r\n");
		tls_printf(session,
			   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
		tls_printf(session, "<auth id=\"main\">\r\n");
		tls_printf(session,
			   "<message>Please enter your login cookie.</message>\r\n");
		tls_printf(session,
			   "<form method=\"post\" action=\"/login.html\">\r\n");
		tls_printf(session,
			   "<input type=\"text\" name=\"cookie\" label=\"Cookie:\" />\r\n");
		tls_printf(session, "</form></auth>\r\n");

		tls_close(session);
		exit(0);
	} else if (!strcmp(buf, "POST /login.html HTTP/1.1")) {
		int len = 0;
		syslog(LOG_INFO, "Login post\n");
		while ((i = tls_gets(session, buf, sizeof(buf))) > 0) {
			syslog(LOG_INFO, "incoming hdr: '%s'\n", buf);
			if (!strncmp(buf, "Content-Length: ", 16))
				len = atoi(buf + 16);
		}
		syslog(LOG_INFO, "Len is %d\n", len);
		if (len >= sizeof(buf)) {
			tls_printf(session,
				   "HTTP/1/1 404 Response too long\r\n\r\n");
			tls_close(session);
			exit(1);
		}

		ret = tls_recv(session, buf, len);
		GNUTLS_FATAL_ERR(ret);

		buf[ret] = 0;
		syslog(LOG_INFO, "got post '%s'\n", buf);
		if (strncmp(buf, "cookie=", 7)) {
			tls_printf(session,
				   "HTTP/1.1 404 Not a cookie\r\n\r\n");
			tls_close(session);
			exit(1);
		}
		for (i = 0; i < nr_cookies; i++) {
			int j = 0, k = 7;

			while (cookies[i][j]) {
				int c = buf[k];
				if (c == '%' && buf[k + 1] && buf[k + 2]) {
					c = (hexnybble(buf[k + 1]) << 4) +
					    hexnybble(buf[k + 2]);
					k += 2;
				}
				if (c != cookies[i][j])
					break;
				j++;
				k++;
			}
			/* Break out of outer loop if it was a match */
			if (!cookies[i][j] && !buf[k])
				break;
		}
		if (i == nr_cookies) {
			syslog(LOG_INFO, "Cookie not recognised\n");
			tls_printf(session, "HTTP/1.1 200 OK\r\n");
			tls_printf(session, "Connection: close\r\n");
			tls_printf(session, "Content-Type: text/xml\r\n");
			tls_printf(session, "X-Transcend-Version: 1\r\n");
			tls_printf(session, "\r\n");
			tls_printf(session,
				   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
			tls_printf(session, "<auth id=\"main\">\r\n");
			tls_printf(session,
				   "<banner>Invalid cookie</banner>\r\n");
			tls_printf(session,
				   "<message>Please enter your login cookie.</message>\r\n");
			tls_printf(session,
				   "<form method=\"post\" action=\"/login.html\">\r\n");
			tls_printf(session,
				   "<input type=\"text\" name=\"cookie\" label=\"Cookie:\" />\r\n");
			tls_printf(session, "</form></auth>\r\n");
			tls_close(session);
			exit(0);
		}
		syslog(LOG_INFO, "Cookie OK\n");
		tls_printf(session, "HTTP/1.1 200 OK\r\n");
		tls_printf(session, "Content-Type: text/xml\r\n");
		tls_printf(session, "X-Transcend-Version: 1\r\n");
		tls_printf(session, "Set-Cookie: webvpn=%s\r\n",
			   cookies[i]);

		len = snprintf(buf, sizeof(buf),
			       "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
			       "<auth id=\"success\">\r\n"
			       "<banner>Success</banner>\r\n"
			       "</auth>\r\n");

		tls_printf(session, "Content-Length: %d\r\n", len);
		tls_printf(session, "\r\n");
		ret = tls_send(session, buf, len);
		GNUTLS_FATAL_ERR(ret);

		goto next;
	} else if (strcmp(buf, "CONNECT /CSCOSSLC/tunnel HTTP/1.1")) {
		syslog(LOG_INFO, "Bad request: '%s'\n", buf);
		tls_printf(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
		exit(1);
	}
	while ((i = tls_gets(session, buf, sizeof(buf))) > 0) {
		syslog(LOG_INFO, "incoming hdr: '%s'\n", buf);
		if (!strncmp(buf, "Cookie: webvpn=", 15)) {
			for (i = 0; i < nr_cookies; i++) {
				if (!strcmp(cookies[i], buf + 15)) {
					tun_nr = i;
					break;
				}
			}
		}
	}
	if (i < 0)
		exit(1);
	syslog(LOG_INFO, "tun_nr is %d\n", tun_nr);
	if (tun_nr < 0) {
		tls_printf(session, "HTTP/1.1 503 Bad cookie\r\n");
		tls_printf(session,
			   "X-Reason: I did not like your cookie\r\n\r\n");
		tls_fatal_close(session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}
	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd < 0) {
		int e = errno;
		syslog(LOG_INFO, "Can't open /dev/net/tun: %s\n",
		       strerror(e));
		tls_printf(session, "HTTP/1.1 503 no tun device\r\n");
		tls_printf(session,
			   "X-Reason: Could not open /dev/net/tun: %s\r\n\r\n",
			   strerror(e));
		tls_fatal_close(session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "vpns%d", tun_nr);
	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0) {
		int e = errno;
		syslog(LOG_INFO, "TUNSETIFF: %s\n", strerror(e));
		tls_printf(session, "HTTP/1.1 503 TUNSETIFF\r\n");
		tls_printf(session,
			   "X-Reason: TUNSETIFF failed: %s\r\n\r\n",
			   strerror(errno));
		tls_fatal_close(session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}

	tls_printf(session, "HTTP/1.1 200 connected\r\n");
	tls_printf(session, "X-CSTP-MTU: 1500\r\n");
	tls_printf(session, "X-CSTP-DPD: 60\r\n");
	tls_printf(session, "X-CSTP-Address: 172.31.255.%d\r\n",
		   100 + tun_nr);
	tls_printf(session, "X-CSTP-Netmask: 255.255.255.255\r\n");
	tls_printf(session, "X-CSTP-DNS: 172.31.255.1\r\n");
	tls_printf(session, "X-CSTP-Address: 2001:770:15f::%x\r\n",
		   0x100 + tun_nr);
	tls_printf(session, "X-CSTP-Netmask: 2001:770:15f::%x/128\r\n",
		   0x100 + tun_nr);
	tls_printf(session,
		   "X-CSTP-Split-Include: 172.31.255.0/255.255.255.0\r\n");
	tls_printf(session, "X-CSTP-Banner: Hello there\r\n");
	tls_printf(session, "\r\n");
	while (1) {
		fd_set rfds;
		int l, pktlen;

		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(tunfd, &rfds);

		if (select(tunfd + 1, &rfds, NULL, NULL, NULL) <= 0)
			break;

		if (FD_ISSET(0, &rfds)) {
			l = tls_recv(session, buf, sizeof(buf));
			GNUTLS_FATAL_ERR(l);

			if (l < 8) {
				syslog(LOG_INFO,
				       "Can't read CSTP header\n");
				exit(1);
			}
			if (buf[0] != 'S' || buf[1] != 'T' ||
			    buf[2] != 'F' || buf[3] != 1 || buf[7]) {
				syslog(LOG_INFO,
				       "Can't recognise CSTP header\n");
				exit(1);
			}
			pktlen = (buf[4] << 8) + buf[5];
			if (l != 8 + pktlen) {
				syslog(LOG_INFO, "Unexpected length\n");
				exit(1);
			}
			switch (buf[6]) {
			case AC_PKT_DPD_RESP:
			case AC_PKT_KEEPALIVE:
				break;

			case AC_PKT_DPD_OUT:
				ret =
				    tls_send(session, "STF\x1\x0\x0\x4\x0",
					     8);
				GNUTLS_FATAL_ERR(ret);
				break;

			case AC_PKT_DISCONN:
				syslog(LOG_INFO, "Received BYE packet\n");
				break;

			case AC_PKT_DATA:
				write(tunfd, buf + 8, pktlen);
				break;
			}
		}
		if (FD_ISSET(tunfd, &rfds)) {
			int l = read(tunfd, buf + 8, sizeof(buf) - 8);
			buf[0] = 'S';
			buf[1] = 'T';
			buf[2] = 'F';
			buf[3] = 1;
			buf[4] = l >> 8;
			buf[5] = l & 0xff;
			buf[6] = 0;
			buf[7] = 0;

			ret = tls_send(session, buf, l + 8);
			GNUTLS_FATAL_ERR(ret);
		}


	}
}
#endif
