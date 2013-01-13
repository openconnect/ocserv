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
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
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

#include <vpn.h>
#include <auth.h>
#include <cookies.h>
#include <tlslib.h>

#include <http-parser/http_parser.h>

#define SUCCESS_MSG "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" \
                        "<auth id=\"success\">\r\n" \
                        "<banner>Success</banner>\r\n" \
                        "</auth>\r\n"

int get_auth_handler(server_st *server)
{
char file[PATH_MAX];
struct stat st;
int ret;

	snprintf(file, sizeof(file), "%s/%s", server->config->root_dir, "index.xml");

	ret = stat(file, &st);
	if (ret == 0) {
		tls_print(server->session, "HTTP/1.1 200 OK\r\n");
		tls_printf(server->session, "Content-Length: %u\r\n", (unsigned int)st.st_size);
		tls_print(server->session, "Content-Type: text/html\r\n");
		tls_print(server->session, "X-Transcend-Version: 1\r\n");
		tls_print(server->session, "\r\n");

		ret = tls_send_file(server->session, file);

fprintf(stderr, "file: %d, sent: %d\n", (int)st.st_size, ret);
		
		return 0;
	} else {
		tls_print(server->session, "HTTP/1.1 200 OK\r\n");
		tls_print(server->session, "Connection: close\r\n");
		tls_print(server->session, "Content-Type: text/xml\r\n");
		tls_print(server->session, "X-Transcend-Version: 1\r\n");
		tls_print(server->session, "\r\n");
		tls_print(server->session,
			   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
		tls_print(server->session, "<auth id=\"main\">\r\n");
		tls_print(server->session,
			   "<message>Please enter your username and password.</message>\r\n");
		tls_print(server->session,
			   "<form method=\"post\" action=\"/auth.xml\">\r\n");
		tls_print(server->session,
			   "<input type=\"text\" name=\"username\" label=\"Username:\" />\r\n");
		tls_print(server->session,
			   "<input type=\"password\" name=\"password\" label=\"Password:\" />\r\n");
		tls_print(server->session, "</form></auth>\r\n");
		
		return 1;
	}
}

int get_cert_username(server_st *server, const gnutls_datum_t* raw, 
			char* username, size_t username_size)
{
gnutls_x509_crt_t crt;
int ret;

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		oclog(server, LOG_ERR, "certificate error: %s", gnutls_strerror(ret));
		goto fail;
	}
	
	ret = gnutls_x509_crt_import(crt, raw, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		oclog(server, LOG_ERR, "certificate error: %s", gnutls_strerror(ret));
		goto fail;
	}
	
	ret = gnutls_x509_crt_get_dn_by_oid (crt, server->config->cert_user_oid, 
						0, 0, username, &username_size);
	if (ret < 0) {
		oclog(server, LOG_ERR, "certificate error: %s", gnutls_strerror(ret));
		goto fail;
	}
	
	ret = 0;
	
fail:
	gnutls_x509_crt_deinit(crt);
	return ret;
	
}

int post_auth_handler(server_st *server)
{
int ret;
struct req_data_st *req = server->parser->data;
const char* reason = "Authentication failed";
unsigned char cookie[COOKIE_SIZE];
char str_cookie[2*COOKIE_SIZE+1];
char cert_username[MAX_USERNAME_SIZE];
char * username = NULL;
char * password = NULL;
char *p;
unsigned int i;
struct stored_cookie_st sc;

	if (server->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
		/* body should be "username=test&password=test" */
		username = strstr(req->body, "username=");
		if (username == NULL) {
			reason = "No username";
			goto auth_fail;
		}
		username += sizeof("username=")-1;

		password = strstr(req->body, "password=");
		if (password == NULL) {
			reason = "No password";
			goto auth_fail;
		}
		password += sizeof("password=")-1;
		
		/* modify body */
		p = username;
		while(*p != 0) {
			if (*p == '&') {
				*p = 0;
				break;
			}
			p++;
		}

		p = password;
		while(*p != 0) {
			if (*p == '&') {
				*p = 0;
				break;
			}
			p++;
		}
		
		/* now verify username and passwords */
		if (strcmp(username, "test") != 0 || strcmp(password, "test") != 0)
			goto auth_fail;
	}

	if (server->config->auth_types & AUTH_TYPE_CERTIFICATE) {
		const gnutls_datum_t * cert;
		unsigned int ncerts;

		/* this is superflous. Verification has already been performed 
		 * during handshake. */
		cert = gnutls_certificate_get_peers (server->session, &ncerts);
		
		if (cert == NULL) {
			reason = "No certificate found";
			goto auth_fail;
		}

		if (server->config->cert_user_oid) { /* otherwise certificate username is ignored */
			ret = get_cert_username(server, cert, cert_username, sizeof(cert_username));
			if (ret < 0) {
				oclog(server, LOG_ERR, "Cannot get username (%s) from certificate", server->config->cert_user_oid);
				reason = "No username in certificate";
				goto auth_fail;
			}
			
			if (username) {
				if (strcmp(username, cert_username) != 0)
					oclog(server, LOG_NOTICE, "User '%s' presented the certificate of user '%s'", username, cert_username);
			} else {
				username = cert_username;
			}
		} 
	}

	oclog(server, LOG_INFO, "User '%s' logged in\n", username);

	/* generate cookie */
	ret = gnutls_rnd(GNUTLS_RND_RANDOM, cookie, sizeof(cookie));
	GNUTLS_FATAL_ERR(ret);
	
	p = str_cookie;
	for (i=0;i<sizeof(cookie);i++) {
		sprintf(p, "%.2x", (unsigned int)cookie[i]);
		p+=2;
	}

	memset(&sc, 0, sizeof(sc));
	sc.expiration = time(0) + server->config->cookie_validity;
	if (username)
		snprintf(sc.username, sizeof(sc.username), "%s", username);

	/* store cookie */
	ret = store_cookie(server, cookie, sizeof(cookie), &sc);
	if (ret < 0) {
		reason = "Storage issue";
		goto auth_fail;
	}

	/* reply */

	tls_print(server->session, "HTTP/1.1 200 OK\r\n");
	tls_print(server->session, "Content-Type: text/xml\r\n");
        tls_printf(server->session, "Content-Length: %u\r\n", (unsigned)(sizeof(SUCCESS_MSG)-1));
	tls_print(server->session, "X-Transcend-Version: 1\r\n");
	tls_printf(server->session, "Set-Cookie: webvpn=%s\r\n", str_cookie);
	tls_print(server->session, "\r\n"SUCCESS_MSG);

	return 0;

auth_fail:
	tls_print(server->session, "HTTP/1.1 503 Service Unavailable\r\n");
	tls_printf(server->session,
		   "X-Reason: %s\r\n\r\n", reason);
	tls_fatal_close(server->session, GNUTLS_A_ACCESS_DENIED);
	exit(1);
}

int get_login_handler(server_st *server)
{
char file[PATH_MAX];
struct stat st;
int ret;

	snprintf(file, sizeof(file), "%s/%s", server->config->root_dir, "login.xml");

	ret = stat(file, &st);
	if (ret == 0) {
		tls_print(server->session, "HTTP/1.1 200 OK\r\n");
		tls_printf(server->session, "Content-Length: %u\r\n", (unsigned int)st.st_size);
		tls_print(server->session, "Content-Type: text/html\r\n");
		tls_print(server->session, "X-Transcend-Version: 1\r\n");
		tls_print(server->session, "\r\n");

		tls_send_file(server->session, file);
		
		return 0;
	} else {
		tls_print(server->session, "HTTP/1.1 200 OK\r\n");
		tls_print(server->session, "Connection: close\r\n");
		tls_print(server->session, "Content-Type: text/xml\r\n");
		tls_print(server->session, "X-Transcend-Version: 1\r\n");
		tls_print(server->session, "\r\n");
		tls_print(server->session,
			   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
		tls_print(server->session, "<auth id=\"main\">\r\n");
		tls_print(server->session,
			   "<message>Please enter your login cookie.</message>\r\n");
		tls_print(server->session,
			   "<form method=\"post\" action=\"/login.xml\">\r\n");
		tls_print(server->session,
			   "<input type=\"text\" name=\"cookie\" label=\"Cookie:\" />\r\n");
		tls_print(server->session, "</form></auth>\r\n");
		
		return 1;
	}
}

/* Checks cookie if present and retrieves it. Returns negative error code
 * if cannot be found */
static int check_cookie(server_st *server, struct stored_cookie_st *sc)
{
struct req_data_st *req = server->parser->data;
int ret;

	if (req->cookie_set == 0) {
		oclog(server, LOG_INFO, "No cookie found\n");
		return -1;
	}
	
	ret = retrieve_cookie(server, req->cookie, sizeof(req->cookie), sc);
	if (ret < 0) {
		oclog(server, LOG_INFO, "Cookie not recognised\n");
		return -1;
	}
	
	return 0;
}

int post_login_handler(server_st *server)
{
int ret;
struct req_data_st *req = server->parser->data;
char str_cookie[2*COOKIE_SIZE+1];
char *p;
unsigned int i;
struct stored_cookie_st sc;

	ret = check_cookie(server, &sc);
	if (ret < 0) {
		goto auth_fail;
	}

	p = str_cookie;
	for (i=0;i<sizeof(req->cookie);i++) {
		sprintf(p, "%.2x", (unsigned int)req->cookie[i]);
		p+=2;
	}

	oclog(server, LOG_INFO, "User '%s' logged in via cookie\n", sc.username);

	tls_print(server->session, "HTTP/1.1 200 OK\r\n");
	tls_print(server->session, "Content-Type: text/xml\r\n");
	tls_print(server->session, "X-Transcend-Version: 1\r\n");
        tls_printf(server->session, "Content-Length: %u\r\n", (unsigned)(sizeof(SUCCESS_MSG)-1));
	tls_printf(server->session, "Set-Cookie: webvpn=%s\r\n",
			   str_cookie);
	tls_print(server->session, "\r\n"SUCCESS_MSG);

	return 0;

auth_fail:
	return get_login_handler(server);
}


int connect_handler(server_st *server)
{
int ret;
struct req_data_st *req = server->parser->data;
char buf[256];
fd_set rfds;
int l, pktlen;
int tls_fd, max;
struct stored_cookie_st sc;
unsigned int tun_nr = 0;

	ret = check_cookie(server, &sc);
	if (ret < 0) {
		oclog(server, LOG_INFO, "Connect request without authentication");
		tls_print(server->session, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
		tls_fatal_close(server->session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}

	if (strcmp(req->url, "/CSCOSSLC/tunnel") != 0) {
		oclog(server, LOG_INFO, "Bad connect request: '%s'\n", req->url);
		tls_print(server->session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
		tls_fatal_close(server->session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}

	oclog(server, LOG_INFO, "Connected\n");

	tls_print(server->session, "HTTP/1.1 200 CONNECTED\r\n");
	tls_print(server->session, "X-CSTP-MTU: 1500\r\n");
	tls_print(server->session, "X-CSTP-DPD: 60\r\n");
	tls_printf(server->session, "X-CSTP-Address: 172.31.255.%d\r\n",
		   100 + tun_nr);
	tls_print(server->session, "X-CSTP-Netmask: 255.255.255.255\r\n");
	tls_print(server->session, "X-CSTP-DNS: 172.31.255.1\r\n");
	tls_printf(server->session, "X-CSTP-Address: 2001:770:15f::%x\r\n",
		   0x100 + tun_nr);
	tls_printf(server->session, "X-CSTP-Netmask: 2001:770:15f::%x/128\r\n",
		   0x100 + tun_nr);
	tls_print(server->session,
		   "X-CSTP-Split-Include: 172.31.255.0/255.255.255.0\r\n");
	tls_print(server->session, "X-CSTP-Banner: Hello there\r\n");
	tls_print(server->session, "\r\n");

	tls_fd = (long)gnutls_transport_get_ptr(server->session);

	for(;;) {
		FD_ZERO(&rfds);
		
		FD_SET(tls_fd, &rfds);
		FD_SET(server->tunfd, &rfds);
		max = MAX(server->tunfd,tls_fd);

		if (gnutls_record_check_pending(server->session) == 0) {
			ret = select(max + 1, &rfds, NULL, NULL, NULL);
			if (ret <= 0)
				break;
		}

		if (FD_ISSET(server->tunfd, &rfds)) {
			int l = read(server->tunfd, buf + 8, sizeof(buf) - 8);
			buf[0] = 'S';
			buf[1] = 'T';
			buf[2] = 'F';
			buf[3] = 1;
			buf[4] = l >> 8;
			buf[5] = l & 0xff;
			buf[6] = 0;
			buf[7] = 0;

			ret = tls_send(server->session, buf, l + 8);
			GNUTLS_FATAL_ERR(ret);
		}

		if (FD_ISSET(tls_fd, &rfds) || gnutls_record_check_pending(server->session)) {
			l = tls_recv(server->session, buf, sizeof(buf));
			GNUTLS_FATAL_ERR(l);

			if (l < 8) {
				oclog(server, LOG_INFO,
				       "Can't read CSTP header\n");
				exit(1);
			}
			if (buf[0] != 'S' || buf[1] != 'T' ||
			    buf[2] != 'F' || buf[3] != 1 || buf[7]) {
				oclog(server, LOG_INFO,
				       "Can't recognise CSTP header\n");
				exit(1);
			}
			pktlen = (buf[4] << 8) + buf[5];
			if (l != 8 + pktlen) {
				oclog(server, LOG_INFO, "Unexpected length\n");
				exit(1);
			}
			switch (buf[6]) {
			case AC_PKT_DPD_RESP:
			case AC_PKT_KEEPALIVE:
				break;

			case AC_PKT_DPD_OUT:
				ret =
				    tls_send(server->session, "STF\x1\x0\x0\x4\x0",
					     8);
				GNUTLS_FATAL_ERR(ret);
				break;

			case AC_PKT_DISCONN:
				oclog(server, LOG_INFO, "Received BYE packet\n");
				break;

			case AC_PKT_DATA:
				write(server->tunfd, buf + 8, pktlen);
				break;
			}
		}



	}

	return 0;
}
