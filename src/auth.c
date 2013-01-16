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

const char login_msg[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
	"<auth id=\"main\">\r\n"
	 "<message>Please enter your username and password.</message>\r\n"
	 "<form method=\"post\" action=\"/auth\">\r\n"
	 "<input type=\"text\" name=\"username\" label=\"Username:\" />\r\n"
	 "<input type=\"password\" name=\"password\" label=\"Password:\" />\r\n"
	 "</form></auth>\r\n";

int get_auth_handler(server_st *server)
{
int ret;

	tls_puts(server->session, "HTTP/1.1 200 OK\r\n");
	tls_puts(server->session, "Connection: close\r\n");
	tls_puts(server->session, "Content-Type: text/xml\r\n");
	tls_printf(server->session, "Content-Length: %u\r\n", sizeof(login_msg)-1);
	tls_puts(server->session, "X-Transcend-Version: 1\r\n");
	tls_puts(server->session, "\r\n");

	tls_send(server->session, login_msg, sizeof(login_msg)-1);
	
	return 0;

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

int post_old_auth_handler(server_st *server)
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

	tls_puts(server->session, "HTTP/1.1 200 OK\r\n");
	tls_puts(server->session, "Content-Type: text/xml\r\n");
        tls_printf(server->session, "Content-Length: %u\r\n", (unsigned)(sizeof(SUCCESS_MSG)-1));
	tls_puts(server->session, "X-Transcend-Version: 1\r\n");
	tls_printf(server->session, "Set-Cookie: webvpn=%s\r\n", str_cookie);
	tls_puts(server->session, "\r\n"SUCCESS_MSG);

	return 0;

auth_fail:
	tls_puts(server->session, "HTTP/1.1 503 Service Unavailable\r\n");
	tls_printf(server->session,
		   "X-Reason: %s\r\n\r\n", reason);
	tls_fatal_close(server->session, GNUTLS_A_ACCESS_DENIED);
	exit(1);
}

#define XMLUSER "<username>"
#define XMLPASS "<password>"
#define XMLUSER_END "</username>"
#define XMLPASS_END "</password>"

int post_new_auth_handler(server_st *server)
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
		/* body should contain <username>test</username><password>test</password> */
		username = strstr(req->body, XMLUSER);
		if (username == NULL) {
			reason = "No username";
			goto ask_auth;
		}
		username += sizeof(XMLUSER)-1;

		password = strstr(req->body, XMLPASS);
		if (password == NULL) {
			reason = "No password";
			goto auth_fail;
		}
		password += sizeof(XMLPASS)-1;
		
		/* modify body */
		p = username;
		while(*p != 0) {
			if (*p == '<' && (strncmp(p, XMLUSER_END, sizeof(XMLUSER_END)-1) == 0)) {
				*p = 0;
				break;
			}
			p++;
		}

		p = password;
		while(*p != 0) {
			if (*p == '<' && (strncmp(p, XMLPASS_END, sizeof(XMLPASS_END)-1) == 0)) {
				*p = 0;
				break;
			}
			p++;
		}
		
		/* XXX: now verify username and passwords */
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

	tls_puts(server->session, "HTTP/1.1 200 OK\r\n");
	tls_puts(server->session, "Content-Type: text/xml\r\n");
        tls_printf(server->session, "Content-Length: %u\r\n", (unsigned)(sizeof(SUCCESS_MSG)-1));
	tls_puts(server->session, "X-Transcend-Version: 1\r\n");
	tls_printf(server->session, "Set-Cookie: webvpn=%s\r\n", str_cookie);
	tls_puts(server->session, "\r\n"SUCCESS_MSG);

	return 0;

ask_auth:
	return get_auth_handler(server);

auth_fail:
	tls_puts(server->session, "HTTP/1.1 503 Service Unavailable\r\n");
	tls_printf(server->session,
		   "X-Reason: %s\r\n\r\n", reason);
	tls_fatal_close(server->session, GNUTLS_A_ACCESS_DENIED);
	exit(1);
}
