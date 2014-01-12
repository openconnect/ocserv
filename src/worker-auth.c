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
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
#include <ipc.pb-c.h>

#include <vpn.h>
#include "html.h"
#include <worker.h>
#include <cookies.h>
#include <common.h>
#include <tlslib.h>

#include <http_parser.h>

#define SUCCESS_MSG_HEAD "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
                        "<auth id=\"success\">\n" \
                        "<title>SSL VPN Service</title>"

#define SUCCESS_MSG_FOOT "</auth>\n"

#define CONFIG_MSG "<vpn-client-pkg-version><pkgversion>0,0,0000</pkgversion></vpn-client-pkg-version>\n"

static const char login_msg_user[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" "<auth id=\"main\">\n"
    "<message>Please enter your username</message>\n"
    "<form method=\"post\" action=\"/auth\">\n"
    "<input type=\"text\" name=\"username\" label=\"Username:\" />\n"
    "</form></auth>\n";

static const char login_msg_no_user[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" "<auth id=\"main\">\n"
    "<message>%s</message>\n" "<form method=\"post\" action=\"/auth\">\n"
    "<input type=\"password\" name=\"password\" label=\"Password:\" />\n"
    "</form></auth>\n";

int get_auth_handler2(worker_st * ws, unsigned http_ver, const char *pmsg)
{
	int ret;
	char login_msg[MAX_MSG_SIZE + sizeof(login_msg_user)];
	unsigned int lsize;
	char *u;

	tls_cork(ws->session);
	ret = tls_printf(ws->session, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "Content-Type: text/xml\r\n");
	if (ret < 0)
		return -1;

	if (ws->auth_state == S_AUTH_REQ) {
		/* only ask password */
		if (pmsg == NULL)
			pmsg = "Please enter password";
		lsize =
		    snprintf(login_msg, sizeof(login_msg), login_msg_no_user,
			     pmsg);
	} else {
		/* ask for username only */
		lsize = snprintf(login_msg, sizeof(login_msg), login_msg_user);
	}

	ret =
	    tls_printf(ws->session, "Content-Length: %u\r\n",
		       (unsigned int)lsize);
	if (ret < 0)
		return -1;

#ifdef ANYCONNECT_CLIENT_COMPAT
	if (ws->username[0] != 0) {
		/* This is to make sure that some cisco clients that
		 * like to connect for each request, don't lose the
		 * username */
		u = escape_url(ws->username, strlen(ws->username), NULL);
		ret = tls_printf(ws->session, "Set-Cookie: ocuser=%s\r\n", u);

		free(u);

		if (ret < 0)
			return -1;
	}
#endif

	ret = tls_puts(ws->session, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "\r\n");
	if (ret < 0)
		return -1;

	ret = tls_send(ws->session, login_msg, lsize);
	if (ret < 0)
		return -1;

	ret = tls_uncork(ws->session);
	if (ret < 0)
		return -1;

	return 0;
}

int get_auth_handler(worker_st * ws, unsigned http_ver)
{
	return get_auth_handler2(ws, http_ver, NULL);
}

static
int get_cert_names(worker_st * ws, const gnutls_datum_t * raw,
		   char *username, size_t username_size,
		   char *groupname, size_t groupname_size)
{
	gnutls_x509_crt_t crt;
	int ret;

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "certificate init error: %s",
		      gnutls_strerror(ret));
		goto fail;
	}

	ret = gnutls_x509_crt_import(crt, raw, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "certificate import error: %s",
		      gnutls_strerror(ret));
		goto fail;
	}

	if (ws->config->cert_user_oid) {	/* otherwise certificate username is ignored */
		ret =
		    gnutls_x509_crt_get_dn_by_oid(crt,
						  ws->config->cert_user_oid, 0,
						  0, username, &username_size);
	} else {
		ret = gnutls_x509_crt_get_dn(crt, username, &username_size);
	}
	if (ret < 0) {
		oclog(ws, LOG_ERR, "cannot obtain user from certificate DN: %s",
		      gnutls_strerror(ret));
		goto fail;
	}

	if (ws->config->cert_group_oid) {
		ret =
		    gnutls_x509_crt_get_dn_by_oid(crt,
						  ws->config->cert_group_oid, 0,
						  0, groupname,
						  &groupname_size);
		if (ret < 0) {
			oclog(ws, LOG_ERR,
			      "cannot obtain group from certificate DN: %s",
			      gnutls_strerror(ret));
			goto fail;
		}
	} else {
		groupname[0] = 0;
	}

	ret = 0;

 fail:
	gnutls_x509_crt_deinit(crt);
	return ret;

}

static int recv_auth_reply(worker_st * ws, char *txt, size_t max_txt_size)
{
	unsigned i;
	int ret;
	int socketfd = -1;
	AuthReplyMsg *msg = NULL;

	ret = recv_socket_msg(ws->cmd_fd, AUTH_REP, &socketfd,
			      (void *)&msg,
			      (unpack_func) auth_reply_msg__unpack);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error receiving auth reply message");
		return ret;
	}

	oclog(ws, LOG_DEBUG, "received auth reply message %u",
	      (unsigned)msg->reply);

	switch (msg->reply) {
	case AUTH_REPLY_MSG__AUTH__REP__MSG:
		if (txt == NULL || msg->msg == NULL) {
			oclog(ws, LOG_ERR, "received unexpected msg");
			return ERR_AUTH_FAIL;
		}

		snprintf(txt, max_txt_size, "%s", msg->msg);

		ret = ERR_AUTH_CONTINUE;
		goto cleanup;
	case AUTH_REPLY_MSG__AUTH__REP__OK:
		if (socketfd != -1) {
			ws->tun_fd = socketfd;

			if (msg->vname == NULL || msg->user_name == NULL) {
				ret = ERR_AUTH_FAIL;
				goto cleanup;
			}

			snprintf(ws->tun_name, sizeof(ws->tun_name), "%s",
				 msg->vname);
			snprintf(ws->username, sizeof(ws->username), "%s",
				 msg->user_name);

			if (msg->cookie.len != sizeof(ws->cookie) ||
			    msg->session_id.len != sizeof(ws->session_id)) {
				ret = ERR_AUTH_FAIL;
				goto cleanup;
			}
			memcpy(ws->cookie, msg->cookie.data, msg->cookie.len);
			memcpy(ws->session_id, msg->session_id.data,
			       msg->session_id.len);

			/* Read any additional data */
			if (msg->ipv4_dns != NULL) {
				free(ws->config->network.ipv4_dns);
				ws->config->network.ipv4_dns =
				    strdup(msg->ipv4_dns);
			}

			if (msg->ipv6_dns != NULL) {
				free(ws->config->network.ipv6_dns);
				ws->config->network.ipv4_dns =
				    strdup(msg->ipv6_dns);
			}

			if (msg->ipv4_nbns != NULL) {
				free(ws->config->network.ipv4_nbns);
				ws->config->network.ipv4_nbns =
				    strdup(msg->ipv4_nbns);
			}

			if (msg->ipv6_nbns != NULL) {
				free(ws->config->network.ipv6_nbns);
				ws->config->network.ipv4_nbns =
				    strdup(msg->ipv6_nbns);
			}

			if (msg->ipv4_netmask != NULL) {
				free(ws->config->network.ipv4_netmask);
				ws->config->network.ipv4_netmask =
				    strdup(msg->ipv4_netmask);
			}

			if (msg->ipv6_netmask != NULL) {
				free(ws->config->network.ipv6_netmask);
				ws->config->network.ipv4_netmask =
				    strdup(msg->ipv6_netmask);
			}

			if (msg->has_rx_per_sec)
				ws->config->rx_per_sec = msg->rx_per_sec;

			if (msg->has_tx_per_sec)
				ws->config->tx_per_sec = msg->tx_per_sec;

			if (msg->has_net_priority)
				ws->config->net_priority = msg->net_priority;

			/* routes */
			ws->routes_size = msg->n_routes;

			for (i = 0; i < ws->routes_size; i++) {
				ws->routes[i] = strdup(msg->routes[i]);
			}
		} else {
			oclog(ws, LOG_ERR, "error in received message");
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
		break;
	case AUTH_REPLY_MSG__AUTH__REP__FAILED:
	default:
		if (msg->reply != AUTH_REPLY_MSG__AUTH__REP__FAILED)
			oclog(ws, LOG_ERR, "unexpected auth reply %u",
			      (unsigned)msg->reply);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	if (msg != NULL)
		auth_reply_msg__free_unpacked(msg, NULL);
	return ret;
}

/* grabs the username from the session certificate */
static
int get_cert_info(worker_st * ws, char *user, unsigned user_size,
		  char *group, unsigned group_size)
{
	const gnutls_datum_t *cert;
	unsigned int ncerts;
	int ret;

	/* this is superflous. Verification has already been performed 
	 * during handshake. */
	cert = gnutls_certificate_get_peers(ws->session, &ncerts);

	if (cert == NULL) {
		return -1;
	}

	ret = get_cert_names(ws, cert, user, user_size, group, group_size);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "cannot get username (%s) from certificate",
		      ws->config->cert_user_oid);
		return -1;
	}

	return 0;
}

/* sends a cookie authentication request to main thread and waits for
 * a reply.
 * Returns 0 on success.
 */
int auth_cookie(worker_st * ws, void *cookie, size_t cookie_size)
{
	int ret;
	AuthCookieRequestMsg msg = AUTH_COOKIE_REQUEST_MSG__INIT;
	char tmp_user[MAX_USERNAME_SIZE];
	char tmp_group[MAX_USERNAME_SIZE];

	if ((ws->config->auth_types & AUTH_TYPE_CERTIFICATE)
	    && ws->config->force_cert_auth != 0) {
		if (ws->cert_auth_ok == 0) {
			oclog(ws, LOG_INFO,
			      "no certificate provided for cookie authentication");
			return -1;
		}

		ret = get_cert_info(ws, tmp_user, sizeof(tmp_user),
				    tmp_group, sizeof(tmp_group));
		if (ret < 0) {
			oclog(ws, LOG_INFO, "cannot obtain certificate info");
			return -1;
		}

		msg.tls_auth_ok = 1;
		msg.cert_user_name = tmp_user;
		msg.cert_group_name = tmp_group;
	}

	msg.cookie.data = cookie;
	msg.cookie.len = cookie_size;

	oclog(ws, LOG_DEBUG, "sending cookie authentication request");

	ret = send_msg_to_main(ws, AUTH_COOKIE_REQ, &msg,
			       (pack_size_func)
			       auth_cookie_request_msg__get_packed_size,
			       (pack_func) auth_cookie_request_msg__pack);
	if (ret < 0) {
		oclog(ws, LOG_INFO,
		      "error sending cookie authentication request");
		return ret;
	}

	ret = recv_auth_reply(ws, NULL, 0);
	if (ret < 0) {
		oclog(ws, LOG_INFO,
		      "error receiving cookie authentication reply");
		return ret;
	}

	return 0;
}

int post_common_handler(worker_st * ws, unsigned http_ver)
{
	int ret, size;
	char str_cookie[2 * COOKIE_SIZE + 1];
	char *p;
	unsigned i;
	char msg[MAX_BANNER_SIZE + 32];

	p = str_cookie;
	for (i = 0; i < sizeof(ws->cookie); i++) {
		sprintf(p, "%.2x", (unsigned int)ws->cookie[i]);
		p += 2;
	}

	/* reply */
	tls_cork(ws->session);

	ret = tls_printf(ws->session, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "Content-Type: text/xml\r\n");
	if (ret < 0)
		return -1;

	if (ws->config->banner) {
		size =
		    snprintf(msg, sizeof(msg), "<banner>%s</banner>",
			     ws->config->banner);
		if (size <= 0)
			return -1;
	} else {
		msg[0] = 0;
		size = 0;
	}

	size += (sizeof(SUCCESS_MSG_HEAD) - 1) + (sizeof(SUCCESS_MSG_FOOT) - 1);

	ret = tls_printf(ws->session, "Content-Length: %u\r\n", (unsigned)size);
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret =
	    tls_printf(ws->session, "Set-Cookie: webvpn=%s;Max-Age=%u\r\n",
		       str_cookie, (unsigned)ws->config->cookie_validity);
	if (ret < 0)
		return -1;

#ifdef ANYCONNECT_CLIENT_COMPAT
	ret =
	    tls_puts(ws->session,
		     "Set-Cookie: webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure\r\n");
	if (ret < 0)
		return -1;

	if (ws->config->xml_config_file) {
		ret =
		    tls_printf(ws->session,
			       "Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:%s&lu:/+CSCOT+/translation-table?textdomain%%3DAnyConnect%%26type%%3Dmanifest&fu:profiles%%2F%s&fh:%s; path=/; secure\r\n",
			       ws->config->cert_hash,
			       ws->config->xml_config_file,
			       ws->config->xml_config_hash);
	} else {
		ret =
		    tls_printf(ws->session,
			       "Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:%s; path=/; secure\r\n",
			       ws->config->cert_hash);
	}

	if (ret < 0)
		return -1;
#endif

	ret =
	    tls_printf(ws->session,
		       "\r\n" SUCCESS_MSG_HEAD "%s" SUCCESS_MSG_FOOT, msg);
	if (ret < 0)
		return -1;

#ifdef ANYCONNECT_CLIENT_COMPAT
	ret = tls_send(ws->session, CONFIG_MSG, sizeof(CONFIG_MSG) - 1);
	if (ret < 0)
		return -1;
#endif

	ret = tls_uncork(ws->session);
	if (ret < 0)
		return -1;

	return 0;
}

#define XMLUSER "<username>"
#define XMLPASS "<password>"
#define XMLUSER_END "</username>"
#define XMLPASS_END "</password>"

/* Returns the username and password in newly allocated
 * buffers.
 */
static
int read_user_pass(worker_st * ws, char *body, unsigned body_length,
		   char **username, char **password)
{
	char *p;

	if (memmem(body, body_length, "<?xml", 5) != 0) {
		oclog(ws, LOG_HTTP_DEBUG, "POST body: '%.*s'", body_length,
		      body);

		if (username != NULL) {
			/* body should contain <username>test</username><password>test</password> */
			*username =
			    memmem(body, body_length, XMLUSER,
				   sizeof(XMLUSER) - 1);
			if (*username == NULL) {
				oclog(ws, LOG_ERR,
				      "cannot find username in client XML message");
				return -1;
			}
			*username += sizeof(XMLUSER) - 1;
		}

		if (password != NULL) {
			*password =
			    memmem(body, body_length, XMLPASS,
				   sizeof(XMLPASS) - 1);
			if (*password == NULL) {
				oclog(ws, LOG_ERR,
				      "cannot find password in client XML message");
				return -1;
			}
			*password += sizeof(XMLPASS) - 1;
		}

		/* modify body */
		if (username != NULL) {
			p = *username;
			while (*p != 0) {
				if (*p == '<'
				    &&
				    (strncmp
				     (p, XMLUSER_END,
				      sizeof(XMLUSER_END) - 1) == 0)) {
					*p = 0;
					break;
				}
				p++;
			}

			*username =
			    unescape_html(*username, strlen(*username), NULL);
		}

		if (password != NULL) {
			p = *password;
			while (*p != 0) {
				if (*p == '<'
				    &&
				    (strncmp
				     (p, XMLPASS_END,
				      sizeof(XMLPASS_END) - 1) == 0)) {
					*p = 0;
					break;
				}
				p++;

			}

			*password =
			    unescape_html(*password, strlen(*password), NULL);
		}

	} else {		/* non-xml version */
		/* body should be "username=test&password=test" */
		if (username != NULL) {
			*username =
			    memmem(body, body_length, "username=",
				   sizeof("username=") - 1);
			if (*username == NULL) {
				oclog(ws, LOG_ERR,
				      "cannot find username in client message");
				return -1;
			}
			*username += sizeof("username=") - 1;
		}

		if (password != NULL) {
			*password =
			    memmem(body, body_length, "password=",
				   sizeof("password=") - 1);
			if (*password == NULL) {
				oclog(ws, LOG_ERR,
				      "cannot find password in client message");
				return -1;
			}
			*password += sizeof("password=") - 1;
		}

		/* modify body */
		if (username != NULL) {
			p = *username;
			while (*p != 0) {
				if (*p == '&') {
					*p = 0;
					break;
				}
				p++;
			}

			*username =
			    unescape_url(*username, strlen(*username), NULL);
		}

		if (password != NULL) {
			p = *password;
			while (*p != 0) {
				if (*p == '&') {
					*p = 0;
					break;
				}
				p++;
			}

			*password =
			    unescape_url(*password, strlen(*password), NULL);
		}
	}

	if (username != NULL && *username == NULL) {
		oclog(ws, LOG_ERR,
		      "username requested but no username in client message");
		return -1;
	}

	if (password != NULL && *password == NULL) {
		oclog(ws, LOG_ERR,
		      "password requested but no password in client message");
		return -1;
	}

	return 0;
}

int post_auth_handler(worker_st * ws, unsigned http_ver)
{
	int ret;
	struct http_req_st *req = &ws->req;
	const char *reason = "Authentication failed";
	char *username = NULL;
	char *password = NULL;
	char tmp_user[MAX_USERNAME_SIZE];
	char tmp_group[MAX_USERNAME_SIZE];
	char msg[MAX_MSG_SIZE];
	unsigned complete_auth = 0;

restart:

	if (ws->auth_state == S_AUTH_INACTIVE) {
		AuthInitMsg ireq = AUTH_INIT_MSG__INIT;
		
#ifdef ANYCONNECT_CLIENT_COMPAT
		if (req->ocuser_cookie_set != 0) {
			/* the client has provided the username in a different
			 * session and reconnected here to provide the password.
			 * So we read the username from the cookie, start auth
			 * and continue reading the password.
			 */
			complete_auth = 1;
			ireq.user_name = ws->username;
		} else
#endif
		if (ws->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
			ret =
			    read_user_pass(ws, req->body, req->body_length,
					   &username, NULL);
			if (ret < 0) {
				oclog(ws, LOG_ERR, "failed reading username");
				goto ask_auth;
			}

			snprintf(tmp_user, sizeof(tmp_user), "%s", username);
			free(username);
			ireq.user_name = tmp_user;
		}

		if (ws->config->auth_types & AUTH_TYPE_CERTIFICATE) {
			if (ws->cert_auth_ok == 0) {
				oclog(ws, LOG_INFO,
				      "no certificate provided for authentication");
				goto auth_fail;
			}

			ret = get_cert_info(ws, tmp_user, sizeof(tmp_user),
					    tmp_group, sizeof(tmp_group));
			if (ret < 0) {
				oclog(ws, LOG_ERR,
				      "failed reading certificate info");
				goto auth_fail;
			}

			ireq.tls_auth_ok = 1;
			ireq.cert_user_name = tmp_user;
			ireq.cert_group_name = tmp_group;
		}

		ireq.hostname = req->hostname;

		ret = send_msg_to_main(ws, AUTH_INIT,
				       &ireq,
				       (pack_size_func)
				       auth_init_msg__get_packed_size,
				       (pack_func) auth_init_msg__pack);
		if (ret < 0) {
			oclog(ws, LOG_ERR,
			      "failed sending auth init message to main");
			goto auth_fail;
		}

		ws->auth_state = S_AUTH_INIT;
	} else if (ws->auth_state == S_AUTH_INIT
		   || ws->auth_state == S_AUTH_REQ) {
		AuthRequestMsg areq = AUTH_REQUEST_MSG__INIT;

		if (ws->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
			ret =
			    read_user_pass(ws, req->body, req->body_length,
					   NULL, &password);
			if (ret < 0) {
				oclog(ws, LOG_ERR, "failed reading password");
				goto auth_fail;
			}

			areq.password = password;

			ret = send_msg_to_main(ws, AUTH_REQ, &areq,
					       (pack_size_func)
					       auth_request_msg__get_packed_size,
					       (pack_func)
					       auth_request_msg__pack);

			free(password);

			if (ret < 0) {
				oclog(ws, LOG_ERR,
				      "failed sending auth req message to main");
				goto auth_fail;
			}

			ws->auth_state = S_AUTH_REQ;
		} else
			goto auth_fail;
	} else {
		oclog(ws, LOG_ERR, "unexpected POST request in auth state %u",
		      (unsigned)ws->auth_state);
		goto auth_fail;
	}

	ret = recv_auth_reply(ws, msg, sizeof(msg));
	if (ret == ERR_AUTH_CONTINUE) {
		oclog(ws, LOG_DEBUG, "continuing authentication for '%s'",
		      ws->username);
		ws->auth_state = S_AUTH_REQ;

#ifdef ANYCONNECT_CLIENT_COMPAT
		if (complete_auth != 0) {
			goto restart;
		}
#endif
		return get_auth_handler2(ws, http_ver, msg);
	} else if (ret < 0) {
		oclog(ws, LOG_ERR, "failed authentication for '%s'",
		      ws->username);
		goto auth_fail;
	}

	oclog(ws, LOG_INFO, "user '%s' logged in", ws->username);
	ws->auth_state = S_AUTH_COMPLETE;

	return post_common_handler(ws, http_ver);

 ask_auth:
	return get_auth_handler(ws, http_ver);

 auth_fail:
	tls_printf(ws->session,
		   "HTTP/1.1 503 Service Unavailable\r\nX-Reason: %s\r\n\r\n",
		   reason);
	tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
	exit(1);
}
