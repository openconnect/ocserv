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
#include <base64.h>

#include <vpn.h>
#include "html.h"
#include <worker.h>
#include <cookies.h>
#include <common.h>
#include <tlslib.h>

#include <http_parser.h>

#define VERSION_MSG "<version who=\"sg\">0.1(1)</version>\n"

#define SUCCESS_MSG_HEAD "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
			"<config-auth client=\"vpn\" type=\"complete\">\n" \
			VERSION_MSG \
                        "<auth id=\"success\">\n" \
                        "<title>SSL VPN Service</title>"

#define SUCCESS_MSG_FOOT "</auth></config-auth>\n"

static const char login_msg_user[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<config-auth client=\"vpn\" type=\"auth-request\">\n"
    VERSION_MSG
    "<auth id=\"main\">\n"
    "<message>Please enter your username</message>\n"
    "<form method=\"post\" action=\"/auth\">\n"
    "<input type=\"text\" name=\"username\" label=\"Username:\" />\n"
    "</form></auth>\n" "</config-auth>";

static const char login_msg_no_user[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<config-auth client=\"vpn\" type=\"auth-request\">\n"
    VERSION_MSG
    "<auth id=\"main\">\n"
    "<message>%s</message>\n"
    "<form method=\"post\" action=\"/auth\">\n"
    "<input type=\"password\" name=\"password\" label=\"Password:\" />\n"
    "</form></auth></config-auth>\n";

int get_auth_handler2(worker_st * ws, unsigned http_ver, const char *pmsg)
{
	int ret;
	char login_msg[MAX_MSG_SIZE + sizeof(login_msg_user)];
	char context[BASE64_LENGTH(SID_SIZE) + 1];
	unsigned int lsize;

	tls_cork(ws->session);
	ret = tls_printf(ws->session, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	if (ws->sid_set != 0) {
		base64_encode((char *)ws->sid, sizeof(ws->sid), (char *)context,
			      sizeof(context));

		ret =
		    tls_printf(ws->session,
			       "Set-Cookie: webvpncontext=%s; Max-Age=%u; Secure\r\n",
			       context, (unsigned)MAX_AUTH_SECS);
		if (ret < 0)
			return -1;

		oclog(ws, LOG_DEBUG, "sent sid: %s", context);
	}

	ret = tls_puts(ws->session, "Content-Type: text/xml\r\n");
	if (ret < 0)
		return -1;

	if (ws->auth_state == S_AUTH_REQ) {
		/* only ask password */
		if (pmsg == NULL)
			pmsg = "Please enter your password.";
		lsize =
		    snprintf(login_msg, sizeof(login_msg), login_msg_no_user,
			     pmsg);
	} else {
		/* ask for username only */
		lsize =
		    snprintf(login_msg, sizeof(login_msg), "%s",
			     login_msg_user);
	}

	ret =
	    tls_printf(ws->session, "Content-Length: %u\r\n",
		       (unsigned int)lsize);
	if (ret < 0)
		return -1;

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

/* auth reply from main process */
static int recv_cookie_auth_reply(worker_st * ws)
{
	unsigned i;
	int ret;
	int socketfd = -1;
	AuthReplyMsg *msg = NULL;
	PROTOBUF_ALLOCATOR(pa, ws);

	ret = recv_socket_msg(ws, ws->cmd_fd, AUTH_COOKIE_REP, &socketfd,
			      (void *)&msg,
			      (unpack_func) auth_reply_msg__unpack);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error receiving auth reply message");
		return ret;
	}

	oclog(ws, LOG_DEBUG, "received auth reply message (value: %u)",
	      (unsigned)msg->reply);

	switch (msg->reply) {
	case AUTH__REP__OK:
		if (socketfd != -1) {
			ws->tun_fd = socketfd;

			if (msg->vname == NULL || msg->user_name == NULL) {
				ret = ERR_AUTH_FAIL;
				goto cleanup;
			}

			snprintf(ws->vinfo.name, sizeof(ws->vinfo.name), "%s",
				 msg->vname);
			snprintf(ws->username, sizeof(ws->username), "%s",
				 msg->user_name);

			if (msg->has_cookie == 0 ||
			    msg->cookie.len != sizeof(ws->cookie) ||
			    msg->session_id.len != sizeof(ws->session_id)) {

				ret = ERR_AUTH_FAIL;
				goto cleanup;
			}
			memcpy(ws->cookie, msg->cookie.data, msg->cookie.len);
			memcpy(ws->session_id, msg->session_id.data,
			       msg->session_id.len);

			if (msg->ipv4 != NULL) {
				talloc_free(ws->vinfo.ipv4);
				if (strcmp(msg->ipv4, "0.0.0.0") == 0)
					ws->vinfo.ipv4 = NULL;
				else
					ws->vinfo.ipv4 =
					    talloc_strdup(ws, msg->ipv4);
			}

			if (msg->ipv6 != NULL) {
				talloc_free(ws->vinfo.ipv6);
				if (strcmp(msg->ipv6, "::") == 0)
					ws->vinfo.ipv6 = NULL;
				else
					ws->vinfo.ipv6 =
					    talloc_strdup(ws, msg->ipv6);
			}

			if (msg->ipv4_local != NULL) {
				talloc_free(ws->vinfo.ipv4_local);
				if (strcmp(msg->ipv4_local, "0.0.0.0") == 0)
					ws->vinfo.ipv4_local = NULL;
				else
					ws->vinfo.ipv4_local =
					    talloc_strdup(ws, msg->ipv4_local);
			}

			if (msg->ipv6_local != NULL) {
				talloc_free(ws->vinfo.ipv6_local);
				if (strcmp(msg->ipv6_local, "::") == 0)
					ws->vinfo.ipv6_local = NULL;
				else
					ws->vinfo.ipv6_local =
					    talloc_strdup(ws, msg->ipv6_local);
			}

			/* Read any additional data */
			if (msg->ipv4_netmask != NULL) {
				talloc_free(ws->config->network.ipv4_netmask);
				ws->config->network.ipv4_netmask =
				    talloc_strdup(ws, msg->ipv4_netmask);
			}

			if (msg->ipv6_netmask != NULL) {
				talloc_free(ws->config->network.ipv6_netmask);
				ws->config->network.ipv6_netmask =
				    talloc_strdup(ws, msg->ipv6_netmask);
			}

			ws->config->network.ipv6_prefix = msg->ipv6_prefix;

			if (msg->has_rx_per_sec)
				ws->config->rx_per_sec = msg->rx_per_sec;

			if (msg->has_tx_per_sec)
				ws->config->tx_per_sec = msg->tx_per_sec;

			if (msg->has_net_priority)
				ws->config->net_priority = msg->net_priority;

			if (msg->has_no_udp && msg->no_udp != 0)
				ws->config->udp_port = 0;

			/* routes */
			ws->routes_size = msg->n_routes;

			for (i = 0; i < ws->routes_size; i++) {
				ws->routes[i] =
				    talloc_strdup(ws, msg->routes[i]);

				/* If a default route is detected */
				if (ws->routes[i] != NULL &&
				    (strcmp(ws->routes[i], "default") == 0 ||
				     strcmp(ws->routes[i], "0.0.0.0/0") == 0)) {

				     /* disable all routes */
				     ws->routes_size = 0;
				     ws->default_route = 1;
				     break;
				}
			}

			if (check_if_default_route(ws->routes, ws->routes_size))
				ws->default_route = 1;

			ws->dns_size = msg->n_dns;

			for (i = 0; i < ws->dns_size; i++) {
				ws->dns[i] = talloc_strdup(ws, msg->dns[i]);
			}

			ws->nbns_size = msg->n_nbns;

			for (i = 0; i < ws->nbns_size; i++) {
				ws->nbns[i] = talloc_strdup(ws, msg->nbns[i]);
			}
		} else {
			oclog(ws, LOG_ERR, "error in received message");
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
		break;
	case AUTH__REP__FAILED:
	default:
		if (msg->reply != AUTH__REP__FAILED)
			oclog(ws, LOG_ERR, "unexpected auth reply %u",
			      (unsigned)msg->reply);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	if (msg != NULL)
		auth_reply_msg__free_unpacked(msg, &pa);
	return ret;
}

/* returns the fd */
static int connect_to_secmod(worker_st * ws)
{
	int sd, ret, e;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		oclog(ws, LOG_ERR, "error opening unix socket (for sec-mod) %s",
		      strerror(e));
		return -1;
	}

	ret =
	    connect(sd, (struct sockaddr *)&ws->secmod_addr,
		    ws->secmod_addr_len);
	if (ret < 0) {
		e = errno;
		close(sd);
		oclog(ws, LOG_ERR,
		      "error connecting to sec-mod socket '%s': %s",
		      ws->secmod_addr.sun_path, strerror(e));
		return -1;
	}
	return sd;
}

static
int send_msg_to_secmod(worker_st * ws, int sd, uint8_t cmd,
		       const void *msg, pack_size_func get_size, pack_func pack)
{
	oclog(ws, LOG_DEBUG, "sending message '%s' to secmod",
	      cmd_request_to_str(cmd));

	return send_msg(ws, sd, cmd, msg, get_size, pack);
}

static int recv_auth_reply(worker_st * ws, int sd, char *txt,
			   size_t max_txt_size)
{
	int ret;
	SecAuthReplyMsg *msg = NULL;
	PROTOBUF_ALLOCATOR(pa, ws);

	ret = recv_msg(ws, sd, SM_CMD_AUTH_REP,
		       (void *)&msg, (unpack_func) sec_auth_reply_msg__unpack);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error receiving auth reply message");
		return ret;
	}

	oclog(ws, LOG_DEBUG, "received auth reply message (value: %u)",
	      (unsigned)msg->reply);

	switch (msg->reply) {
	case AUTH__REP__MSG:
		if (txt == NULL || msg->msg == NULL) {
			oclog(ws, LOG_ERR, "received unexpected msg");
			return ERR_AUTH_FAIL;
		}

		snprintf(txt, max_txt_size, "%s", msg->msg);
		if (msg->has_sid && msg->sid.len == sizeof(ws->sid)) {
			/* update our sid */
			memcpy(ws->sid, msg->sid.data, sizeof(ws->sid));
			ws->sid_set = 1;
		}

		ret = ERR_AUTH_CONTINUE;
		goto cleanup;
	case AUTH__REP__OK:
		if (msg->user_name == NULL) {
			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}

		snprintf(ws->username, sizeof(ws->username), "%s",
			 msg->user_name);

		if (msg->has_sid && msg->sid.len == sizeof(ws->sid)) {
			/* update our sid */
			memcpy(ws->sid, msg->sid.data, sizeof(ws->sid));
			ws->sid_set = 1;
		}

		if (msg->has_cookie == 0 ||
		    msg->cookie.len != sizeof(ws->cookie) ||
		    msg->dtls_session_id.len != sizeof(ws->session_id)) {

			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
		memcpy(ws->cookie, msg->cookie.data, msg->cookie.len);
		ws->cookie_set = 1;
		memcpy(ws->session_id, msg->dtls_session_id.data,
		       msg->dtls_session_id.len);

		break;
	case AUTH__REP__FAILED:
	default:
		if (msg->reply != AUTH__REP__FAILED)
			oclog(ws, LOG_ERR, "unexpected auth reply %u",
			      (unsigned)msg->reply);
		ret = ERR_AUTH_FAIL;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	if (msg != NULL)
		sec_auth_reply_msg__free_unpacked(msg, &pa);
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
	    && ws->config->cisco_client_compat == 0) {
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

	ret = send_msg_to_main(ws, AUTH_COOKIE_REQ, &msg, (pack_size_func)
			       auth_cookie_request_msg__get_packed_size,
			       (pack_func) auth_cookie_request_msg__pack);
	if (ret < 0) {
		oclog(ws, LOG_INFO,
		      "error sending cookie authentication request");
		return ret;
	}

	ret = recv_cookie_auth_reply(ws);
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
	char str_cookie[BASE64_LENGTH(COOKIE_SIZE) + 1];
	size_t str_cookie_size = sizeof(str_cookie);
	char msg[MAX_BANNER_SIZE + 32];

	base64_encode((char *)ws->cookie, sizeof(ws->cookie),
		      (char *)str_cookie, str_cookie_size);

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
	    tls_printf(ws->session,
		       "Set-Cookie: webvpn=%s; Max-Age=%u; Secure\r\n",
		       str_cookie, (unsigned)ws->config->cookie_validity);
	if (ret < 0)
		return -1;

#ifdef ANYCONNECT_CLIENT_COMPAT
	ret =
	    tls_puts(ws->session,
		     "Set-Cookie: webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure\r\n");
	if (ret < 0)
		return -1;

	if (ws->config->xml_config_file) {
		ret =
		    tls_printf(ws->session,
			       "Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:%s&lu:/+CSCOT+/translation-table?textdomain%%3DAnyConnect%%26type%%3Dmanifest&fu:profiles%%2F%s&fh:%s; path=/; Secure\r\n",
			       ws->config->cert_hash,
			       ws->config->xml_config_file,
			       ws->config->xml_config_hash);
	} else {
		ret =
		    tls_printf(ws->session,
			       "Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:%s; path=/; Secure\r\n",
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

		if (username != NULL) {
			/* body should contain <username>test</username><password>test</password> */
			*username =
			    memmem(body, body_length, XMLUSER,
				   sizeof(XMLUSER) - 1);
			if (*username == NULL) {
				oclog(ws, LOG_DEBUG,
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
				oclog(ws, LOG_DEBUG,
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
			    unescape_html(ws, *username, strlen(*username),
					  NULL);
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
			    unescape_html(ws, *password, strlen(*password),
					  NULL);
		}

	} else {		/* non-xml version */
		/* body should be "username=test&password=test" */
		if (username != NULL) {
			*username =
			    memmem(body, body_length, "username=",
				   sizeof("username=") - 1);
			if (*username == NULL) {
				oclog(ws, LOG_DEBUG,
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
				oclog(ws, LOG_DEBUG,
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
			    unescape_url(ws, *username, strlen(*username),
					 NULL);
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
			    unescape_url(ws, *password, strlen(*password),
					 NULL);
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
	int ret, sd = -1;
	struct http_req_st *req = &ws->req;
	const char *reason = "Authentication failed";
	char *username = NULL;
	char *password = NULL;
	char tmp_user[MAX_USERNAME_SIZE];
	char tmp_group[MAX_USERNAME_SIZE];
	char ipbuf[128];
	char msg[MAX_MSG_SIZE];

	oclog(ws, LOG_HTTP_DEBUG, "POST body: '%.*s'", (int)req->body_length,
	      req->body);

	if (ws->auth_state == S_AUTH_INACTIVE) {
		SecAuthInitMsg ireq = SEC_AUTH_INIT_MSG__INIT;

		if (ws->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
			ret =
			    read_user_pass(ws, req->body, req->body_length,
					   &username, NULL);
			if (ret < 0) {
				/* No username, see if we are continuing a previous session */
				if (ws->config->cisco_client_compat != 0 &&
				    gnutls_session_is_resumed(ws->session) !=
				    0) {
					SecAuthContMsg rreq =
					    SEC_AUTH_CONT_MSG__INIT;

					/* could it be a client reconnecting and sending
					 * his password? */
					ret =
					    read_user_pass(ws, req->body,
							   req->body_length,
							   NULL, &password);
					if (ret < 0) {
						oclog(ws, LOG_INFO,
						      "failed reading password as well");
						goto ask_auth;
					}

					rreq.tls_auth_ok = ws->cert_auth_ok;
					rreq.password = password;
					rreq.ip =
					    human_addr2((void *)&ws->remote_addr, ws->remote_addr_len,
						       ipbuf, sizeof(ipbuf), 0);

					if (ws->sid_set != 0) {
						rreq.sid.data = ws->sid;
						rreq.sid.len = sizeof(ws->sid);
					}

					sd = connect_to_secmod(ws);
					if (sd == -1) {
						oclog(ws, LOG_ERR,
						      "failed connecting to sec mod");
						goto auth_fail;
					}

					ret =
					    send_msg_to_secmod(ws, sd,
							       SM_CMD_AUTH_CONT,
							       &rreq,
							       (pack_size_func)
							       sec_auth_cont_msg__get_packed_size,
							       (pack_func)
							       sec_auth_cont_msg__pack);
					talloc_free(username);

					if (ret < 0) {
						oclog(ws, LOG_ERR,
						      "failed sending auth reinit message to main");
						goto auth_fail;
					}

					ws->auth_state = S_AUTH_INIT;
					goto recv_reply;
				}

				oclog(ws, LOG_INFO, "failed reading username");
				goto ask_auth;
			}

			snprintf(ws->username, sizeof(ws->username), "%s",
				 username);
			talloc_free(username);
			ireq.user_name = ws->username;
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
		ireq.ip =
		    human_addr2((void *)&ws->remote_addr, ws->remote_addr_len,
			       ipbuf, sizeof(ipbuf), 0);

		sd = connect_to_secmod(ws);
		if (sd == -1) {
			oclog(ws, LOG_ERR, "failed connecting to sec mod");
			goto auth_fail;
		}

		ret = send_msg_to_secmod(ws, sd, SM_CMD_AUTH_INIT,
					 &ireq, (pack_size_func)
					 sec_auth_init_msg__get_packed_size,
					 (pack_func) sec_auth_init_msg__pack);
		if (ret < 0) {
			oclog(ws, LOG_ERR,
			      "failed sending auth init message to sec mod");
			goto auth_fail;
		}

		ws->auth_state = S_AUTH_INIT;
	} else if (ws->auth_state == S_AUTH_INIT
		   || ws->auth_state == S_AUTH_REQ) {
		SecAuthContMsg areq = SEC_AUTH_CONT_MSG__INIT;

		if (ws->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
			ret =
			    read_user_pass(ws, req->body, req->body_length,
					   NULL, &password);
			if (ret < 0) {
				oclog(ws, LOG_ERR, "failed reading password");
				goto auth_fail;
			}

			areq.password = password;
			if (ws->sid_set != 0) {
				areq.sid.data = ws->sid;
				areq.sid.len = sizeof(ws->sid);
			}

			sd = connect_to_secmod(ws);
			if (sd == -1) {
				oclog(ws, LOG_ERR,
				      "failed connecting to sec mod");
				goto auth_fail;
			}

			ret =
			    send_msg_to_secmod(ws, sd, SM_CMD_AUTH_CONT, &areq,
					       (pack_size_func)
					       sec_auth_cont_msg__get_packed_size,
					       (pack_func)
					       sec_auth_cont_msg__pack);
			talloc_free(password);

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

 recv_reply:
	ret = recv_auth_reply(ws, sd, msg, sizeof(msg));
	if (sd != -1)
		close(sd);

	if (ret == ERR_AUTH_CONTINUE) {
		oclog(ws, LOG_DEBUG, "continuing authentication for '%s'",
		      ws->username);
		ws->auth_state = S_AUTH_REQ;

		return get_auth_handler2(ws, http_ver, msg);
	} else if (ret < 0) {
		oclog(ws, LOG_ERR, "failed authentication for '%s'",
		      ws->username);
		goto auth_fail;
	}

	oclog(ws, LOG_INFO, "user '%s' obtained cookie", ws->username);
	ws->auth_state = S_AUTH_COOKIE;

	return post_common_handler(ws, http_ver);

 ask_auth:
	if (sd != -1)
		close(sd);
	return get_auth_handler(ws, http_ver);

 auth_fail:
	if (sd != -1)
		close(sd);
	tls_printf(ws->session,
		   "HTTP/1.1 503 Service Unavailable\r\nX-Reason: %s\r\n\r\n",
		   reason);
	tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
	exit(1);
}
