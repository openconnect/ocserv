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

static const char oc_success_msg_head[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<config-auth client=\"vpn\" type=\"complete\">\n"
			VERSION_MSG
                        "<auth id=\"success\">\n"
                        "<title>SSL VPN Service</title>";

static const char oc_success_msg_foot[] = "</auth></config-auth>\n";

static const char ocv3_success_msg_head[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                        "<auth id=\"success\">\n"
                        "<title>SSL VPN Service</title>";

static const char ocv3_success_msg_foot[] = "</auth>\n";

#define OC_LOGIN_MSG_START \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
    "<config-auth client=\"vpn\" type=\"auth-request\">\n" \
    VERSION_MSG \
    "<auth id=\"main\">\n" \
    "<message>%s</message>\n" \
    "<form method=\"post\" action=\"/auth\">\n"

static const char oc_login_msg_end[] =
    "</form></auth>\n" "</config-auth>";

static const char login_msg_user[] =
    "<input type=\"text\" name=\"username\" label=\"Username:\" />\n";

static const char login_msg_password[] =
    "<input type=\"password\" name=\"password\" label=\"Password:\" />\n";

#define OCV3_LOGIN_MSG_START \
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
    "<auth id=\"main\">\n" \
    "<message>%s</message>\n" \
    "<form method=\"post\" action=\"/auth\">\n"

static const char ocv3_login_msg_end[] =
    "</form></auth>\n";

static int get_cert_info(worker_st * ws);
static int basic_auth_handler(worker_st * ws, unsigned http_ver, const char *msg);

int ws_switch_auth_to(struct worker_st *ws, unsigned auth)
{
	unsigned i;

	if (ws->selected_auth && ws->selected_auth->enabled != 0 &&
	    ws->selected_auth->type & auth)
		return 1;

	for (i=0;i<ws->perm_config->auth_methods;i++) {
		if (ws->perm_config->auth[i].enabled && (ws->perm_config->auth[i].type & auth) != 0) {
			ws->selected_auth = &ws->perm_config->auth[i];
			return 1;
		}
	}
	return 0;
}

void ws_disable_auth(struct worker_st *ws, unsigned auth)
{
	unsigned i;

	for (i=0;i<ws->perm_config->auth_methods;i++) {
		if ((ws->perm_config->auth[i].type & auth) != 0) {
			ws->perm_config->auth[i].enabled = 0;
		}
	}
}

static int append_group_idx(worker_st * ws, str_st *str, unsigned i)
{
	char temp[128];
	const char *name;
	const char *value;

	value = ws->config->group_list[i];
	if (ws->config->friendly_group_list != NULL && ws->config->friendly_group_list[i] != NULL)
		name = ws->config->friendly_group_list[i];
	else
		name = ws->config->group_list[i];

	snprintf(temp, sizeof(temp), "<option value=\"%s\">%s</option>\n", value, name);
	if (str_append_str(str, temp) < 0)
		return -1;

	return 0;
}

static int append_group_str(worker_st * ws, str_st *str, const char *group)
{
	char temp[128];
	const char *name;
	const char *value;
	unsigned i;

	value = name = group;

	if (ws->config->friendly_group_list) {
		for (i=0;i<ws->config->group_list_size;i++) {
			if (strcmp(ws->config->group_list[i], group) == 0) {
				if (ws->config->friendly_group_list[i] != NULL)
					name = ws->config->friendly_group_list[i];
				break;
			}
		}
	}

	snprintf(temp, sizeof(temp), "<option value=\"%s\">%s</option>\n", value, name);
	if (str_append_str(str, temp) < 0)
		return -1;

	return 0;
}

int get_auth_handler2(worker_st * ws, unsigned http_ver, const char *pmsg)
{
	int ret;
	char context[BASE64_LENGTH(SID_SIZE) + 1];
	unsigned int i, j;
	str_st str;
	const char *login_msg_start;
	const char *login_msg_end;

	if (ws->req.user_agent_type == AGENT_OPENCONNECT_V3) {
		login_msg_start = OCV3_LOGIN_MSG_START;
		login_msg_end = ocv3_login_msg_end;
	} else {
		login_msg_start = OC_LOGIN_MSG_START;
		login_msg_end = oc_login_msg_end;
	}

	if (ws->selected_auth->type & AUTH_TYPE_GSSAPI && ws->auth_state < S_AUTH_COOKIE) {
		if (ws->req.authorization == NULL || ws->req.authorization_size == 0)
			return basic_auth_handler(ws, http_ver, NULL);
		else
			return post_auth_handler(ws, http_ver);
	}

	str_init(&str, ws);

	oclog(ws, LOG_HTTP_DEBUG, "HTTP sending: 200 OK");
	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;


	if (ws->sid_set != 0) {
		base64_encode((char *)ws->sid, sizeof(ws->sid), (char *)context,
			      sizeof(context));

		ret =
		    cstp_printf(ws,
			       "Set-Cookie: webvpncontext=%s; Max-Age=%u; Secure\r\n",
			       context, (unsigned)ws->config->cookie_timeout);
		if (ret < 0)
			return -1;

		oclog(ws, LOG_DEBUG, "sent sid: %s", context);
	} else {
		ret =
		    cstp_puts(ws,
			     "Set-Cookie: webvpncontext=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure\r\n");
		if (ret < 0)
			return -1;
	}

	ret = cstp_puts(ws, "Content-Type: text/xml\r\n");
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	if (ws->auth_state == S_AUTH_REQ) {
		/* only ask password */
		if (pmsg == NULL)
			pmsg = "Please enter your password";

		ret = str_append_printf(&str, login_msg_start, pmsg);
		if (ret < 0) {
			ret = -1;
			goto cleanup;
		}

		ret = str_append_str(&str, login_msg_password);
		if (ret < 0) {
			ret = -1;
			goto cleanup;
		}

		ret = str_append_str(&str, login_msg_end);
		if (ret < 0) {
			ret = -1;
			goto cleanup;
		}

	} else {
		if (pmsg == NULL)
			pmsg = "Please enter your username";

		/* ask for username and groups */
		ret = str_append_printf(&str, login_msg_start, pmsg);
		if (ret < 0) {
			ret = -1;
			goto cleanup;
		}

		if (ws->selected_auth->type & AUTH_TYPE_USERNAME_PASS) {
			ret = str_append_str(&str, login_msg_user);
			if (ret < 0) {
				ret = -1;
				goto cleanup;
			}
		}

		if (ws->selected_auth->type & AUTH_TYPE_CERTIFICATE && ws->cert_auth_ok != 0) {
			ret = get_cert_info(ws);
			if (ret < 0) {
				ret = -1;
				oclog(ws, LOG_WARNING, "cannot obtain certificate information");
				goto cleanup;
			}
		}

		/* send groups */
		if (ws->config->group_list_size > 0 || ws->cert_groups_size > 0) {
			ret = str_append_str(&str, "<select name=\"group_list\" label=\"GROUP:\">\n");
			if (ret < 0) {
				ret = -1;
				goto cleanup;
			}

			/* Several anyconnect clients (and openconnect) submit the group name
			 * separately in that form. In that case they expect that we re-order
			 * the list and we place the group they selected first. WTF! No respect
			 * to server time.
			 */
			if (ws->groupname[0] != 0) {
				ret = append_group_str(ws, &str, ws->groupname);
				if (ret < 0) {
					ret = -1;
					goto cleanup;
				}
			}

			if (ws->config->default_select_group) {
				ret = str_append_printf(&str, "<option>%s</option>\n", ws->config->default_select_group);
				if (ret < 0) {
					ret = -1;
					goto cleanup;
				}
			}

			/* append any groups available in the certificate */
			if (ws->selected_auth->type & AUTH_TYPE_CERTIFICATE && ws->cert_auth_ok != 0) {
				unsigned dup;

				for (i=0;i<ws->cert_groups_size;i++) {
					dup = 0;
					for (j=0;j<ws->config->group_list_size;j++) {
						if (strcmp(ws->cert_groups[i], ws->config->group_list[j]) == 0) {
							dup = 1;
							break;
						}
					}

					if (dup == 0 && ws->groupname[0] != 0 && strcmp(ws->groupname, ws->cert_groups[i]) == 0)
						dup = 1;

					if (dup != 0)
						continue;

					ret = str_append_printf(&str, "<option>%s</option>\n", ws->cert_groups[i]);
					if (ret < 0) {
						ret = -1;
						goto cleanup;
					}
				}
			}


			for (i=0;i<ws->config->group_list_size;i++) {
				if (ws->groupname[0] != 0 && strcmp(ws->groupname, ws->config->group_list[i]) == 0)
					continue;

				ret = append_group_idx(ws, &str, i);
				if (ret < 0) {
					ret = -1;
					goto cleanup;
				}
			}
			ret = str_append_str(&str, "</select>\n");
			if (ret < 0) {
				ret = -1;
				goto cleanup;
			}
		}

		ret = str_append_str(&str, login_msg_end);
		if (ret < 0) {
			ret = -1;
			goto cleanup;
		}

	}

	ret =
	    cstp_printf(ws, "Content-Length: %u\r\n",
		       (unsigned int)str.length);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = cstp_puts(ws, "X-Transcend-Version: 1\r\n");
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = cstp_puts(ws, "\r\n");
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = cstp_send(ws, str.data, str.length);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}


	ret = cstp_uncork(ws);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = 0;

 cleanup:
 	str_clear(&str);
	return ret;
}

int get_auth_handler(worker_st * ws, unsigned http_ver)
{
	return get_auth_handler2(ws, http_ver, NULL);
}

int get_cert_names(worker_st * ws, const gnutls_datum_t * raw)
{
	gnutls_x509_crt_t crt;
	int ret;
	unsigned i;
	size_t size;

	if (ws->cert_username[0] != 0 || ws->cert_groups_size > 0)
		return 0; /* already read, nothing to do */

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

	size = sizeof(ws->cert_username);
	if (ws->config->cert_user_oid) {	/* otherwise certificate username is ignored */
		ret =
		    gnutls_x509_crt_get_dn_by_oid(crt,
					  ws->config->cert_user_oid, 0,
					  0, ws->cert_username, &size);
	} else {
		ret = gnutls_x509_crt_get_dn(crt, ws->cert_username, &size);
	}
	if (ret < 0) {
		if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
			oclog(ws, LOG_ERR, "certificate's username exceed the maximum buffer size (%u)",
			      (unsigned)sizeof(ws->cert_username));
		else
			oclog(ws, LOG_ERR, "cannot obtain user from certificate DN: %s",
			      gnutls_strerror(ret));
		goto fail;
	}

	if (ws->config->cert_group_oid) {
		i = 0;
		do {
			ws->cert_groups = talloc_realloc(ws, ws->cert_groups, char*,  i+1);
			if (ws->cert_groups == NULL) {
				oclog(ws, LOG_ERR, "cannot allocate memory for cert groups");
				ret = -1;
				goto fail;
			}

			size = 0;
			ret =
			    gnutls_x509_crt_get_dn_by_oid(crt,
						  ws->config->cert_group_oid, i,
						  0, NULL, &size);
			if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
				break;

			if (ret != GNUTLS_E_SHORT_MEMORY_BUFFER) {
				if (ret == 0)
					ret = GNUTLS_E_INTERNAL_ERROR;
				oclog(ws, LOG_ERR,
				      "cannot obtain group from certificate DN: %s",
				      gnutls_strerror(ret));
				goto fail;
			}

			ws->cert_groups[i] = talloc_size(ws->cert_groups, size);
			if (ws->cert_groups[i] == NULL) {
				oclog(ws, LOG_ERR, "cannot allocate memory for cert group");
				ret = -1;
				goto fail;
			}

			ret =
			    gnutls_x509_crt_get_dn_by_oid(crt,
						  ws->config->cert_group_oid, i,
						  0, ws->cert_groups[i], &size);
			if (ret < 0) {
				oclog(ws, LOG_ERR,
				      "cannot obtain group from certificate DN: %s",
				      gnutls_strerror(ret));
				goto fail;
			}
			i++;
		} while (ret >= 0);

		ws->cert_groups_size = i;
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

			if (msg->vname == NULL || msg->user_name == NULL || msg->sid.len != sizeof(ws->sid)) {
				ret = ERR_AUTH_FAIL;
				goto cleanup;
			}

			/* update our sid */
			memcpy(ws->sid, msg->sid.data, sizeof(ws->sid));
			ws->sid_set = 1;

			strlcpy(ws->vinfo.name, msg->vname, sizeof(ws->vinfo.name));
			strlcpy(ws->username, msg->user_name, sizeof(ws->username));

			if (msg->group_name != NULL) {
				strlcpy(ws->groupname, msg->group_name, sizeof(ws->groupname));
			} else {
				ws->groupname[0] = 0;
			}

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

			if (msg->ipv4_network != NULL) {
				talloc_free(ws->config->network.ipv4_network);
				ws->config->network.ipv4_network =
				    talloc_strdup(ws, msg->ipv4_network);
			}

			if (msg->ipv6_network != NULL) {
				talloc_free(ws->config->network.ipv6_network);
				ws->config->network.ipv6_network =
				    talloc_strdup(ws, msg->ipv6_network);
			}

			if (msg->has_ipv6_prefix) {
				ws->config->network.ipv6_prefix = msg->ipv6_prefix;
			}

			if (msg->has_rx_per_sec)
				ws->config->rx_per_sec = msg->rx_per_sec;

			if (msg->has_tx_per_sec)
				ws->config->tx_per_sec = msg->tx_per_sec;

			if (msg->has_net_priority)
				ws->config->net_priority = msg->net_priority;

			if (msg->has_no_udp && msg->no_udp != 0)
				ws->perm_config->udp_port = 0;

			if (msg->xml_config_file) {
				talloc_free(ws->config->xml_config_file);
				ws->config->xml_config_file = talloc_strdup(ws, msg->xml_config_file);
			}

			/* routes */
			ws->routes = talloc_size(ws, msg->n_routes*sizeof(char*));
			if (ws->routes != NULL) {
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
			}

			if (check_if_default_route(ws->routes, ws->routes_size))
				ws->default_route = 1;

			ws->no_routes = talloc_size(ws, msg->n_no_routes*sizeof(char*));
			if (ws->no_routes != NULL) {
				ws->no_routes_size = msg->n_no_routes;
				for (i = 0; i < ws->no_routes_size; i++) {
					ws->no_routes[i] =
					    talloc_strdup(ws, msg->no_routes[i]);
				}
			}

			ws->dns = talloc_size(ws, msg->n_dns*sizeof(char*));
			if (ws->dns != NULL) {
				ws->dns_size = msg->n_dns;
				for (i = 0; i < ws->dns_size; i++) {
					ws->dns[i] = talloc_strdup(ws, msg->dns[i]);
				}
			}

			ws->nbns = talloc_size(ws, msg->n_nbns*sizeof(char*));
			if (ws->nbns != NULL) {
				ws->nbns_size = msg->n_nbns;
				for (i = 0; i < ws->nbns_size; i++) {
					ws->nbns[i] = talloc_strdup(ws, msg->nbns[i]);
				}
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
	auth_reply_msg__free_unpacked(msg, &pa);
	return ret;
}

/* returns the fd */
int connect_to_secmod(worker_st * ws)
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

static int recv_auth_reply(worker_st * ws, int sd, char **txt)
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

	if (txt) *txt = NULL;

	switch (msg->reply) {
	case AUTH__REP__MSG:
		if (txt == NULL || msg->msg == NULL) {
			oclog(ws, LOG_ERR, "received unexpected msg");
			return ERR_AUTH_FAIL;
		}

		*txt = talloc_strdup(ws, msg->msg);
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

		strlcpy(ws->username, msg->user_name, sizeof(ws->username));
		if (msg->has_sid && msg->sid.len == sizeof(ws->sid)) {
			/* update our sid */
			memcpy(ws->sid, msg->sid.data, sizeof(ws->sid));
			ws->sid_set = 1;
		}

		if (msg->has_cookie == 0 ||
		    msg->cookie.len == 0 ||
		    msg->dtls_session_id.len != sizeof(ws->session_id)) {

			ret = ERR_AUTH_FAIL;
			goto cleanup;
		}
		
		ws->cookie = talloc_memdup(ws, msg->cookie.data, msg->cookie.len);
		if (ws->cookie) {
			ws->cookie_size = msg->cookie.len;
			ws->cookie_set = 1;
		}
		memcpy(ws->session_id, msg->dtls_session_id.data,
		       msg->dtls_session_id.len);

		if (txt)
			*txt = talloc_strdup(ws, msg->msg);

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
	sec_auth_reply_msg__free_unpacked(msg, &pa);
	return ret;
}

/* grabs the username from the session certificate */
static
int get_cert_info(worker_st * ws)
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

	ret = get_cert_names(ws, cert);
	if (ret < 0) {
		if (ws->config->cert_user_oid == NULL) {
			oclog(ws, LOG_ERR, "cannot read username from certificate; no cert-user-oid is set");
		} else {
			oclog(ws, LOG_ERR, "cannot read username (%s) from certificate",
			      ws->config->cert_user_oid);
		}
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

	if ((ws->selected_auth->type & AUTH_TYPE_CERTIFICATE)
	    && ws->config->cisco_client_compat == 0) {
		if (ws->cert_auth_ok == 0) {
			oclog(ws, LOG_INFO,
			      "no certificate provided for cookie authentication");
			return -1;
		} else {
			ret = get_cert_info(ws);
			if (ret < 0) {
				oclog(ws, LOG_INFO, "cannot obtain certificate info");
				return -1;
			}
		}
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

int post_common_handler(worker_st * ws, unsigned http_ver, const char *imsg)
{
	int ret, size;
	char str_cookie[BASE64_LENGTH(ws->cookie_size)+1];
	size_t str_cookie_size = sizeof(str_cookie);
	char msg[MAX_BANNER_SIZE + 32];
	const char *success_msg_head;
	const char *success_msg_foot;
	unsigned success_msg_head_size;
	unsigned success_msg_foot_size;

	if (ws->req.user_agent_type == AGENT_OPENCONNECT_V3) {
		success_msg_head = ocv3_success_msg_head;
		success_msg_foot = ocv3_success_msg_foot;
		success_msg_head_size = sizeof(ocv3_success_msg_head)-1;
		success_msg_foot_size = sizeof(ocv3_success_msg_foot)-1;
	} else {
		success_msg_head = oc_success_msg_head;
		success_msg_foot = oc_success_msg_foot;
		success_msg_head_size = sizeof(oc_success_msg_head)-1;
		success_msg_foot_size = sizeof(oc_success_msg_foot)-1;
	}

	base64_encode((char *)ws->cookie, ws->cookie_size,
		      (char *)str_cookie, str_cookie_size);

	/* reply */
	oclog(ws, LOG_HTTP_DEBUG, "HTTP sending: 200 OK");

	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	if (ws->selected_auth->type & AUTH_TYPE_GSSAPI && imsg != NULL && imsg[0] != 0) {
		ret = cstp_printf(ws, "WWW-Authenticate: Negotiate %s\r\n", imsg);
		if (ret < 0)
			return -1;
	}

	ret = cstp_puts(ws, "Content-Type: text/xml\r\n");
	if (ret < 0)
		return -1;

	if (ws->config->banner) {
		size =
		    snprintf(msg, sizeof(msg), "<banner>%s</banner>",
			     ws->config->banner);
		if (size <= 0)
			return -1;
		/* snprintf() returns not a very useful value, so we need to recalculate */
		size = strlen(msg);
	} else {
		msg[0] = 0;
		size = 0;
	}

	size += success_msg_head_size + success_msg_foot_size;

	ret = cstp_printf(ws, "Content-Length: %u\r\n", (unsigned)size);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	if (ws->sid_set != 0) {
		char context[BASE64_LENGTH(SID_SIZE) + 1];

		base64_encode((char *)ws->sid, sizeof(ws->sid), (char *)context,
			      sizeof(context));

		ret =
		    cstp_printf(ws,
			       "Set-Cookie: webvpncontext=%s; Secure\r\n",
			       context);
		if (ret < 0)
			return -1;

		oclog(ws, LOG_DEBUG, "sent sid: %s", context);
	}

	ret =
	    cstp_printf(ws,
		       "Set-Cookie: webvpn=%s; Secure\r\n",
		       str_cookie);
	if (ret < 0)
		return -1;

#ifdef ANYCONNECT_CLIENT_COMPAT
	ret =
	    cstp_puts(ws,
		     "Set-Cookie: webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure\r\n");
	if (ret < 0)
		return -1;

	if (ws->config->xml_config_file) {
		ret =
		    cstp_printf(ws,
			       "Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:%s&lu:/+CSCOT+/translation-table?textdomain%%3DAnyConnect%%26type%%3Dmanifest&fu:profiles%%2F%s&fh:%s; path=/; Secure\r\n",
			       ws->config->cert_hash,
			       ws->config->xml_config_file,
			       ws->config->xml_config_hash);
	} else {
		ret =
		    cstp_printf(ws,
			       "Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:%s; path=/; Secure\r\n",
			       ws->config->cert_hash);
	}

	if (ret < 0)
		return -1;
#endif

	ret =
	    cstp_printf(ws,
		       "\r\n%s%s%s", success_msg_head, msg, success_msg_foot);
	if (ret < 0)
		return -1;

	ret = cstp_uncork(ws);
	if (ret < 0)
		return -1;

	return 0;
}

#define XMLUSER "<username>"
#define XMLPASS "<password>"
#define XMLUSER_END "</username>"
#define XMLPASS_END "</password>"

/* Returns the contents of the provided fields in a newly allocated
 * string, or a negative value on error.
 *
 * @body: is the string to search the xml field at, should be null-terminated.
 * @xml_field: the XML field to check for (e.g., MYFIELD)
 * @value: the value that was found
 */
static
int parse_reply(worker_st * ws, char *body, unsigned body_length,
		const char *field, unsigned field_size,
		const char *xml_field, unsigned xml_field_size,
		char **value)
{
	char *p;
	char temp1[64];
	char temp2[64];
	unsigned temp2_len, temp1_len;
	unsigned len, xml = 0;

	if (body == NULL || body_length == 0)
		return -1;

	if (memmem(body, body_length, "<?xml", 5) != 0) {
		xml = 1;
		if (xml_field) {
			field = xml_field;
			field_size = xml_field_size;
		}

		snprintf(temp1, sizeof(temp1), "<%s>", field);
		snprintf(temp2, sizeof(temp2), "</%s>", field);

		temp1_len = strlen(temp1);
		temp2_len = strlen(temp2);

		/* body should contain <field>test</field> */
		*value =
		    strcasestr(body, temp1);
		if (*value == NULL) {
			oclog(ws, LOG_HTTP_DEBUG,
			      "cannot find '%s' in client XML message", field);
			return -1;
		}
		*value += temp1_len;

		p = *value;
		len = 0;
		while (*p != 0) {
			if (*p == '<'
			    && (strncasecmp(p, temp2, temp2_len) == 0)) {
				break;
			}
			p++;
			len++;
		}
	} else {		/* non-xml version */
		snprintf(temp1, sizeof(temp1), "%s=", field);
		temp1_len = strlen(temp1);

		/* body should be "username=test&password=test" */
		*value =
		    strcasestr(body, temp1);
		if (*value == NULL) {
			oclog(ws, LOG_HTTP_DEBUG,
			      "cannot find '%s' in client message", field);
			return -1;
		}

		*value += temp1_len;

		p = *value;
		len = 0;
		while (*p != 0) {
			if (*p == '&') {
				break;
			}
			p++;
			len++;
		}
	}

	if (len == 0) {
		*value = talloc_strdup(ws->req.body, "");
		if (*value != NULL)
			return 0;
		return -1;
	}
	if (xml)
		*value = unescape_html(ws->req.body, *value, len, NULL);
	else
		*value = unescape_url(ws->req.body, *value, len, NULL);

	if (*value == NULL) {
		oclog(ws, LOG_ERR,
		      "%s requested but no such field in client message", field);
		return -1;
	}

	return 0;
}

#define SPNEGO_MSG "<html><body>Please authenticate using GSSAPI</body></html>"
static
int basic_auth_handler(worker_st * ws, unsigned http_ver, const char *msg)
{
	int ret;

	oclog(ws, LOG_HTTP_DEBUG, "HTTP sending: 401 Unauthorized");
	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 401 Unauthorized\r\n", http_ver);
	if (ret < 0)
		return -1;

	if (ws->perm_config->auth_methods > 1) {
		ret = cstp_puts(ws, "X-HTTP-Auth-Support: fallback\r\n");
		if (ret < 0)
			return -1;
	}

	if (msg == NULL) {
		oclog(ws, LOG_HTTP_DEBUG, "HTTP sending: WWW-Authenticate: Negotiate");
		ret = cstp_puts(ws, "WWW-Authenticate: Negotiate\r\n");
	} else {
		oclog(ws, LOG_HTTP_DEBUG, "HTTP sending: WWW-Authenticate: Negotiate %s", msg);
		ret = cstp_printf(ws, "WWW-Authenticate: Negotiate %s\r\n", msg);
	}
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Content-Length: 0\r\n");
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = cstp_puts(ws, "\r\n");
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = cstp_uncork(ws);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = 0;

 cleanup:
	return ret;
}

#define USERNAME_FIELD "username"
#define PASSWORD_FIELD "password"
#define GROUPNAME_FIELD "group%5flist"
#define GROUPNAME_FIELD2 "group_list"
#define GROUPNAME_FIELD_XML "group-select"

#define MSG_INTERNAL_ERROR "Internal error"
#define MSG_CERT_READ_ERROR "Could not read certificate"
#define MSG_NO_CERT_ERROR "No certificate"
#define MSG_NO_PASSWORD_ERROR "No password"

int post_auth_handler(worker_st * ws, unsigned http_ver)
{
	int ret = -1, sd = -1;
	struct http_req_st *req = &ws->req;
	const char *reason = "Authentication failed";
	char *username = NULL;
	char *password = NULL;
	char *groupname = NULL;
	char *msg = NULL;
	unsigned def_group = 0;

	if (req->body_length > 0) {
		oclog(ws, LOG_HTTP_DEBUG, "POST body: '%.*s'", (int)req->body_length,
		      req->body);
	}

	if (ws->sid_set && ws->auth_state == S_AUTH_INACTIVE)
		ws->auth_state = S_AUTH_INIT;

	if (ws->auth_state == S_AUTH_INACTIVE) {
		SecAuthInitMsg ireq = SEC_AUTH_INIT_MSG__INIT;

		ret = parse_reply(ws, req->body, req->body_length,
				GROUPNAME_FIELD, sizeof(GROUPNAME_FIELD)-1,
				GROUPNAME_FIELD_XML, sizeof(GROUPNAME_FIELD_XML)-1,
				&groupname);
		if (ret < 0) {
			ret = parse_reply(ws, req->body, req->body_length,
					GROUPNAME_FIELD2, sizeof(GROUPNAME_FIELD2)-1,
					GROUPNAME_FIELD_XML, sizeof(GROUPNAME_FIELD_XML)-1,
					&groupname);
		}

		if (ret < 0) {
			oclog(ws, LOG_HTTP_DEBUG, "failed reading groupname");
		} else {
			if (ws->config->default_select_group != NULL &&
				   strcmp(groupname, ws->config->default_select_group) == 0) {
				def_group = 1;
			} else {
				strlcpy(ws->groupname, groupname, sizeof(ws->groupname));
				ireq.group_name = ws->groupname;
			}
		}
		talloc_free(groupname);

		if (ws->selected_auth->type & AUTH_TYPE_GSSAPI) {
			if (req->authorization == NULL || req->authorization_size == 0)
				return basic_auth_handler(ws, http_ver, NULL);

			if (req->authorization_size > 10) {
				ireq.user_name = req->authorization + 10;
				ireq.auth_type |= AUTH_TYPE_GSSAPI;
			} else {
				oclog(ws, LOG_HTTP_DEBUG, "Invalid authorization data: %.*s", req->authorization_size, req->authorization);
				goto auth_fail;
			}
		}

		if (ws->selected_auth->type & AUTH_TYPE_USERNAME_PASS) {

			ret = parse_reply(ws, req->body, req->body_length,
					USERNAME_FIELD, sizeof(USERNAME_FIELD)-1,
					NULL, 0,
					&username);
			if (ret < 0) {
				oclog(ws, LOG_HTTP_DEBUG, "failed reading username");
				goto ask_auth;
			}

			strlcpy(ws->username, username, sizeof(ws->username));
			talloc_free(username);
			ireq.user_name = ws->username;
			ireq.auth_type |= AUTH_TYPE_USERNAME_PASS;
		}

		if (ws->selected_auth->type & AUTH_TYPE_CERTIFICATE) {
			if (ws->cert_auth_ok == 0) {
				reason = MSG_NO_CERT_ERROR;
				oclog(ws, LOG_INFO,
				      "no certificate provided for authentication");
				goto auth_fail;
			} else {
				ret = get_cert_info(ws);
				if (ret < 0) {
					reason = MSG_CERT_READ_ERROR;
					oclog(ws, LOG_ERR,
					      "failed reading certificate info");
					goto auth_fail;
				}
			}

			if (def_group == 0 && ws->cert_groups_size > 0 && ws->groupname[0] == 0) {
				oclog(ws, LOG_HTTP_DEBUG, "user has not selected a group");
				return get_auth_handler2(ws, http_ver, "Please select your group");
			}

			ireq.tls_auth_ok = ws->cert_auth_ok;
			ireq.cert_user_name = ws->cert_username;
			ireq.cert_group_names = ws->cert_groups;
			ireq.n_cert_group_names = ws->cert_groups_size;
			ireq.auth_type |= AUTH_TYPE_CERTIFICATE;
		}

		ireq.hostname = req->hostname;
		ireq.ip = ws->remote_ip_str;

		sd = connect_to_secmod(ws);
		if (sd == -1) {
			reason = MSG_INTERNAL_ERROR;
			oclog(ws, LOG_ERR, "failed connecting to sec mod");
			goto auth_fail;
		}

		ret = send_msg_to_secmod(ws, sd, SM_CMD_AUTH_INIT,
					 &ireq, (pack_size_func)
					 sec_auth_init_msg__get_packed_size,
					 (pack_func) sec_auth_init_msg__pack);
		if (ret < 0) {
			reason = MSG_INTERNAL_ERROR;
			oclog(ws, LOG_ERR,
			      "failed sending auth init message to sec mod");
			goto auth_fail;
		}

		ws->auth_state = S_AUTH_INIT;
	} else if (ws->auth_state == S_AUTH_INIT
		   || ws->auth_state == S_AUTH_REQ) {
		SecAuthContMsg areq = SEC_AUTH_CONT_MSG__INIT;

		areq.ip = ws->remote_ip_str;

		if (ws->selected_auth->type & AUTH_TYPE_GSSAPI) {
			if (req->authorization == NULL || req->authorization_size <= 10) {
				if (req->authorization != NULL)
					oclog(ws, LOG_HTTP_DEBUG, "Invalid authorization data: %.*s", req->authorization_size, req->authorization);
				goto auth_fail;
			}
			areq.password = req->authorization + 10;
		}

		if (areq.password == NULL && ws->selected_auth->type & AUTH_TYPE_USERNAME_PASS) {
			ret = parse_reply(ws, req->body, req->body_length,
					PASSWORD_FIELD, sizeof(PASSWORD_FIELD)-1,
					NULL, 0,
					&password);
			if (ret < 0) {
				reason = MSG_NO_PASSWORD_ERROR;
				oclog(ws, LOG_ERR, "failed reading password");
				goto auth_fail;
			}

			areq.password = password;
		}

		if (areq.password != NULL) {
			if (ws->sid_set != 0) {
				areq.sid.data = ws->sid;
				areq.sid.len = sizeof(ws->sid);
			}

			sd = connect_to_secmod(ws);
			if (sd == -1) {
				reason = MSG_INTERNAL_ERROR;
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
				reason = MSG_INTERNAL_ERROR;
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

	ret = recv_auth_reply(ws, sd, &msg);
	if (sd != -1) {
		close(sd);
		sd = -1;
	}

	if (ret == ERR_AUTH_CONTINUE) {
		oclog(ws, LOG_DEBUG, "continuing authentication for '%s'",
		      ws->username);
		ws->auth_state = S_AUTH_REQ;

		if (ws->selected_auth->type & AUTH_TYPE_GSSAPI) {
			ret = basic_auth_handler(ws, http_ver, msg);
		} else {
			ret = get_auth_handler2(ws, http_ver, msg);
		}
		goto cleanup;
	} else if (ret < 0) {
		if (ws->selected_auth->type & AUTH_TYPE_GSSAPI) {
			/* Fallback from GSSAPI to USERNAME-PASSWORD */
			ws_disable_auth(ws, AUTH_TYPE_GSSAPI);
			oclog(ws, LOG_ERR, "failed gssapi authentication");
			if (ws_switch_auth_to(ws, AUTH_TYPE_USERNAME_PASS) == 0)
				goto auth_fail;

			ws->auth_state = S_AUTH_INACTIVE;
			ws->sid_set = 0;
			goto ask_auth;
		} else {
			oclog(ws, LOG_ERR, "failed authentication for '%s'",
			      ws->username);
			goto auth_fail;
		}
	}

	oclog(ws, LOG_HTTP_DEBUG, "user '%s' obtained cookie", ws->username);
	ws->auth_state = S_AUTH_COOKIE;

	ret = post_common_handler(ws, http_ver, msg);
	goto cleanup;

 ask_auth:

	return get_auth_handler(ws, http_ver);

 auth_fail:

	if (sd != -1)
		close(sd);
	oclog(ws, LOG_HTTP_DEBUG, "HTTP sending: 401 Unauthorized");
	cstp_printf(ws,
		   "HTTP/1.%d 401 Unauthorized\r\nContent-Length: 0\r\nX-Reason: %s\r\n\r\n",
		   http_ver, reason);
	cstp_fatal_close(ws, GNUTLS_A_ACCESS_DENIED);
	talloc_free(msg);
	exit_worker(ws);
 cleanup:
 	talloc_free(msg);
 	return ret;
}
