/*
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
#include "ipc.h"
#include "html.h"
#include <worker.h>
#include <cookies.h>
#include <common.h>
#include <tlslib.h>

#include <http-parser/http_parser.h>

#define SUCCESS_MSG_HEAD "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" \
                        "<auth id=\"success\">\n" \
                        "<title>SSL VPN Service</title>"

#define SUCCESS_MSG_FOOT "</auth>\n"

static const char login_msg_user[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	"<auth id=\"main\">\n"
	 "<message>Please enter your username</message>\n"
	 "<form method=\"post\" action=\"/auth\">\n"
	 "<input type=\"text\" name=\"username\" label=\"Username:\" />\n"
	 "</form></auth>\n";

static const char login_msg_no_user[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	"<auth id=\"main\">\n"
	 "<message>%s</message>\n"
	 "<form method=\"post\" action=\"/auth\">\n"
	 "<input type=\"password\" name=\"password\" label=\"Password:\" />\n"
	 "</form></auth>\n";

int get_auth_handler2(worker_st *ws, unsigned http_ver, const char* pmsg)
{
int ret;
char login_msg[MAX_MSG_SIZE+sizeof(login_msg_user)];
unsigned int lsize;

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
		lsize = snprintf(login_msg, sizeof(login_msg), login_msg_no_user, pmsg);
	} else {
		/* ask for username only */
		lsize = snprintf(login_msg, sizeof(login_msg), login_msg_user);
	}

	ret = tls_printf(ws->session, "Content-Length: %u\r\n", (unsigned int)lsize);
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

int get_auth_handler(worker_st *ws, unsigned http_ver)
{
	return get_auth_handler2(ws, http_ver, NULL);
}

static
int get_cert_names(worker_st *ws, const gnutls_datum_t* raw, 
			char* username, size_t username_size,
			char* groupname, size_t groupname_size)
{
gnutls_x509_crt_t crt;
int ret;

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "certificate init error: %s", gnutls_strerror(ret));
		goto fail;
	}
	
	ret = gnutls_x509_crt_import(crt, raw, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "certificate import error: %s", gnutls_strerror(ret));
		goto fail;
	}
	
	if (ws->config->cert_user_oid) { /* otherwise certificate username is ignored */
		ret = gnutls_x509_crt_get_dn_by_oid (crt, ws->config->cert_user_oid, 
							0, 0, username, &username_size);
	} else {
		ret = gnutls_x509_crt_get_dn (crt, username, &username_size);
	}
	if (ret < 0) {
		oclog(ws, LOG_ERR, "cannot obtain user from certificate DN: %s", gnutls_strerror(ret));
		goto fail;
	}

	if (ws->config->cert_group_oid) {
		ret = gnutls_x509_crt_get_dn_by_oid (crt, ws->config->cert_group_oid, 
							0, 0, groupname, &groupname_size);
		if (ret < 0) {
			oclog(ws, LOG_ERR, "cannot obtain group from certificate DN: %s", gnutls_strerror(ret));
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

static int send_auth_req(int fd, const struct cmd_auth_req_st* r)
{
	struct iovec iov[2];
	uint8_t cmd;
	struct msghdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	
	cmd = AUTH_REQ;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = (void*)r;
	iov[1].iov_len = sizeof(*r);
	
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	return(sendmsg(fd, &hdr, 0));
}

static int send_auth_init(int fd, const struct cmd_auth_init_st* r)
{
	struct iovec iov[2];
	uint8_t cmd;
	struct msghdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	
	cmd = AUTH_INIT;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = (void*)r;
	iov[1].iov_len = sizeof(*r);
	
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	return(sendmsg(fd, &hdr, 0));
}

static int send_auth_cookie_req(int fd, const struct cmd_auth_cookie_req_st* r)
{
	struct iovec iov[2];
	uint8_t cmd;
	struct msghdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	
	cmd = AUTH_COOKIE_REQ;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = (void*)r;
	iov[1].iov_len = sizeof(*r);
	
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	return(sendmsg(fd, &hdr, 0));
}

static int read_str_value_length(worker_st *ws, char** res)
{
int ret;
uint8_t len;

	ret = force_read(ws->cmd_fd, &len, 1);
	if (ret != 1) {
		oclog(ws, LOG_ERR, "Error receiving length-value from main (%d)", ret);
		return ERR_BAD_COMMAND;
	}
				
	if (len > 0) {
		*res = malloc(((int)len)+1);
		if (*res == NULL)
			return ERR_MEM;

		ret = force_read(ws->cmd_fd, *res, len);
		if (ret != len) {
			oclog(ws, LOG_ERR, "Error receiving value from main (%d)", ret);
			return ERR_BAD_COMMAND;
		}
		(*res)[len] = 0;
	}
	
	return 0;
}

static
int deserialize_additional_data(worker_st* ws)
{
int ret;
uint8_t len;
unsigned i;

	/* IPV4 DNS */
	ret = read_str_value_length(ws, &ws->ipv4_dns);
	if (ret < 0)
		return ret;

	/* IPV6 DNS */
	ret = read_str_value_length(ws, &ws->ipv6_dns);
	if (ret < 0)
		return ret;

	/* IPV4 NBNS */
	ret = read_str_value_length(ws, &ws->ipv4_nbns);
	if (ret < 0)
		return ret;

	/* IPV6 NBNS */
	ret = read_str_value_length(ws, &ws->ipv6_nbns);
	if (ret < 0)
		return ret;

	/* IPV4 netmask */
	ret = read_str_value_length(ws, &ws->ipv4_netmask);
	if (ret < 0)
		return ret;

	/* IPV6 netmask */
	ret = read_str_value_length(ws, &ws->ipv6_netmask);
	if (ret < 0)
		return ret;

	/* number of routes */
	ret = force_read(ws->cmd_fd, &len, 1);
	if (ret != 1) {
		oclog(ws, LOG_ERR, "Error receiving length-value from main (%d)", ret);
		return ERR_BAD_COMMAND;
	}
	ws->routes_size = len;

	/* routes */
	for (i=0;i<ws->routes_size;i++) {
		ret = force_read(ws->cmd_fd, &ws->routes[i].size, 1);
		if (ret != 1) {
			oclog(ws, LOG_ERR, "Error received route size from main (%d)", ret);
			return ERR_BAD_COMMAND;
		}

		ws->routes[i].route = malloc(ws->routes[i].size+1);
		if (ws->routes[i].route == NULL)
			return ERR_MEM;

		ret = force_read(ws->cmd_fd, ws->routes[i].route, ws->routes[i].size);
		if (ret != ws->routes[i].size) {
			oclog(ws, LOG_ERR, "Error received routes from main (%d)", ret);
			return ERR_BAD_COMMAND;
		}
		ws->routes[i].route[ws->routes[i].size] = 0;
	}
	
	return 0;
}

static int recv_auth_reply(worker_st *ws, struct cmd_auth_reply_st *resp)
{
	struct iovec iov[2];
	uint8_t cmd = 0;
	struct msghdr hdr;
	int ret, cmdlen;
	union {
		struct cmsghdr    cm;
		char              control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr  *cmptr;
	
	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = resp;
	iov[1].iov_len = sizeof(*resp);
	
	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2 + MAX_ROUTES;

	hdr.msg_control = control_un.control;
	hdr.msg_controllen = sizeof(control_un.control);

	ret = recvmsg( ws->cmd_fd, &hdr, 0);
	
	cmdlen = ret;
	
	if (cmdlen < 2) {
		oclog(ws, LOG_ERR, "Received incorrect data (%d, expected %d) from main", cmdlen, (int)2);
		return ERR_AUTH_FAIL;
	}
	if (cmd != AUTH_REP)
		return ERR_AUTH_FAIL;
		
	cmdlen--;

	switch(resp->reply) {
		case REP_AUTH_MSG:
			return ERR_AUTH_CONTINUE;
		case REP_AUTH_OK:
			if (cmdlen < sizeof(*resp)) {
				oclog(ws, LOG_ERR, "Received incorrect data (%d, expected %d) from main", ret, (int)sizeof(*resp)+1);
				return ERR_AUTH_FAIL;
			}

			if ( (cmptr = CMSG_FIRSTHDR(&hdr)) != NULL && cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
				if (cmptr->cmsg_level != SOL_SOCKET)
					return -1;
				if (cmptr->cmsg_type != SCM_RIGHTS)
					return ERR_AUTH_FAIL;
				
				memcpy(&ws->tun_fd, CMSG_DATA(cmptr), sizeof(int));
				memcpy(ws->tun_name, resp->data.ok.vname, sizeof(ws->tun_name));
				memcpy(ws->username, resp->data.ok.user, sizeof(ws->username));
				memcpy(ws->cookie, resp->data.ok.cookie, sizeof(ws->cookie));
				memcpy(ws->session_id, resp->data.ok.session_id, sizeof(ws->session_id));

				/* Read any additional data */
				
				ret = deserialize_additional_data(ws);
				if (ret < 0)
					return ret;
					
			} else
				return ERR_AUTH_FAIL;
			break;
		default:
			return ERR_AUTH_FAIL;
	}
	
	return 0;
}

/* grabs the username from the session certificate */
static
int get_cert_info(worker_st *ws, char* user, unsigned user_size,
				char* group, unsigned group_size)
{
const gnutls_datum_t * cert;
unsigned int ncerts;
int ret;

	/* this is superflous. Verification has already been performed 
	 * during handshake. */
	cert = gnutls_certificate_get_peers (ws->session, &ncerts);

	if (cert == NULL) {
		return -1;
	}
		
	ret = get_cert_names(ws, cert, user, user_size, group, group_size);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "Cannot get username (%s) from certificate", ws->config->cert_user_oid);
		return -1;
	}

	return 0;
}

/* sends an authentication request to main thread and waits for
 * a reply. 
 * Returns 0 on success, AUTH_ERR_CONTINUE on partial success (must
 * be called again in that case) and a negative error code on other errors.
 */
static int auth_user_pass(worker_st *ws, struct cmd_auth_req_st* areq)
{
int ret;
	
	oclog(ws, LOG_DEBUG, "sending auth request");

	ret = send_auth_req(ws->cmd_fd, areq);
	if (ret < 0)
		return ret;
	
	return 0;
}

/* sends a cookie authentication request to main thread and waits for
 * a reply.
 * Returns 0 on success.
 */
int auth_cookie(worker_st *ws, void* cookie, size_t cookie_size)
{
int ret;
struct cmd_auth_cookie_req_st areq;
struct cmd_auth_reply_st resp;

	memset(&areq, 0, sizeof(areq));

	if (cookie_size != sizeof(areq.cookie))
		return -1;

	if ((ws->config->auth_types & AUTH_TYPE_CERTIFICATE) && ws->config->force_cert_auth != 0) {
		if (ws->cert_auth_ok == 0) {
			oclog(ws, LOG_INFO, "no certificate provided for cookie authentication");
			return -1;
		}

		ret = get_cert_info(ws, areq.cert_user, sizeof(areq.cert_user),
					areq.cert_group, sizeof(areq.cert_group));
		if (ret < 0)
			return -1;

		areq.tls_auth_ok = 1;
	}

	memcpy(areq.cookie, cookie, sizeof(areq.cookie));

	oclog(ws, LOG_DEBUG, "sending cookie authentication request");
	ret = send_auth_cookie_req(ws->cmd_fd, &areq);
	if (ret < 0)
		return ret;

	return recv_auth_reply(ws, &resp);
}

int post_common_handler(worker_st *ws, unsigned http_ver)
{
int ret, size;
char str_cookie[2*COOKIE_SIZE+1];
char *p;
unsigned i;
char msg[MAX_BANNER_SIZE+32];

	p = str_cookie;
	for (i=0;i<sizeof(ws->cookie);i++) {
		sprintf(p, "%.2x", (unsigned int)ws->cookie[i]);
		p+=2;
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
		size = snprintf(msg, sizeof(msg), "<banner>%s</banner>", ws->config->banner);
		if (size <= 0)
			return -1;
	} else {
		msg[0] = 0;
		size = 0;
	}

	size += (sizeof(SUCCESS_MSG_HEAD)-1) + (sizeof(SUCCESS_MSG_FOOT)-1);

        ret = tls_printf(ws->session, "Content-Length: %u\r\n", (unsigned)size);
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret = tls_printf(ws->session, "Set-Cookie: webvpn=%s;Max-Age=%u\r\n", str_cookie, (unsigned)ws->config->cookie_validity);
	if (ret < 0)
		return -1;

#ifdef ANYCONNECT_CLIENT_COMPAT
        ret = tls_puts(ws->session, "Set-Cookie: webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; secure\r\n");
       	if (ret < 0)
       		return -1;

	if (ws->config->xml_config_file) {
		ret = tls_printf(ws->session, "Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:%s&lu:/+CSCOT+/translation-table?textdomain%%3DAnyConnect%%26type%%3Dmanifest&fu:profiles%%2F%s&fh:%s; path=/; secure\r\n", 
		        ws->config->cert_hash,
		        ws->config->xml_config_file,
		        ws->config->xml_config_hash);
	} else {
		ret = tls_printf(ws->session, "Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:%s; path=/; secure\r\n", 
		        ws->config->cert_hash);
	}

	if (ret < 0)
		return -1;
#endif

	ret = tls_printf(ws->session, "\r\n"SUCCESS_MSG_HEAD"%s"SUCCESS_MSG_FOOT, msg);
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
int read_user_pass(worker_st *ws, char* body, unsigned body_length, char** username, char** password)
{
	char *p;
	
	if (memmem(body, body_length, "<?xml", 5) != 0) {
		oclog(ws, LOG_DEBUG, "POST body: '%.*s'", body_length, body);

		if (username != NULL) {
			/* body should contain <username>test</username><password>test</password> */
			*username = memmem(body, body_length, XMLUSER, sizeof(XMLUSER)-1);
			if (*username == NULL) {
				return -1;
			}
			*username += sizeof(XMLUSER)-1;
		}

		if (password != NULL) {
        		*password = memmem(body, body_length, XMLPASS, sizeof(XMLPASS)-1);
	        	if (*password == NULL) {
	        		return -1;
	        	}
	        	*password += sizeof(XMLPASS)-1;
                }
	
		/* modify body */
		if (username != NULL) {
			p = *username;
			while(*p != 0) {
				if (*p == '<' && (strncmp(p, XMLUSER_END, sizeof(XMLUSER_END)-1) == 0)) {
					*p = 0;
					break;
				}
				p++;
			}

			*username = unescape_html(*username, strlen(*username), NULL);
		}

		if (password != NULL) {
        		p = *password;
        		while(*p != 0) {
        			if (*p == '<' && (strncmp(p, XMLPASS_END, sizeof(XMLPASS_END)-1) == 0)) {
        				*p = 0;
        				break;
        			}
        			p++;

        		}

			*password = unescape_html(*password, strlen(*password), NULL);
                }
	
	} else { /* non-xml version */
		/* body should be "username=test&password=test" */
		if (username != NULL) {
			*username = memmem(body, body_length, "username=", sizeof("username=")-1);
			if (*username == NULL) {
				return -1;
			}
			*username += sizeof("username=")-1;
		}

		if (password != NULL) {
        		*password = memmem(body, body_length, "password=", sizeof("password=")-1);
        		if (*password == NULL) {
        			return -1;
        		}
        		*password += sizeof("password=")-1;
                }
	
		/* modify body */
		if (username != NULL) {
			p = *username;
			while(*p != 0) {
				if (*p == '&') {
					*p = 0;
					break;
				}
				p++;
			}
			
			*username = unescape_url(*username, strlen(*username), NULL);
		}

		if (password != NULL) {
        		p = *password;
        		while(*p != 0) {
        			if (*p == '&') {
        				*p = 0;
        				break;
        			}
        			p++;
        		}

			*password = unescape_url(*password, strlen(*password), NULL);
                }
	}
	
	if (username != NULL && *username == NULL)
		return -1;

	if (password != NULL && *password == NULL)
		return -1;
	
	return 0;
}

int post_auth_handler(worker_st *ws, unsigned http_ver)
{
int ret;
struct http_req_st *req = &ws->req;
const char* reason = "Authentication failed";
char * username = NULL;
char * password = NULL;
struct cmd_auth_reply_st resp;

	if (ws->auth_state == S_AUTH_INACTIVE) {
		struct cmd_auth_init_st areq;

		memset(&areq, 0, sizeof(areq));

		if (ws->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
			ret = read_user_pass(ws, req->body, req->body_length, &username, NULL);
			if (ret < 0)
				goto ask_auth;

			snprintf(areq.user, sizeof(areq.user), "%s", username);
			free(username);
			areq.user_present = 1;
		}

		if (ws->config->auth_types & AUTH_TYPE_CERTIFICATE) {
			if (ws->cert_auth_ok == 0) {
				oclog(ws, LOG_INFO, "no certificate provided for authentication");
				return -1;
			}

			ret = get_cert_info(ws, areq.cert_user, sizeof(areq.cert_user),
						areq.cert_group, sizeof(areq.cert_group));
			if (ret < 0)
				return -1;

			areq.tls_auth_ok = 1;
		}

		if (req->hostname[0] != 0) {
			memcpy(areq.hostname, req->hostname, sizeof(areq.hostname));
		}

		ret = send_auth_init(ws->cmd_fd, &areq);
		if (ret < 0)
			goto auth_fail;
		
		ws->auth_state = S_AUTH_INIT;
	} else {
		struct cmd_auth_req_st areq;

		if (ws->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
			memset(&areq, 0, sizeof(areq));

			ret = read_user_pass(ws, req->body, req->body_length, NULL, &password);
			if (ret < 0)
				goto ask_auth;

			areq.pass_size = snprintf(areq.pass, sizeof(areq.pass), "%s", password);
			free(password);

			ret = auth_user_pass(ws, &areq);
			if (ret < 0)
				goto auth_fail;
		
			ws->auth_state = S_AUTH_REQ;
		} else
			goto auth_fail;
	}

	ret = recv_auth_reply(ws, &resp);
	if (ret == ERR_AUTH_CONTINUE) {
		ws->auth_state = S_AUTH_REQ;
		return get_auth_handler2(ws, http_ver, resp.data.msg);
        } else if (ret < 0)
		goto auth_fail;

	oclog(ws, LOG_INFO, "User '%s' logged in", ws->username);
	ws->auth_state = S_AUTH_COMPLETE;

	return post_common_handler(ws, http_ver);

ask_auth:
	return get_auth_handler(ws, http_ver);

auth_fail:
	tls_printf(ws->session,
		   "HTTP/1.1 503 Service Unavailable\r\nX-Reason: %s\r\n\r\n", reason);
	tls_fatal_close(ws->session, GNUTLS_A_ACCESS_DENIED);
	exit(1);
}
