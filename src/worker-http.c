/*
 * Copyright (C) 2015 Red Hat
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
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifdef ENABLE_COMPRESSION
# ifdef HAVE_LZ4
#  include <lz4.h>
# endif
# include "lzs.h"
#endif

#include <nettle/base64.h>
#include <base64-helper.h>
#include <c-strcase.h>
#include <c-ctype.h>

#include <vpn.h>
#include <worker.h>

#define CS_AES128_GCM "OC-DTLS1_2-AES128-GCM"
#define CS_AES256_GCM "OC-DTLS1_2-AES256-GCM"

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
	LL("/VPN", get_auth_handler, post_auth_handler),
	LL("/cert.pem", get_cert_handler, NULL),
	LL("/cert.cer", get_cert_der_handler, NULL),
	LL("/ca.pem", get_ca_handler, NULL),
	LL("/ca.cer", get_ca_der_handler, NULL),
	LL_DIR("/profiles", get_config_handler, NULL),
#ifdef ANYCONNECT_CLIENT_COMPAT
	LL("/1/index.html", get_empty_handler, NULL),
	LL("/1/Linux", get_empty_handler, NULL),
	LL("/1/Linux_64", get_empty_handler, NULL),
	LL("/1/Windows", get_empty_handler, NULL),
	LL("/1/Darwin_i386", get_empty_handler, NULL),
	LL("/1/binaries/vpndownloader.sh", get_dl_handler, NULL),
	LL("/1/VPNManifest.xml", get_string_handler, NULL),
	LL("/1/binaries/update.txt", get_string_handler, NULL),

	LL("/+CSCOT+/", get_string_handler, NULL),
	LL("/logout", get_empty_handler, NULL),
#endif
	{NULL, 0, 0, NULL, NULL}
};

/* Consider switching to gperf when this table grows significantly.
 * These tables are used for the custom DTLS cipher negotiation via
 * HTTP headers (WTF), and the compression negotiation.
 */
static const dtls_ciphersuite_st ciphersuites[] = {
	{
	 .oc_name = CS_AES128_GCM,
	 .gnutls_name =
	 "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL",
	 .gnutls_version = GNUTLS_DTLS1_2,
	 .gnutls_mac = GNUTLS_MAC_AEAD,
	 .gnutls_kx = GNUTLS_KX_RSA,
	 .gnutls_cipher = GNUTLS_CIPHER_AES_128_GCM,
	 .txt_version = "3.2.7",
	 .server_prio = 90},
	{
	 .oc_name = CS_AES256_GCM,
	 .gnutls_name =
	 "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-GCM:+AEAD:+RSA:%COMPAT:+SIGN-ALL",
	 .gnutls_version = GNUTLS_DTLS1_2,
	 .gnutls_mac = GNUTLS_MAC_AEAD,
	 .gnutls_kx = GNUTLS_KX_RSA,
	 .gnutls_cipher = GNUTLS_CIPHER_AES_256_GCM,
	 .server_prio = 80,
	 .txt_version = "3.2.7",
	 },
	{
	 .oc_name = "AES128-SHA",
	 .gnutls_name =
	 "NONE:+VERS-DTLS0.9:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:%COMPAT",
	 .gnutls_version = GNUTLS_DTLS0_9,
	 .gnutls_mac = GNUTLS_MAC_SHA1,
	 .gnutls_kx = GNUTLS_KX_RSA,
	 .gnutls_cipher = GNUTLS_CIPHER_AES_128_CBC,
	 .server_prio = 50,
	 },
	{
	 .oc_name = "DES-CBC3-SHA",
	 .gnutls_name =
	 "NONE:+VERS-DTLS0.9:+COMP-NULL:+3DES-CBC:+SHA1:+RSA:%COMPAT",
	 .gnutls_version = GNUTLS_DTLS0_9,
	 .gnutls_mac = GNUTLS_MAC_SHA1,
	 .gnutls_kx = GNUTLS_KX_RSA,
	 .gnutls_cipher = GNUTLS_CIPHER_3DES_CBC,
	 .server_prio = 1,
	 }
};

#ifdef HAVE_LZ4
/* Wrappers over LZ4 functions */
static
int lz4_decompress(void *dst, int dstlen, const void *src, int srclen)
{
	return LZ4_decompress_safe(src, dst, srclen, dstlen);
}

static
int lz4_compress(void *dst, int dstlen, const void *src, int srclen)
{
	/* we intentionally restrict output to srclen so that
	 * compression fails early for packets that expand. */
	return LZ4_compress_limitedOutput(src, dst, srclen, srclen);
}
#endif

#ifdef ENABLE_COMPRESSION
struct compression_method_st comp_methods[] = {
#ifdef HAVE_LZ4
	{
		.id = OC_COMP_LZ4,
		.name = "oc-lz4",
		.decompress = lz4_decompress,
		.compress = lz4_compress,
		.server_prio = 90,
	},
#endif
	{
		.id = OC_COMP_LZS,
		.name = "lzs",
		.decompress = (decompress_fn)lzs_decompress,
		.compress = (compress_fn)lzs_compress,
		.server_prio = 80,
	}
};
#endif

static
void header_value_check(struct worker_st *ws, struct http_req_st *req)
{
	unsigned tmplen, i;
	int ret;
	size_t nlen, value_length;
	char *token, *value;
	char *str, *p;
	const dtls_ciphersuite_st *cand = NULL;
	const compression_method_st *comp_cand = NULL;
	const compression_method_st **selected_comp;
	gnutls_cipher_algorithm_t want_cipher;
	gnutls_mac_algorithm_t want_mac;

	if (req->value.length <= 0)
		return;

	if (ws->perm_config->debug < DEBUG_SENSITIVE &&
		((req->header.length == 6 && strncasecmp((char*)req->header.data, "Cookie", 6) == 0) ||
		(req->header.length == 20 && strncasecmp((char*)req->header.data, "X-DTLS-Master-Secret", 20) == 0)))
		oclog(ws, LOG_HTTP_DEBUG, "HTTP processing: %.*s: (censored)", (int)req->header.length,
		      req->header.data);
	else
		oclog(ws, LOG_HTTP_DEBUG, "HTTP processing: %.*s: %.*s", (int)req->header.length,
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
		if (req->use_psk || !ws->config->dtls_legacy) /* ignored */
			break;

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

		/* check validity */
		if (!valid_hostname(req->hostname)) {
			oclog(ws, LOG_HTTP_DEBUG, "Skipping invalid hostname '%s'", req->hostname);
			req->hostname[0] = 0;
		}

		break;
	case HEADER_DEVICE_TYPE:
		if (value_length + 1 > sizeof(req->devtype)) {
			req->devtype[0] = 0;
			goto cleanup;
		}
		memcpy(req->devtype, value, value_length);
		req->devtype[value_length] = 0;

		oclog(ws, LOG_DEBUG,
		      "Device-type: '%s'", value);
		break;
	case HEADER_PLATFORM:
		if (strncasecmp(value, "apple-ios", 9) == 0 ||
		    strncasecmp(value, "android", 7) == 0) {

			oclog(ws, LOG_DEBUG,
			      "Platform: '%s' (mobile)", value);
			req->is_mobile = 1;
		} else {
			oclog(ws, LOG_DEBUG,
			      "Platform: '%s'", value);
		}
		break;
	case HEADER_SUPPORT_SPNEGO:
		ws_switch_auth_to(ws, AUTH_TYPE_GSSAPI);
		req->spnego_set = 1;
		break;
	case HEADER_AUTHORIZATION:
		if (req->authorization != NULL)
			talloc_free(req->authorization);
		req->authorization = value;
		req->authorization_size = value_length;
		value = NULL;
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

		if (strncasecmp(req->user_agent, "Open AnyConnect VPN Agent v", 27) == 0) {
			unsigned version = atoi(&req->user_agent[27]);
			if (version <= 3)
				req->user_agent_type = AGENT_OPENCONNECT_V3;
			else
				req->user_agent_type = AGENT_OPENCONNECT;
		}
		break;

	case HEADER_DTLS_CIPHERSUITE:
		req->selected_ciphersuite = NULL;
		str = (char *)value;

		p = strstr(str, DTLS_PROTO_INDICATOR);
		if (p != NULL && (p[sizeof(DTLS_PROTO_INDICATOR)-1] == 0 || p[sizeof(DTLS_PROTO_INDICATOR)-1] == ':')) {
			/* OpenConnect DTLS setup was detected. */
			if (ws->config->dtls_psk) {
				req->use_psk = 1;
				req->master_secret_set = 1; /* we don't need it */
				break;
			}
		}

		if (ws->session != NULL) {
			want_mac = gnutls_mac_get(ws->session);
			want_cipher = gnutls_cipher_get(ws->session);
		} else {
			want_mac = -1;
			want_cipher = -1;
		}

		while ((token = strtok(str, ":")) != NULL) {
			for (i = 0;
			     i < sizeof(ciphersuites) / sizeof(ciphersuites[0]);
			     i++) {
				if (strcmp(token, ciphersuites[i].oc_name) == 0) {
					if (ciphersuites[i].txt_version != NULL && gnutls_check_version(ciphersuites[i].txt_version) == NULL) {
						continue; /* not supported */
					}

					if (cand == NULL ||
					    cand->server_prio < ciphersuites[i].server_prio ||
					    (want_cipher != -1 && want_cipher == ciphersuites[i].gnutls_cipher &&
					     want_mac == ciphersuites[i].gnutls_mac)) {
						cand =
						    &ciphersuites[i];

						/* if our candidate matches the TLS session
						 * ciphersuite, we are finished */
						if (want_cipher != -1) {
							if (want_cipher == cand->gnutls_cipher &&
							    want_mac == cand->gnutls_mac)
							    goto ciphersuite_finish;
						}
					}
				}
			}
			str = NULL;
		}
 ciphersuite_finish:
	        req->selected_ciphersuite = cand;

		break;
#ifdef ENABLE_COMPRESSION
	case HEADER_DTLS_ENCODING:
	case HEADER_CSTP_ENCODING:
	        if (ws->config->enable_compression == 0)
	        	break;

		if (req->next_header == HEADER_DTLS_ENCODING)
			selected_comp = &ws->dtls_selected_comp;
		else
			selected_comp = &ws->cstp_selected_comp;
	        *selected_comp = NULL;

		str = (char *)value;
		while ((token = strtok(str, ",")) != NULL) {
			for (i = 0;
			     i < sizeof(comp_methods) / sizeof(comp_methods[0]);
			     i++) {
				if (c_strcasecmp(token, comp_methods[i].name) == 0) {
					if (comp_cand == NULL ||
					    comp_cand->server_prio <
					    comp_methods[i].server_prio) {
						comp_cand =
						    &comp_methods[i];
					}
				}
			}
			str = NULL;
		}
	        *selected_comp = comp_cand;
		break;
#endif

	case HEADER_CSTP_BASE_MTU:
		req->link_mtu = atoi((char *)value);
		break;
	case HEADER_CSTP_MTU:
		req->tunnel_mtu = atoi((char *)value);
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
		/* don't bother parsing cookies if we are already authenticated */
		if (ws->auth_state > S_AUTH_COOKIE)
			break;

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

				/* we allow for BASE64_DECODE_LENGTH reporting few bytes more
				 * than the expected */
				nlen = BASE64_DECODE_LENGTH(tmplen);
				if (nlen < sizeof(ws->cookie) || nlen > sizeof(ws->cookie)+8)
					return;

				/* we assume that - should be build time optimized */
				if (sizeof(ws->buffer) < sizeof(ws->cookie)+8)
					abort();

				ret =
				    oc_base64_decode((uint8_t*)p, tmplen,
						  ws->buffer, &nlen);
				if (ret == 0 || nlen != sizeof(ws->cookie)) {
					oclog(ws, LOG_INFO,
					      "could not decode cookie: %.*s",
					      tmplen, p);
					ws->cookie_set = 0;
				} else {
					memcpy(ws->cookie, ws->buffer, sizeof(ws->cookie));
					ws->auth_state = S_AUTH_COOKIE;
					ws->cookie_set = 1;
				}
			} else if (strncmp(p, "webvpncontext=", 14) == 0) {
				p += 14;
				tmplen -= 14;

				while (tmplen > 1 && c_isspace(p[tmplen - 1])) {
					tmplen--;
				}

				nlen = BASE64_DECODE_LENGTH(tmplen);
				ret =
				    oc_base64_decode((uint8_t*)p, tmplen,
						  ws->sid, &nlen);
				if (ret == 0 || nlen != sizeof(ws->sid)) {
					oclog(ws, LOG_SENSITIVE,
					      "could not decode sid: %.*s",
					      tmplen, p);
					ws->sid_set = 0;
				} else {
					ws->sid_set = 1;
					oclog(ws, LOG_SENSITIVE,
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

url_handler_fn http_get_url_handler(const char *url)
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

url_handler_fn http_post_url_handler(struct worker_st *ws, const char *url)
{
	const struct known_urls_st *p;
	unsigned i;

	p = known_urls;
	do {
		if (p->url != NULL && strcmp(p->url, url) == 0)
			return p->post_handler;
		p++;
	} while (p->url != NULL);

	for (i=0;i<ws->config->kkdcp_size;i++) {
		if (ws->config->kkdcp[i].url && strcmp(ws->config->kkdcp[i].url, url) == 0)
			return post_kkdcp_handler;
	}

	return NULL;
}

int http_url_cb(http_parser * parser, const char *at, size_t length)
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

int http_header_field_cb(http_parser * parser, const char *at, size_t length)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;
	int ret;

	if (req->header_state != HTTP_HEADER_RECV) {
		/* handle value */
		if (req->header_state == HTTP_HEADER_VALUE_RECV)
			header_value_check(ws, req);
		req->header_state = HTTP_HEADER_RECV;
		str_reset(&req->header);
	}

	ret = str_append_data(&req->header, at, length);
	if (ret < 0)
		return ret;

	return 0;
}

/* include hash table of headers */
#include "http-heads.h"

static void header_check(struct http_req_st *req)
{
	const struct http_headers_st *p;

	p = in_word_set((char *)req->header.data, req->header.length);
	if (p != NULL) {
		req->next_header = p->id;
		return;
	}
	req->next_header = 0;
}

int http_header_value_cb(http_parser * parser, const char *at, size_t length)
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

int http_header_complete_cb(http_parser * parser)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;

	/* handle header value */
	header_value_check(ws, req);

	if (ws->selected_auth->type & AUTH_TYPE_GSSAPI && ws->auth_state == S_AUTH_INACTIVE &&
	    req->spnego_set == 0) {
		/* client retried getting the form without the SPNEGO header, probably
		 * wants a fallback authentication method */
		if (ws_switch_auth_to(ws, AUTH_TYPE_USERNAME_PASS) == 0)
			oclog(ws, LOG_INFO, "no fallback from gssapi authentication");
	}

	req->headers_complete = 1;
	return 0;
}

int http_message_complete_cb(http_parser * parser)
{
	struct worker_st *ws = parser->data;
	struct http_req_st *req = &ws->req;

	req->message_complete = 1;
	return 0;
}

int http_body_cb(http_parser * parser, const char *at, size_t length)
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

void http_req_init(worker_st * ws)
{
	str_init(&ws->req.header, ws);
	str_init(&ws->req.value, ws);
}

void http_req_reset(worker_st * ws)
{
	ws->req.headers_complete = 0;
	ws->req.message_complete = 0;
	ws->req.body_length = 0;
	ws->req.spnego_set = 0;
	ws->req.url[0] = 0;

	ws->req.header_state = HTTP_HEADER_INIT;
	str_reset(&ws->req.header);
	str_reset(&ws->req.value);
}

void http_req_deinit(worker_st * ws)
{
	http_req_reset(ws);
	str_clear(&ws->req.header);
	str_clear(&ws->req.value);
	talloc_free(ws->req.body);
	ws->req.body = NULL;
}

