/*
 * Copyright (C) 2013, 2014, 2015 Nikos Mavrogiannopoulos
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
#ifdef HAVE_LZ4
# include <lz4.h>
#endif
#include "lzs.h"

#include <base64.h>
#include <c-strcase.h>
#include <c-ctype.h>

#include <vpn.h>
#include <worker.h>
#include <cookies.h>
#include <tlslib.h>

#ifdef ANYCONNECT_CLIENT_COMPAT
const char empty_msg[] = "<html></html>\n";

int get_config_handler(worker_st *ws, unsigned http_ver)
{
int ret;
struct stat st;

	oclog(ws, LOG_HTTP_DEBUG, "requested config: %s", ws->req.url); 
	if (ws->config->xml_config_file == NULL) {
		oclog(ws, LOG_INFO, "requested config but no config file is set");
		cstp_printf(ws, "HTTP/1.%u 404 Not found\r\n", http_ver);
		return -1;
	}
	
	ret = stat( ws->config->xml_config_file, &st);
	if (ret == -1) {
		oclog(ws, LOG_INFO, "cannot load config file '%s'", ws->config->xml_config_file);
		cstp_printf(ws, "HTTP/1.%u 404 Not found\r\n", http_ver);
		return -1;
	}

	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Content-Type: text/xml\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_printf(ws, "Content-Length: %u\r\n", (unsigned)st.st_size);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_uncork(ws);
	if (ret < 0)
		return -1;
	
	ret = cstp_send_file(ws, ws->config->xml_config_file);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error sending file '%s': %s", ws->config->xml_config_file, gnutls_strerror(ret));
		return -1;
	}

	return 0;
}

#define VPN_VERSION "0,0,0000\n"
#define XML_START "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n</vpn>\n"

int get_string_handler(worker_st *ws, unsigned http_ver)
{
int ret;
const char *data;
int len;

	oclog(ws, LOG_HTTP_DEBUG, "requested fixed string: %s", ws->req.url); 
	if (!strcmp(ws->req.url, "/1/binaries/update.txt")) {
		data = VPN_VERSION;
		len = sizeof(VPN_VERSION)-1;
	} else {
		data = XML_START;
		len = sizeof(XML_START)-1;
	}

	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Content-Type: text/xml\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_printf(ws, "Content-Length: %d\r\n\r\n", len);
	if (ret < 0)
		return -1;
		
	ret = cstp_send(ws, data, len);
	if (ret < 0)
		return -1;

	ret = cstp_uncork(ws);
	if (ret < 0)
		return -1;
	
	return 0;
}

#define SH_SCRIPT "#!/bin/sh\n\n" \
	"exit 0"

int get_dl_handler(worker_st *ws, unsigned http_ver)
{
int ret;
const char *data;
int len;

	oclog(ws, LOG_HTTP_DEBUG, "requested downloader: %s", ws->req.url); 

	data = SH_SCRIPT;
	len = sizeof(SH_SCRIPT)-1;

	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Content-Type: application/x-shellscript\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_printf(ws, "Content-Length: %d\r\n\r\n", len);
	if (ret < 0)
		return -1;
		
	ret = cstp_send(ws, data, len);
	if (ret < 0)
		return -1;

	ret = cstp_uncork(ws);
	if (ret < 0)
		return -1;
	
	return 0;
}

int get_empty_handler(worker_st *ws, unsigned http_ver)
{
int ret;

	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "Content-Type: text/html\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_printf(ws, "Content-Length: %u\r\n", (unsigned int)sizeof(empty_msg)-1);
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_puts(ws, "\r\n");
	if (ret < 0)
		return -1;

	ret = cstp_send(ws, empty_msg, sizeof(empty_msg)-1);
	if (ret < 0)
		return -1;
	
	ret = cstp_uncork(ws);
	if (ret < 0)
		return -1;
	
	return 0;
}

#endif

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

#ifdef HAVE_LZ4
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


void header_value_check(struct worker_st *ws, struct http_req_st *req)
{
	unsigned tmplen, i;
	int ret;
	size_t nlen, value_length;
	char *token, *value;
	char *str, *p;
	const dtls_ciphersuite_st *cand = NULL;
	const compression_method_st *comp_cand = NULL;
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

	case HEADER_DTLS_ENCODING:
	        if (ws->config->disable_compression)
	        	break;

	        ws->dtls_selected_comp = NULL;

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
	        ws->dtls_selected_comp = comp_cand;

		break;

	case HEADER_CSTP_ENCODING:
	        if (ws->config->disable_compression)
	        	break;

	        ws->cstp_selected_comp = NULL;

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
	        ws->cstp_selected_comp = comp_cand;

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

