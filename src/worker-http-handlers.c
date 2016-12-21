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

#include <vpn.h>
#include <worker.h>
#include <tlslib.h>

#define HTML_404 "<html><body><h1>404 Not Found</h1></body></html>\r\n"

int response_404(worker_st *ws, unsigned http_ver)
{
	if (cstp_printf(ws, "HTTP/1.%u 404 Not found\r\n", http_ver) < 0 ||
	    cstp_printf(ws, "Content-length: %u\r\n", (unsigned)(sizeof(HTML_404) - 1)) < 0 ||
	    cstp_puts  (ws, "Connection: close\r\n\r\n") < 0 ||
	    cstp_puts  (ws, HTML_404) < 0)
		return -1;
	return 0;
}

static int send_headers(worker_st *ws, unsigned http_ver, const char *content_type,
			unsigned content_length)
{
	if (cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver) < 0 ||
	    cstp_puts  (ws, "Connection: Keep-Alive\r\n") < 0 ||
	    cstp_printf(ws, "Content-Type: %s\r\n", content_type) < 0 ||
	    cstp_puts  (ws, "X-Transcend-Version: 1\r\n") < 0 ||
	    cstp_printf(ws, "Content-Length: %u\r\n", content_length) < 0 ||
	    cstp_puts  (ws, "\r\n") < 0)
		return -1;
	return 0;
}

static int send_data(worker_st *ws, unsigned http_ver, const char *content_type,
		       const char *data, int content_length)
{
	/* don't bother uncorking on error - the connection will be closed anyway */
	cstp_cork(ws);
	if (send_headers(ws, http_ver, content_type, content_length) < 0 ||
	    cstp_send(ws, data, content_length) < 0 ||
	    cstp_uncork(ws) < 0)
		return -1;
	return 0;
}

int get_cert_handler(worker_st * ws, unsigned http_ver)
{
	if (ws->conn_type != SOCK_TYPE_UNIX) { /* we have TLS */
		const gnutls_datum_t *certs;
		gnutls_datum_t out = {NULL, 0};
		int ret;

		oclog(ws, LOG_DEBUG, "requested server certificate");

		certs = gnutls_certificate_get_ours(ws->session);
		if (certs == NULL) {
			return -1;
		}

		ret = gnutls_pem_base64_encode_alloc("CERTIFICATE", &certs[0], &out);
		if (ret < 0)
			return -1;

		ret = send_data(ws, http_ver, "application/x-pem-file", (char*)out.data, out.size);
		gnutls_free(out.data);

		return ret;
	} else {
		return -1;
	}
}
int get_cert_der_handler(worker_st * ws, unsigned http_ver)
{
	if (ws->conn_type != SOCK_TYPE_UNIX) { /* we have TLS */
		const gnutls_datum_t *certs;

		oclog(ws, LOG_DEBUG, "requested raw server certificate");

		certs = gnutls_certificate_get_ours(ws->session);
		if (certs == NULL) {
			return -1;
		}

		return send_data(ws, http_ver, "application/pkix-cert", (char*)certs[0].data, certs[0].size);
	} else {
		return -1;
	}
}


static
int ca_handler(worker_st * ws, unsigned http_ver, unsigned der)
{
#if GNUTLS_VERSION_NUMBER < 0x030205
	return -1;
#else
	if (ws->conn_type != SOCK_TYPE_UNIX) { /* we have TLS */
		const gnutls_datum_t *certs;
		gnutls_datum_t out = {NULL, 0}, tmpca;
		unsigned i;
		int ret;
		gnutls_x509_crt_t issuer = NULL, crt = NULL;

		oclog(ws, LOG_DEBUG, "requested server CA");

		certs = gnutls_certificate_get_ours(ws->session);
		if (certs == NULL) {
			oclog(ws, LOG_DEBUG, "could not obtain our cert");
			return -1;
		}

		ret = gnutls_x509_crt_init(&crt);
		if (ret < 0) {
			oclog(ws, LOG_DEBUG, "could not initialize cert");
			return -1;
		}

		ret = gnutls_x509_crt_init(&issuer);
		if (ret < 0) {
			oclog(ws, LOG_DEBUG, "could not initialize cert");
			ret = -1;
			goto cleanup;
		}

		ret = gnutls_x509_crt_import(crt, &certs[0], GNUTLS_X509_FMT_DER);
		if (ret < 0) {
			ret = -1;
			oclog(ws, LOG_DEBUG, "could not import our cert");
			goto cleanup;
		}

		for (i=0;i<8;i++) {
			ret = gnutls_certificate_get_crt_raw(ws->creds->xcred, i, 1, &tmpca);
			if (ret < 0) {
				goto cleanup;
			}

			ret = gnutls_x509_crt_import(issuer, &tmpca, GNUTLS_X509_FMT_DER);
			if (ret < 0) {
				ret = -1;
				oclog(ws, LOG_DEBUG, "could not import issuer cert");
				goto cleanup;
			}

			ret = gnutls_x509_crt_check_issuer(crt, issuer);
			if (ret != 0) {
				ret = gnutls_x509_crt_export2(issuer, der?GNUTLS_X509_FMT_DER:GNUTLS_X509_FMT_PEM, &out);
				if (ret < 0) {
					ret = -1;
					oclog(ws, LOG_DEBUG, "could not export issuer of cert");
					goto cleanup;
				}
				break;
			}

			gnutls_x509_crt_deinit(issuer);
			issuer = NULL;
		}

		ret = send_data(ws, http_ver, "application/pkix-cert", (char*)out.data, out.size);

 cleanup:
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			oclog(ws, LOG_DEBUG, "could not get CA; does the server cert list contain the CA certificate?");
			ret = -1;
		}

		if (crt)
			gnutls_x509_crt_deinit(crt);
		if (issuer)
			gnutls_x509_crt_deinit(issuer);
		gnutls_free(out.data);

		return ret;
	} else {
		return -1;
	}
#endif
}

int get_ca_handler(worker_st * ws, unsigned http_ver)
{
	return ca_handler(ws, http_ver, 0);
}

int get_ca_der_handler(worker_st * ws, unsigned http_ver)
{
	return ca_handler(ws, http_ver, 1);
}

int get_config_handler(worker_st *ws, unsigned http_ver)
{
	int ret;
	struct stat st;

	oclog(ws, LOG_HTTP_DEBUG, "requested config: %s", ws->req.url); 

	cookie_authenticate_or_exit(ws);

	if (ws->user_config->xml_config_file == NULL) {
		oclog(ws, LOG_INFO, "requested config but no config file is set");
		response_404(ws, http_ver);
		return -1;
	}
	
	ret = stat(ws->user_config->xml_config_file, &st);
	if (ret == -1) {
		oclog(ws, LOG_INFO, "cannot load config file '%s'", ws->user_config->xml_config_file);
		response_404(ws, http_ver);
		return -1;
	}

	cstp_cork(ws);
	if (send_headers(ws, http_ver, "text/xml", (unsigned)st.st_size) < 0 ||
	    cstp_uncork(ws) < 0)
		return -1;

	ret = cstp_send_file(ws, ws->user_config->xml_config_file);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error sending file '%s': %s", ws->user_config->xml_config_file, gnutls_strerror(ret));
		return -1;
	}

	return 0;
}

#ifdef ANYCONNECT_CLIENT_COMPAT
#define VPN_VERSION "0,0,0000\n"
#define XML_START "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n</vpn>\n"

int get_string_handler(worker_st *ws, unsigned http_ver)
{
	oclog(ws, LOG_HTTP_DEBUG, "requested fixed string: %s", ws->req.url); 
	if (!strcmp(ws->req.url, "/1/binaries/update.txt")) {
		return send_data(ws, http_ver, "text/xml", VPN_VERSION,
				   sizeof(VPN_VERSION) - 1);
	} else {
		return send_data(ws, http_ver, "text/xml", XML_START,
				   sizeof(XML_START) - 1);
	}
}

#define SH_SCRIPT "#!/bin/sh\n\n" \
	"exit 0"

int get_dl_handler(worker_st *ws, unsigned http_ver)
{
	oclog(ws, LOG_HTTP_DEBUG, "requested downloader: %s", ws->req.url); 
	return send_data(ws, http_ver, "application/x-shellscript", SH_SCRIPT,
			   sizeof(SH_SCRIPT) - 1);
}

#define EMPTY_MSG "<html></html>\n"

int get_empty_handler(worker_st *ws, unsigned http_ver)
{
	return send_data(ws, http_ver, "text/html", EMPTY_MSG,
			   sizeof(EMPTY_MSG) - 1);
}

#endif

