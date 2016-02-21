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

#ifdef ANYCONNECT_CLIENT_COMPAT
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

static int send_string(worker_st *ws, unsigned http_ver, const char *content_type,
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

#define VPN_VERSION "0,0,0000\n"
#define XML_START "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n</vpn>\n"

int get_string_handler(worker_st *ws, unsigned http_ver)
{
	oclog(ws, LOG_HTTP_DEBUG, "requested fixed string: %s", ws->req.url); 
	if (!strcmp(ws->req.url, "/1/binaries/update.txt")) {
		return send_string(ws, http_ver, "text/xml", VPN_VERSION,
				   sizeof(VPN_VERSION) - 1);
	} else {
		return send_string(ws, http_ver, "text/xml", XML_START,
				   sizeof(XML_START) - 1);
	}
}

#define SH_SCRIPT "#!/bin/sh\n\n" \
	"exit 0"

int get_dl_handler(worker_st *ws, unsigned http_ver)
{
	oclog(ws, LOG_HTTP_DEBUG, "requested downloader: %s", ws->req.url); 
	return send_string(ws, http_ver, "application/x-shellscript", SH_SCRIPT,
			   sizeof(SH_SCRIPT) - 1);
}

#define EMPTY_MSG "<html></html>\n"

int get_empty_handler(worker_st *ws, unsigned http_ver)
{
	return send_string(ws, http_ver, "text/html", EMPTY_MSG,
			   sizeof(EMPTY_MSG) - 1);
}

#endif

