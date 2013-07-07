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
#include <worker.h>
#include <cookies.h>
#include <tlslib.h>

#ifdef ANYCONNECT_CLIENT_COMPAT
const char empty_msg[] = "<html></html>\n";

int get_config_handler(worker_st *ws, unsigned http_ver)
{
int ret;
struct stat st;

	oclog(ws, LOG_DEBUG, "requested config: %s", ws->req.url); 
	if (ws->config->xml_config_file == NULL) {
		oclog(ws, LOG_INFO, "requested config but no config file is set");
		tls_printf(ws->session, "HTTP/1.%u 404 Not found\r\n", http_ver);
		return -1;
	}
	
	ret = stat( ws->config->xml_config_file, &st);
	if (ret == -1) {
		oclog(ws, LOG_INFO, "cannot load config file '%s'", ws->config->xml_config_file);
		tls_printf(ws->session, "HTTP/1.%u 404 Not found\r\n", http_ver);
		return -1;
	}

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

	ret = tls_puts(ws->session, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret = tls_printf(ws->session, "Content-Length: %u\r\n", (unsigned)st.st_size);
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "\r\n");
	if (ret < 0)
		return -1;

	ret = tls_uncork(ws->session);
	if (ret < 0)
		return -1;
	
	ret = tls_send_file(ws->session, ws->config->xml_config_file);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error sending file '%s': %s", ws->config->xml_config_file, gnutls_strerror(ret));
		return -1;
	}

	return 0;
}

int get_string_handler(worker_st *ws, unsigned http_ver)
{
int ret;
const char *data;
int len;

	oclog(ws, LOG_DEBUG, "requested fixed string: %s", ws->req.url); 
	if (!strcmp(ws->req.url, "/2/binaries/update.txt"))
		data = "0,0,0000\n";
	else
		data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<vpn rev=\"1.0\">\n</vpn>\n";
	len = strlen(data);

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

	ret = tls_puts(ws->session, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret = tls_printf(ws->session, "Content-Length: %d\r\n\r\n", len);
	if (ret < 0)
		return -1;
		
	ret = tls_send(ws->session, data, len);
	if (ret < 0)
		return -1;

	ret = tls_uncork(ws->session);
	if (ret < 0)
		return -1;
	
	return 0;
}

int get_empty_handler(worker_st *ws, unsigned http_ver)
{
int ret;

	tls_cork(ws->session);
	ret = tls_printf(ws->session, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "Connection: Keep-Alive\r\n");
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "Content-Type: text/html\r\n");
	if (ret < 0)
		return -1;

	ret = tls_printf(ws->session, "Content-Length: %u\r\n", (unsigned int)sizeof(empty_msg)-1);
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "X-Transcend-Version: 1\r\n");
	if (ret < 0)
		return -1;

	ret = tls_puts(ws->session, "\r\n");
	if (ret < 0)
		return -1;

	ret = tls_send(ws->session, empty_msg, sizeof(empty_msg)-1);
	if (ret < 0)
		return -1;
	
	ret = tls_uncork(ws->session);
	if (ret < 0)
		return -1;
	
	return 0;
}

#endif
