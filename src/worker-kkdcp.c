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

#include <vpn.h>
#include <worker.h>

int post_kkdcp_handler(worker_st *ws, unsigned http_ver)
{
	int ret, e, fd;
	struct http_req_st *req = &ws->req;
	unsigned i, length;
	kkdcp_st *handler = NULL;
	char buf[16*1024];
	const char *reason = "Unknown";

	for (i=0;i<ws->config->kkdcp_size;i++) {
		if (ws->config->kkdcp[i].url && strcmp(ws->config->kkdcp[i].url, req->url) == 0) {
			handler = &ws->config->kkdcp[i];
			break;
		}
	}

	if (handler == NULL) {
		oclog(ws, LOG_HTTP_DEBUG, "could not figure kkdcp handler for %s", req->url);
		return -1;
	}

	if (req->body_length == 0) {
		oclog(ws, LOG_HTTP_DEBUG, "empty body length for kkdcp handler %s", req->url);
		return -1;
	}

	oclog(ws, LOG_HTTP_DEBUG, "POST kkdcp data: %u bytes", (unsigned)req->body_length);

	fd = socket(handler->ai_family, handler->ai_socktype, handler->ai_protocol);
	if (fd == -1) {
		e = errno;
		oclog(ws, LOG_INFO, "kkdcp: socket error: %s", strerror(e));
		reason = "Socket error";
		goto fail;
	}

	ret = connect(fd, (struct sockaddr*)&handler->addr, handler->addr_len);
	if (ret == -1) {
		e = errno;
		oclog(ws, LOG_INFO, "kkdcp: connect error: %s", strerror(e));
		reason = "Connect error";
		goto fail;
	}

	ret = send(fd, req->body, req->body_length, 0);
	if (ret != req->body_length) {
		if (ret == -1) {
			e = errno;
			oclog(ws, LOG_INFO, "kkdcp: send error: %s", strerror(e));
		} else {
			oclog(ws, LOG_INFO, "kkdcp: send error: only %d were sent", ret);
		}
		reason = "Send error";
		goto fail;
	}

	ret = recv(fd, buf, sizeof(buf), 0);
	if (ret == -1) {
		e = errno;
		oclog(ws, LOG_INFO, "kkdcp: recv error: %s", strerror(e));
		reason = "Recv error";
		goto fail;
	}
	length = ret;

	cstp_cork(ws);
	ret = cstp_printf(ws, "HTTP/1.%u 200 OK\r\n", http_ver);
	if (ret < 0) {
		goto fail;
	}

	if (handler->content_type) {
		ret =
		    cstp_printf(ws, "Content-Type: %s\r\n", handler->content_type);
		if (ret < 0) {
			goto fail;
		}
	}

	ret =
	    cstp_printf(ws, "Content-Length: %u\r\n",
		       (unsigned int)length);
	if (ret < 0) {
		goto fail;
	}

	ret = cstp_puts(ws, "Connection: Keep-Alive\r\n");
	if (ret < 0) {
		goto fail;
	}

	ret = cstp_puts(ws, "\r\n");
	if (ret < 0) {
		goto fail;
	}

	ret = cstp_send(ws, buf, length);
	if (ret < 0) {
		goto fail;
	}

	ret = cstp_uncork(ws);
	if (ret < 0) {
		goto fail;
	}

	ret = 0;
	goto cleanup;
 fail:
	cstp_printf(ws,
		   "HTTP/1.%u 502 Bad Gateway\r\nX-Reason: %s\r\n\r\n",
		   http_ver, reason);
	ret = -1;

 cleanup:
 	close(fd);
 	return ret;

}
