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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <base64.h>

#include <vpn.h>
#include <worker.h>
#include <main.h>

char *human_addr2(const struct sockaddr *sa, socklen_t salen,
		       void *_buf, size_t buflen, unsigned full)
{
	char *save_buf = _buf;
	char *buf = _buf;
	size_t l;

	if (!buf || !buflen)
		return NULL;

	if (full != 0 && salen == sizeof(struct sockaddr_in6) &&
		((struct sockaddr_in6*)sa)->sin6_port != 0) {
		*buf = '[';
		buf++;
		buflen--;
	}

	if (getnameinfo(sa, salen, buf, buflen, NULL, 0, NI_NUMERICHOST) != 0)
		return NULL;

	if (salen == sizeof(struct sockaddr_in6)) {
		char *p = strchr(buf, '%');
		/* remove any zone info */
		if (p != NULL) {
			*p = 0;
		}
	}

	if (full == 0)
		goto finish;

	l = strlen(buf);
	buf += l;
	buflen -= l;

	if (salen == sizeof(struct sockaddr_in6) &&
		((struct sockaddr_in6*)sa)->sin6_port != 0) {
		*buf = ']';
		buf++;
		buflen--;
	}

	*buf = ':';
	buf++;
	buflen--;

	if (getnameinfo(sa, salen, NULL, 0, buf, buflen, NI_NUMERICSERV) != 0)
		return NULL;

	if (buf[0] == '0' && buf[1] == 0) {
		buf--;
		buf[0] = 0;
	}

finish:
	return save_buf;
}

void __attribute__ ((format(printf, 3, 4)))
    _oclog(const worker_st * ws, int priority, const char *fmt, ...)
{
	char buf[512];
	char ipbuf[128];
	const char* ip;
	va_list args;

	if (priority == LOG_DEBUG && ws->config->debug == 0)
		return;

	if (priority == LOG_HTTP_DEBUG) {
	    if (ws->config->debug < DEBUG_HTTP)
                return;
            else
                priority = LOG_INFO;
        } else if (priority == LOG_TRANSFER_DEBUG) {
	    if (ws->config->debug < DEBUG_TRANSFERRED)
                return;
            else
                priority = LOG_DEBUG;
        }

	ip = human_addr((void*)&ws->remote_addr, ws->remote_addr_len,
			    ipbuf, sizeof(ipbuf));

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (ip) {
		if (ws->username[0] == 0)
			syslog(priority, "worker: %s %s", ip, buf);
		else
			syslog(priority, "worker[%s]: %s %s", ws->username, ip, buf);
	} else {
		syslog(priority, "worker: [unknown] %s", buf);
	}

	return;
}

/* proc is optional */
void __attribute__ ((format(printf, 4, 5)))
    _mslog(const main_server_st * s, const struct proc_st* proc,
    	int priority, const char *fmt, ...)
{
	char buf[512];
	char ipbuf[128];
	const char* ip = NULL;
	va_list args;

	if (priority == LOG_DEBUG && s->config->debug == 0)
		return;

	if (priority == LOG_HTTP_DEBUG) {
	    if (s->config->debug < DEBUG_HTTP)
                return;
            else
                priority = LOG_DEBUG;
        } else if (priority == LOG_TRANSFER_DEBUG) {
	    if (s->config->debug < DEBUG_TRANSFERRED)
                return;
            else
                priority = LOG_DEBUG;
        }

	if (proc) {
		ip = human_addr((void*)&proc->remote_addr, proc->remote_addr_len,
			    ipbuf, sizeof(ipbuf));
	}

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (ip) {
		if (proc->username[0] == 0)
			syslog(priority, "main: %s %s", ip, buf);
		else
			syslog(priority, "main[%s]: %s %s", proc->username, ip, buf);
	} else {
		syslog(priority, "main: %s", buf);
	}

	return;
}

void  mslog_hex(const main_server_st * s, const struct proc_st* proc,
    	int priority, const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64)
{
	char buf[512];
	int ret;
	size_t buf_size;
	gnutls_datum_t data = {bin, bin_size};

	if (priority == LOG_DEBUG && s->config->debug == 0)
		return;

	if (b64) {
		base64_encode((char*)bin, bin_size, (char*)buf, sizeof(buf));
	} else {
		buf_size = sizeof(buf);
		ret = gnutls_hex_encode(&data, buf, &buf_size);
		if (ret < 0)
			return;
	}

	_mslog(s, proc, priority, "%s %s", prefix, buf);

	return;
}

void  oclog_hex(const worker_st* ws, int priority,
		const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64)
{
	char buf[512];
	int ret;
	size_t buf_size;
	gnutls_datum_t data = {bin, bin_size};

	if (priority == LOG_DEBUG && ws->config->debug == 0)
		return;

	if (b64) {
		base64_encode((char*)bin, bin_size, (char*)buf, sizeof(buf));
	} else {
		buf_size = sizeof(buf);
		ret = gnutls_hex_encode(&data, buf, &buf_size);
		if (ret < 0)
			return;
	}

	_oclog(ws, priority, "%s %s", prefix, buf);

	return;
}
