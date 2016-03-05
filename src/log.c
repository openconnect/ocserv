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
#include <arpa/inet.h>
#include <base64-helper.h>

#include <worker.h>
#include <main.h>
#include <sec-mod.h>


void __attribute__ ((format(printf, 3, 4)))
    _oclog(const worker_st * ws, int priority, const char *fmt, ...)
{
	char buf[512];
	const char* ip;
	va_list args;

	if (priority == LOG_DEBUG && ws->perm_config->debug < DEBUG_INFO)
		return;

	if (priority == LOG_HTTP_DEBUG) {
	    if (ws->perm_config->debug < DEBUG_HTTP)
                return;
            else
                priority = LOG_INFO;
        } else if (priority == LOG_TRANSFER_DEBUG) {
	    if (ws->perm_config->debug < DEBUG_TRANSFERRED)
                return;
            else
                priority = LOG_DEBUG;
        } else if (priority == LOG_SENSITIVE) {
	    if (ws->perm_config->debug < DEBUG_SENSITIVE)
                return;
            else
                priority = LOG_DEBUG;
        }

	ip = ws->remote_ip_str;

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

	if (priority == LOG_DEBUG && s->perm_config->debug < 3)
		return;

	if (priority == LOG_HTTP_DEBUG) {
	    if (s->perm_config->debug < DEBUG_HTTP)
                return;
            else
                priority = LOG_DEBUG;
        } else if (priority == LOG_TRANSFER_DEBUG) {
	    if (s->perm_config->debug < DEBUG_TRANSFERRED)
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

	if (priority == LOG_DEBUG && s->perm_config->debug == 0)
		return;

	if (b64) {
		oc_base64_encode((char*)bin, bin_size, (char*)buf, sizeof(buf));
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

	if (priority == LOG_DEBUG && ws->perm_config->debug == 0)
		return;

	if (b64) {
		oc_base64_encode((char*)bin, bin_size, (char*)buf, sizeof(buf));
	} else {
		buf_size = sizeof(buf);
		ret = gnutls_hex_encode(&data, buf, &buf_size);
		if (ret < 0)
			return;
	}

	_oclog(ws, priority, "%s %s", prefix, buf);

	return;
}

void  seclog_hex(const struct sec_mod_st* sec, int priority,
		const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64)
{
	char buf[512];
	int ret;
	size_t buf_size;
	gnutls_datum_t data = {bin, bin_size};

	if (priority == LOG_DEBUG && sec->perm_config->debug == 0)
		return;

	if (b64) {
		oc_base64_encode((char*)bin, bin_size, (char*)buf, sizeof(buf));
	} else {
		buf_size = sizeof(buf);
		ret = gnutls_hex_encode(&data, buf, &buf_size);
		if (ret < 0)
			return;
	}

	seclog(sec, priority, "%s %s", prefix, buf);

	return;
}
