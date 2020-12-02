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
	char name[MAX_USERNAME_SIZE+MAX_HOSTNAME_SIZE+3];
	const char* ip;
	va_list args;
	int debug_prio;
	unsigned have_vhosts;

	if (ws->vhost)
		debug_prio = WSPCONFIG(ws)->debug;
	else
		debug_prio = GETPCONFIG(ws)->debug;

	if (priority == LOG_DEBUG && debug_prio < DEBUG_DEBUG)
		return;

	if (priority == LOG_INFO && debug_prio < DEBUG_INFO)
		return;

	if (priority == LOG_HTTP_DEBUG) {
	    if (debug_prio < DEBUG_HTTP)
                return;
            else
                priority = LOG_INFO;
        } else if (priority == LOG_TRANSFER_DEBUG) {
	    if (debug_prio < DEBUG_TRANSFERRED)
                return;
            else
                priority = LOG_DEBUG;
        } else if (priority == LOG_SENSITIVE) {
	    if (debug_prio < DEBUG_SENSITIVE)
                return;
            else
                priority = LOG_DEBUG;
        }

	ip = ws->remote_ip_str;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	have_vhosts = HAVE_VHOSTS(ws);

	if (have_vhosts && ws->username[0] != 0) {
		snprintf(name, sizeof(name), "[%s%s]", PREFIX_VHOST(ws->vhost), ws->username);
	} else if (have_vhosts && ws->username[0] == 0 && ws->vhost && ws->vhost->name) {
		snprintf(name, sizeof(name), "[vhost:%s]", VHOSTNAME(ws->vhost));
	} else if (ws->username[0] != 0) {
		snprintf(name, sizeof(name), "[%s]", ws->username);
	} else
		name[0] = 0;

	syslog(priority, "worker%s: %s %s", name, ip?ip:"[unknown]", buf);

	return;
}

/* proc is optional */
void __attribute__ ((format(printf, 4, 5)))
    _mslog(const main_server_st * s, const struct proc_st* proc,
    	int priority, const char *fmt, ...)
{
	char buf[512];
	char ipbuf[128];
	char name[MAX_USERNAME_SIZE+MAX_HOSTNAME_SIZE+3];
	const char* ip = NULL;
	va_list args;
	int debug_prio;
	unsigned have_vhosts;

	if (s)
		debug_prio = GETPCONFIG(s)->debug;
	else
		debug_prio = 1;

	if (priority == LOG_DEBUG && debug_prio < 3)
		return;

	if (priority == LOG_HTTP_DEBUG) {
	    if (debug_prio < DEBUG_HTTP)
                return;
            else
                priority = LOG_DEBUG;
        } else if (priority == LOG_TRANSFER_DEBUG) {
	    if (debug_prio < DEBUG_TRANSFERRED)
                return;
            else
                priority = LOG_DEBUG;
        }

	if (proc) {
		ip = human_addr((void*)&proc->remote_addr, proc->remote_addr_len,
			    ipbuf, sizeof(ipbuf));
	} else {
		ip = "";
	}

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	have_vhosts = s?HAVE_VHOSTS(s):0;

	if (have_vhosts && proc && proc->username[0] != 0) {
		snprintf(name, sizeof(name), "[%s%s]", PREFIX_VHOST(proc->vhost), proc->username);
	} else if (have_vhosts && proc && proc->username[0] == 0 && proc->vhost && proc->vhost->name) {
		snprintf(name, sizeof(name), "[vhost:%s]", VHOSTNAME(proc->vhost));
	} else if (proc && proc->username[0] != 0) {
		snprintf(name, sizeof(name), "[%s]", proc->username);
	} else
		name[0] = 0;

	syslog(priority, "main%s:%s %s", name, ip?ip:"[unknown]", buf);

	return;
}

void  mslog_hex(const main_server_st * s, const struct proc_st* proc,
    	int priority, const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64)
{
	char buf[512];
	int ret;
	size_t buf_size;
	gnutls_datum_t data = {bin, bin_size};
	int debug_prio;

	if (s)
		debug_prio = GETPCONFIG(s)->debug;
	else
		debug_prio = 1;

	if (priority == LOG_DEBUG && debug_prio == 0)
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
	int debug_prio;

	if (ws->vhost)
		debug_prio = WSPCONFIG(ws)->debug;
	else
		debug_prio = GETPCONFIG(ws)->debug;

	if (priority == LOG_DEBUG && debug_prio == 0)
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

	if (priority == LOG_DEBUG && GETPCONFIG(sec)->debug == 0)
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
