/*
 * Copyright (C) 2014, 2015 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <c-ctype.h>
#include <dbus/dbus.h>
#include <occtl.h>
#include <c-strcase.h>
#include <arpa/inet.h>

typedef struct dbus_ctx {
	DBusConnection *conn;
} dbus_ctx;

/* sends a message and returns the reply */
DBusMessage *send_dbus_cmd(dbus_ctx *ctx,
			   const char *bus_name, const char *path,
			   const char *interface, const char *method,
			   unsigned type, const void *arg)
{
	DBusMessage *msg;
	DBusMessageIter args;
	DBusPendingCall *pending = NULL;

	msg = dbus_message_new_method_call(bus_name, path, interface, method);
	if (msg == NULL) {
		goto error;
	}
	dbus_message_iter_init_append(msg, &args);
	if (arg != NULL) {
		if (!dbus_message_iter_append_basic(&args, type, arg)) {
			goto error;
		}
	}

	if (!dbus_connection_send_with_reply
	    (ctx->conn, msg, &pending, DEFAULT_TIMEOUT)) {
		goto error;
	}

	if (pending == NULL)
		goto error;

	dbus_connection_flush(ctx->conn);
	dbus_message_unref(msg);

	/* wait for reply */
	dbus_pending_call_block(pending);

	msg = dbus_pending_call_steal_reply(pending);
	if (msg == NULL)
		goto error;

	dbus_pending_call_unref(pending);

	return msg;
 error:
	if (msg != NULL)
		dbus_message_unref(msg);
	return NULL;

}

int handle_status_cmd(dbus_ctx *ctx, const char *arg)
{
	DBusMessage *msg;
	DBusMessageIter args;
	dbus_bool_t status;
	dbus_uint32_t pid;
	dbus_uint32_t sec_mod_pid;
	dbus_uint32_t clients, stored_tls_sessions, banned_ips;

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv", "status", 0, NULL);
	if (msg == NULL) {
		goto error_send;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error;

	if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args))
		goto error_status;
	dbus_message_iter_get_basic(&args, &status);

	if (!dbus_message_iter_next(&args))
		goto error_recv;

	if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
		goto error_parse;
	dbus_message_iter_get_basic(&args, &pid);

	if (!dbus_message_iter_next(&args))
		goto error_recv;

	if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
		goto error_parse;
	dbus_message_iter_get_basic(&args, &sec_mod_pid);

	if (!dbus_message_iter_next(&args))
		goto error_recv;

	if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
		goto error_parse;
	dbus_message_iter_get_basic(&args, &clients);

	if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
		goto error_parse;
	dbus_message_iter_get_basic(&args, &stored_tls_sessions);

	if (DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&args))
		goto error_parse;
	dbus_message_iter_get_basic(&args, &banned_ips);

	printf("OpenConnect SSL VPN server\n");
	printf("           Status: %s\n", status != 0 ? "online" : "error");
	printf("          Clients: %u\n", (unsigned)clients);
	printf("  IPs in ban list: %u\n", (unsigned)banned_ips);
	printf("   TLS DB entries: %u\n", (unsigned)stored_tls_sessions);
	printf("\n");
	printf("       Server PID: %u\n", (unsigned)pid);
	printf("      Sec-mod PID: %u\n", (unsigned)sec_mod_pid);

	dbus_message_unref(msg);

	return 0;

 error_status:
	printf("OpenConnect SSL VPN server\n");
	printf("     Status: offline\n");
	goto error;

 error_parse:
	fprintf(stderr, "%s: D-BUS message parsing error\n", __func__);
	goto error;
 error_send:
	fprintf(stderr, "%s: D-BUS message creation error\n", __func__);
	goto error;
 error_recv:
	fprintf(stderr, "%s: D-BUS message receiving error\n", __func__);
 error:
	if (msg != NULL)
		dbus_message_unref(msg);

	return 1;
}

int handle_reload_cmd(dbus_ctx *ctx, const char *arg)
{
	DBusMessage *msg;
	DBusMessageIter args;
	dbus_bool_t status;

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv", "reload", 0, NULL);
	if (msg == NULL) {
		goto error_send;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error_server;

	if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args))
		goto error_server;
	dbus_message_iter_get_basic(&args, &status);

	if (status != 0)
		printf("Server scheduled to reload\n");
	else
		goto error_status;

	dbus_message_unref(msg);

	return 0;

 error_server:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	goto cleanup;
 error_status:
	printf("Error scheduling reload\n");
	goto cleanup;
 error_send:
	fprintf(stderr, "%s: D-BUS message creation error\n", __func__);
	goto cleanup;
 cleanup:
	if (msg != NULL)
		dbus_message_unref(msg);

	return 1;
}

int handle_stop_cmd(dbus_ctx *ctx, const char *arg)
{
	DBusMessage *msg;
	DBusMessageIter args;
	dbus_bool_t status;

	if (arg == NULL || need_help(arg) || c_strncasecmp(arg, "now", 3) != 0) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv", "stop", 0, NULL);
	if (msg == NULL) {
		goto error_send;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error_server;

	if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args))
		goto error_server;
	dbus_message_iter_get_basic(&args, &status);

	if (status != 0)
		printf("Server scheduled to stop\n");
	else
		goto error_status;

	dbus_message_unref(msg);

	return 0;

 error_server:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	goto cleanup;
 error_status:
	printf("Error scheduling server stop\n");
	goto cleanup;
 error_send:
	fprintf(stderr, "%s: D-BUS message creation error\n", __func__);
	goto cleanup;
 cleanup:
	if (msg != NULL)
		dbus_message_unref(msg);

	return 1;
}

int handle_unban_ip_cmd(struct dbus_ctx *ctx, const char *arg)
{
	int af;
	struct sockaddr_storage st;
	DBusMessage *msg;
	DBusMessageIter args;
	dbus_bool_t status;
	const char *ip;
	char txt[MAX_IP_STR];
	int ret;

	if (arg == NULL || need_help(arg)) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}
	
	/* convert the IP to the simplest form */
	if (strchr(arg, ':') != 0) {
		af = AF_INET6;
	} else {
		af = AF_INET;
	}

	ret = inet_pton(af, arg, &st);
	if (ret == 1) {
		inet_ntop(af, &st, txt, sizeof(txt));
		ip = txt;
	} else {
		ip = (char*)arg;
	}

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv",
			    "unban_ip", DBUS_TYPE_STRING, &ip);
	if (msg == NULL) {
		goto error;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error;

	if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args))
		goto error;
	dbus_message_iter_get_basic(&args, &status);

	if (status != 0) {
		printf("IP '%s' was unbanned\n", ip);
	} else {
		printf("could not unban IP '%s'\n", ip);
	}

	dbus_message_unref(msg);

	return 0;

 error:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	if (msg != NULL)
		dbus_message_unref(msg);

	return 1;
}

int handle_disconnect_user_cmd(dbus_ctx *ctx, const char *arg)
{
	DBusMessage *msg;
	DBusMessageIter args;
	dbus_bool_t status;

	if (arg == NULL || need_help(arg)) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv",
			    "disconnect_name", DBUS_TYPE_STRING, &arg);
	if (msg == NULL) {
		goto error;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error;

	if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args))
		goto error;
	dbus_message_iter_get_basic(&args, &status);

	if (status != 0) {
		printf("user '%s' was disconnected\n", arg);
	} else {
		printf("could not disconnect user '%s'\n", arg);
	}

	dbus_message_unref(msg);

	return 0;

 error:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	if (msg != NULL)
		dbus_message_unref(msg);

	return 1;
}

int handle_disconnect_id_cmd(dbus_ctx *ctx, const char *arg)
{
	DBusMessage *msg;
	DBusMessageIter args;
	dbus_bool_t status;
	dbus_uint32_t id = 0;
	int ret;

	if (arg != NULL)
		id = atoi(arg);

	if (arg == NULL || need_help(arg) || id == 0) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv",
			    "disconnect_id", DBUS_TYPE_UINT32, &id);
	if (msg == NULL) {
		goto error;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error;

	if (DBUS_TYPE_BOOLEAN != dbus_message_iter_get_arg_type(&args))
		goto error;
	dbus_message_iter_get_basic(&args, &status);

	if (status != 0) {
		printf("connection ID '%s' was disconnected\n", arg);
		ret = 0;
	} else {
		printf("could not disconnect ID '%s'\n", arg);
		ret = 1;
	}

	dbus_message_unref(msg);

	return ret;

 error:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	if (msg != NULL)
		dbus_message_unref(msg);

	return 1;
}

int handle_list_users_cmd(dbus_ctx *ctx, const char *arg)
{
	DBusMessage *msg;
	DBusMessageIter args, suba, subs;
	dbus_int32_t id = 0;
	char *username = "";
	dbus_uint32_t since = 0;
	char *groupname = "", *ip = "";
	char *vpn_ipv4 = "", *vpn_ptp_ipv4 = "";
	char *vpn_ipv6 = "", *vpn_ptp_ipv6 = "";
	char *hostname = "", *auth = "", *device = "";
	char *user_agent = "";
	char str_since[64];
	const char *vpn_ip;
	struct tm *tm;
	time_t t;
	FILE *out;
	unsigned iteration = 0;
	const char *dtls_ciphersuite, *tls_ciphersuite;
	int ret = 1;

	entries_clear();

	out = pager_start();

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv", "list", 0, NULL);
	if (msg == NULL) {
		goto error_server;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error_server;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto error_server;

	dbus_message_iter_recurse(&args, &suba);

	for (;;) {
		if (dbus_message_iter_get_arg_type(&suba) != DBUS_TYPE_STRUCT)
			goto cleanup;
		dbus_message_iter_recurse(&suba, &subs);

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_INT32)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &id);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &username);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &groupname);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &ip);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &device);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &vpn_ptp_ipv4);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &vpn_ipv4);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &vpn_ptp_ipv6);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &vpn_ipv6);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_UINT32)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &since);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &hostname);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &user_agent);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &auth);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &tls_ciphersuite);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &dtls_ciphersuite);

		if (vpn_ipv4 != NULL && vpn_ipv4[0] != 0)
			vpn_ip = vpn_ipv4;
		else
			vpn_ip = vpn_ipv6;

		/* add header */
		if (iteration++ == 0) {
			fprintf(out, "%8s %8s %8s %14s %14s %6s %7s %14s %9s\n",
				"id", "user", "group", "ip", "vpn-ip", "device",
				"since", "dtls-cipher", "status");
		}

		t = since;
		tm = localtime(&t);
		strftime(str_since, sizeof(str_since), DATE_TIME_FMT, tm);

		if (groupname == NULL || groupname[0] == 0)
			groupname = NO_GROUP;

		if (username == NULL || username[0] == 0)
			username = NO_USER;

		fprintf(out, "%8d %8s %8s %14s %14s %6s ",
			(int)id, username, groupname, ip, vpn_ip, device);

		print_time_ival7(time(0), t, out);
		if (dtls_ciphersuite != NULL && dtls_ciphersuite[0] != 0) {
			if (strlen(dtls_ciphersuite) > 16 && strncmp(dtls_ciphersuite, "(DTLS", 5) == 0 &&
			    strncmp(&dtls_ciphersuite[8], ")-(RSA)-", 8) == 0)
				dtls_ciphersuite += 16;
			fprintf(out, " %14s %9s\n", dtls_ciphersuite, auth);
		} else {
			fprintf(out, " %14s %9s\n", "(no dtls)", auth);
		}

		entries_add(ctx, username, strlen(username), id);

		if (!dbus_message_iter_next(&suba))
			break;
	}

	ret = 0;
	goto cleanup;

 error_server:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	goto cleanup;
 error_parse:
	fprintf(stderr, "%s: D-BUS message parsing error\n", __func__);
	goto cleanup;
 error_recv:
	fprintf(stderr, "%s: D-BUS message receiving error\n", __func__);
 cleanup:
	pager_stop(out);
	if (msg != NULL)
		dbus_message_unref(msg);
	return ret;
}

static
int handle_list_banned_cmd(struct dbus_ctx *ctx, const char *arg, unsigned points)
{
	DBusMessage *msg;
	DBusMessageIter args, suba, subs;
	dbus_uint32_t expires = 0;
	char *ip = "";
	dbus_uint32_t score = 0;
	time_t t;
	struct tm *tm;
	int ret = 1;
	char str_since[64];
	unsigned i = 0;
	FILE *out;

	ip_entries_clear();

	out = pager_start();

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv", "list_banned", 0, NULL);
	if (msg == NULL) {
		goto error_server;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error_server;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto error_server;

	dbus_message_iter_recurse(&args, &suba);

	for (i=0;;i++) {
		if (dbus_message_iter_get_arg_type(&suba) != DBUS_TYPE_STRUCT)
			goto cleanup;
		dbus_message_iter_recurse(&suba, &subs);

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_UINT32)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &score);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &ip);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_UINT32)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &expires);

		if (points == 0) {
			if (expires > 0) {
				t = expires;
				tm = localtime(&t);
				strftime(str_since, sizeof(str_since), DATE_TIME_FMT, tm);
			} else {
				goto cont;
			}

			/* add header */
			if (i == 0) {
				fprintf(out, "%14s %14s %30s\n",
					"IP", "score", "expires");
			}
			fprintf(out, "%14s %14u %30s (", ip, (unsigned)score, str_since);
			print_time_ival7(t, time(0), out);
			fputs(")\n", out);
		} else {
			if (i == 0) {
				fprintf(out, "%14s %14s\n",
					"IP", "score");
			}

			fprintf(out, "%14s %14u\n",
				ip, (unsigned)score);
		}

		ip_entries_add(ctx, ip, strlen(ip));
 cont:
		if (!dbus_message_iter_next(&suba))
			break;
	}

	ret = 0;
	goto cleanup;

 error_server:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	goto cleanup;
 error_parse:
	fprintf(stderr, "%s: D-BUS message parsing error\n", __func__);
	goto cleanup;
 error_recv:
	fprintf(stderr, "%s: D-BUS message receiving error\n", __func__);
 cleanup:
	pager_stop(out);
	if (msg != NULL)
		dbus_message_unref(msg);
	return ret;
}

int handle_list_banned_ips_cmd(struct dbus_ctx *ctx, const char *arg)
{
	return handle_list_banned_cmd(ctx, arg, 0);
}

int handle_list_banned_points_cmd(struct dbus_ctx *ctx, const char *arg)
{
	return handle_list_banned_cmd(ctx, arg, 1);
}

int print_list_entries(FILE* out, const char* name, DBusMessageIter * subs)
{
	DBusMessageIter suba;
	const char * tmp;
	unsigned int i = 0;

	if (dbus_message_iter_get_arg_type(subs) != DBUS_TYPE_ARRAY)
		return -1;

	dbus_message_iter_recurse(subs, &suba);

	for (;;) {
		if (dbus_message_iter_get_arg_type(&suba) != DBUS_TYPE_STRING)
			break; /* empty */

		dbus_message_iter_get_basic(&suba, &tmp);
		if (tmp != NULL) {
			if (i==0)
				fprintf(out, "%s %s\n", name, tmp);
			else
				fprintf(out, "\t\t%s\n", tmp);
		}

		i++;
		if (!dbus_message_iter_next(&suba))
			break;
	}

	return i;
}

int common_info_cmd(DBusMessageIter * args)
{
	DBusMessageIter suba, subs;
	dbus_int32_t id = 0;
	dbus_uint32_t rx = 0, tx = 0, mtu = 0;
	char *username = "";
	dbus_uint32_t since = 0;
	char *groupname = "", *ip = "";
	char *vpn_ipv4 = "", *vpn_ptp_ipv4 = "";
	char *vpn_ipv6 = "", *vpn_ptp_ipv6 = "";
	char *hostname = "", *auth = "", *device = "";
	char *user_agent = "";
	char str_since[64];
	struct tm *tm;
	time_t t;
	FILE *out;
	unsigned at_least_one = 0;
	const char *dtls_ciphersuite, *tls_ciphersuite;
	char *cstp_compr = "", *dtls_compr = "";
	int ret = 1, r;

	out = pager_start();

	if (dbus_message_iter_get_arg_type(args) != DBUS_TYPE_ARRAY)
		goto cleanup;

	dbus_message_iter_recurse(args, &suba);

	for (;;) {
		if (dbus_message_iter_get_arg_type(&suba) != DBUS_TYPE_STRUCT) {
			ret = 2;
			goto cleanup;
		}
		dbus_message_iter_recurse(&suba, &subs);

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_INT32)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &id);

		if (at_least_one > 0)
			fprintf(out, "\n");
		fprintf(out, "ID: %d\n", (int)id);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &username);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &groupname);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &ip);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &device);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &vpn_ptp_ipv4);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &vpn_ipv4);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &vpn_ptp_ipv6);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &vpn_ipv6);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_UINT32)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &since);

		t = since;
		tm = localtime(&t);
		strftime(str_since, sizeof(str_since), DATE_TIME_FMT, tm);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &hostname);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &user_agent);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &auth);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &tls_ciphersuite);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &dtls_ciphersuite);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &cstp_compr);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_STRING)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &dtls_compr);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_UINT32)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &mtu);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_UINT32)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &rx);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (dbus_message_iter_get_arg_type(&subs) != DBUS_TYPE_UINT32)
			goto error_parse;
		dbus_message_iter_get_basic(&subs, &tx);

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (username == NULL || username[0] == 0)
			username = NO_USER;

		fprintf(out, "\tUsername: %s  ", username);

		if (groupname == NULL || groupname[0] == 0)
			groupname = NO_GROUP;

		fprintf(out, "Groupname: %s\n", groupname);
		fprintf(out, "\tState: %s  ", auth);
		fprintf(out, "Remote IP: %s\n", ip);

		if (vpn_ipv4 != NULL && vpn_ipv4[0] != 0 &&
		    vpn_ptp_ipv4 != NULL && vpn_ptp_ipv4[0] != 0) {
			fprintf(out, "\tIPv4: %s  ", vpn_ipv4);
			fprintf(out, "P-t-P IPv4: %s\n", vpn_ptp_ipv4);
		}
		if (vpn_ipv6 != NULL && vpn_ipv6[0] != 0 &&
		    vpn_ptp_ipv6 != NULL && vpn_ptp_ipv6[0] != 0) {
			fprintf(out, "\tIPv6: %s  ", vpn_ipv6);
			fprintf(out, "P-t-P IPv6: %s\n", vpn_ptp_ipv6);
		}
		fprintf(out, "\tDevice: %s  ", device);
		if (mtu > 0) {
			fprintf(out, "MTU: %u\n", (unsigned)mtu);
		} else {
			fprintf(out, "MTU: (unknown)\n");
		}

		if (user_agent != NULL && user_agent[0] != 0)
			fprintf(out, "\tUser-Agent: %s\n", user_agent);

		if (rx > 0 || tx > 0) {
			/* print limits */
			char buf[32];

			if (rx > 0 && tx > 0) {
				bytes2human(rx, buf, sizeof(buf), NULL);
				fprintf(out, "\tLimit RX: %s/sec  ", buf);

				bytes2human(tx, buf, sizeof(buf), NULL);
				fprintf(out, "TX: %s/sec\n", buf);
			} else if (tx > 0) {
				bytes2human(tx, buf, sizeof(buf), NULL);
				fprintf(out, "\tLimit TX: %s/sec\n", buf);
			} else if (rx > 0) {
				bytes2human(rx, buf, sizeof(buf), NULL);
				fprintf(out, "\tLimit RX: %s/sec\n", buf);
			}
		}

		print_iface_stats(device, since, out);

		if (hostname != NULL && hostname[0] != 0)
			fprintf(out, "\tHostname: %s\n", hostname);

		fprintf(out, "\tConnected at: %s (", str_since);
		print_time_ival7(time(0), t, out);
		fprintf(out, ")\n");

		fprintf(out, "\tTLS ciphersuite: %s\n", tls_ciphersuite);
		if (dtls_ciphersuite != NULL && dtls_ciphersuite[0] != 0)
			fprintf(out, "\tDTLS cipher: %s\n", dtls_ciphersuite);

		if (cstp_compr != NULL && cstp_compr[0] != 0)
			fprintf(out, "\tCSTP compression: %s\n", cstp_compr);
		if (dtls_compr != NULL && dtls_compr[0] != 0)
			fprintf(out, "\tDTLS compression: %s\n", dtls_compr);

		/* user network info */
		fputs("\n", out);
		if (print_list_entries(out, "\tDNS:", &subs) < 0)
			goto error_parse;

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (print_list_entries(out, "\tNBNS:", &subs) < 0)
			goto error_parse;

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if ((r = print_list_entries(out, "\tRoutes:", &subs)) < 0)
			goto error_parse;
		if (r == 0) {
			fprintf(out, "Routes: defaultroute\n");
		}

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if ((r = print_list_entries(out, "\tNo-routes:", &subs)) < 0)
			goto error_parse;

		if (!dbus_message_iter_next(&subs))
			goto error_recv;

		if (print_list_entries(out, "\tiRoutes:", &subs) < 0)
			goto error_parse;


		at_least_one = 1;
		if (!dbus_message_iter_next(&suba))
			break;
	}

	ret = 0;
	goto cleanup;

 error_parse:
	fprintf(stderr, "%s: D-BUS message parsing error\n", __func__);
	goto cleanup;
 error_recv:
	fprintf(stderr, "%s: D-BUS message receiving error\n", __func__);
 cleanup:
	if (at_least_one == 0)
		fprintf(out, "user or ID not found\n");
	pager_stop(out);

	return ret;
}

int handle_show_user_cmd(dbus_ctx *ctx, const char *arg)
{
	DBusMessage *msg;
	DBusMessageIter args;
	int ret = 1;

	if (arg == NULL || need_help(arg)) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv", "user_info2",
			    DBUS_TYPE_STRING, &arg);
	if (msg == NULL) {
		goto error_send;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error_server;

	ret = common_info_cmd(&args);
	if (ret != 0)
		goto error_server;

	goto cleanup;

 error_server:
	if (ret == 1)
		fprintf(stderr, ERR_SERVER_UNREACHABLE);
	goto cleanup;
 error_send:
	fprintf(stderr, "%s: D-BUS message creation error\n", __func__);
	goto cleanup;
 cleanup:
	if (msg != NULL)
		dbus_message_unref(msg);

	return ret;
}

int handle_show_id_cmd(dbus_ctx *ctx, const char *arg)
{
	DBusMessage *msg;
	DBusMessageIter args;
	dbus_uint32_t id = 0;
	int ret = 1;

	if (arg != NULL)
		id = atoi(arg);

	if (arg == NULL || need_help(arg) || id == 0) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}

	msg = send_dbus_cmd(ctx, "org.infradead.ocserv",
			    "/org/infradead/ocserv",
			    "org.infradead.ocserv", "id_info2",
			    DBUS_TYPE_UINT32, &id);
	if (msg == NULL) {
		goto error_send;
	}

	if (!dbus_message_iter_init(msg, &args))
		goto error_server;

	ret = common_info_cmd(&args);
	if (ret != 0)
		goto error_server;

	goto cleanup;

 error_server:
	if (ret == 1)
		fprintf(stderr, ERR_SERVER_UNREACHABLE);
	goto cleanup;
 error_send:
	fprintf(stderr, "%s: D-BUS message creation error\n", __func__);
	goto cleanup;
 cleanup:
	if (msg != NULL)
		dbus_message_unref(msg);

	return ret;
}

dbus_ctx *conn_init(void *pool, const char *file)
{
	DBusError err;
	dbus_ctx *ctx;
	DBusConnection *conn;

	ctx = talloc(pool, dbus_ctx);
	if (ctx == NULL)
		return NULL;

	dbus_error_init(&err);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) {
		fprintf(stderr, "D-BUS connection error (%s)\n", err.message);
		dbus_error_free(&err);
	}

	if (conn == NULL)
		exit(1);

	ctx->conn = conn;

	return ctx;
}

void conn_close(dbus_ctx *ctx)
{
	dbus_connection_close(ctx->conn);
}

int conn_prehandle(dbus_ctx *ctx)
{
	return 0;
}

void conn_posthandle(dbus_ctx *ctx)
{
	return;
}
