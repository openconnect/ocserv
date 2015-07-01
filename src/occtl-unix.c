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
#include <errno.h>
#include <signal.h>
#include <c-ctype.h>
#include <ctl.h>
#include <ctl.pb-c.h>
#include <occtl.h>
#include <common.h>
#include <c-strcase.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

static
int common_info_cmd(UserListRep *args, FILE *out, cmd_params_st *params);

struct unix_ctx {
	int fd;
	int is_open;
	const char *socket_file;
};

static uint8_t msg_map[] = {   
        [CTL_CMD_STATUS] = CTL_CMD_STATUS_REP,
        [CTL_CMD_RELOAD] = CTL_CMD_RELOAD_REP,
        [CTL_CMD_STOP] = CTL_CMD_STOP_REP,
        [CTL_CMD_LIST] = CTL_CMD_LIST_REP,
        [CTL_CMD_LIST_BANNED] = CTL_CMD_LIST_BANNED_REP,
        [CTL_CMD_USER_INFO] = CTL_CMD_LIST_REP,
        [CTL_CMD_ID_INFO] = CTL_CMD_LIST_REP,
        [CTL_CMD_DISCONNECT_NAME] = CTL_CMD_DISCONNECT_NAME_REP,
        [CTL_CMD_DISCONNECT_ID] = CTL_CMD_DISCONNECT_ID_REP,
        [CTL_CMD_UNBAN_IP] = CTL_CMD_UNBAN_IP_REP,
};

struct cmd_reply_st {
	unsigned cmd;
	uint8_t *data;
	unsigned data_size;
};

static void free_reply(struct cmd_reply_st *rep)
{
	talloc_free(rep->data);
}

static void init_reply(struct cmd_reply_st *rep)
{
	if (rep)
		rep->data = NULL;
}

/* sends a message and returns the reply */
static
int send_cmd(struct unix_ctx *ctx, unsigned cmd, const void *data,
		 pack_size_func get_size, pack_func pack,
		 struct cmd_reply_st *rep)
{
	uint8_t header[3];
	struct iovec iov[2];
	unsigned iov_len = 1;
	int e, ret;
	uint16_t length = 0;
	void *packed = NULL;

	if (get_size)
		length = get_size(data);

	header[0] = cmd;
	memcpy(&header[1], &length, 2);

	iov[0].iov_base = header;
	iov[0].iov_len = 3;

	if (data != NULL) {
		packed = talloc_size(ctx, length);
		if (packed == NULL) {
			fprintf(stderr, "memory error\n");
			return -1;
		}
		iov[1].iov_base = packed;
		iov[1].iov_len = length;
		
		ret = pack(data, packed);
		if (ret == 0) {
			fprintf(stderr, "data packing error\n");
			ret = -1;
			goto fail;
		}
		iov_len++;
	}

	ret = writev(ctx->fd, iov, iov_len);
	if (ret < 0) {
		e = errno;
		fprintf(stderr, "writev: %s\n", strerror(e));
		ret = -1;
		goto fail;
	}

	if (rep != NULL) {
		ret = force_read_timeout(ctx->fd, header, 3, DEFAULT_TIMEOUT);
		if (ret == -1) {
			/*e = errno;
			fprintf(stderr, "read: %s\n", strerror(e));*/
			ret = -1;
			goto fail;
		}

		if (ret != 3) {
			fprintf(stderr, "short read %d\n", ret);
			ret = -1;
			goto fail;
		}

		rep->cmd = header[0];

		if (msg_map[cmd] != rep->cmd) {
			fprintf(stderr, "Unexpected message '%d', expected '%d'\n", (int)rep->cmd, (int)msg_map[cmd]);
			ret = -1;
			goto fail;
		}

		memcpy(&length, &header[1], 2);

		rep->data_size = length;
		rep->data = talloc_size(ctx, length);
		if (rep->data == NULL) {
			fprintf(stderr, "memory error\n");
			ret = -1;
			goto fail;
		}

		ret = force_read_timeout(ctx->fd, rep->data, length, DEFAULT_TIMEOUT);
		if (ret == -1) {
			e = errno;
			talloc_free(rep->data);
			rep->data = NULL;
			fprintf(stderr, "read: %s\n", strerror(e));
			ret = -1;
			goto fail;
		}
	}

	ret = 0;
 fail:
	talloc_free(packed);
	return ret;
}

static
int connect_to_ocserv (const char *socket_file)
{
	int sd, ret, e;
	struct sockaddr_un sa;

	if (socket_file == NULL)
		socket_file = OCCTL_UNIX_SOCKET;

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", socket_file);

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		fprintf(stderr, "error opening socket: %s\n", strerror(e));
		return -1;
	}

	ret = connect(sd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret == -1) {
		e = errno;
		fprintf(stderr, "error connecting to ocserv socket '%s': %s\n", 
			sa.sun_path, strerror(e));
		ret = -1;
		goto error;
	}

	return sd;
error:
	close(sd);
	return ret;

}

int handle_status_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	int ret;
	struct cmd_reply_st raw;
	StatusRep *rep;
	char str_since[64];
	char buf[MAX_TMPSTR_SIZE];
	time_t t;
	struct tm *tm;
	PROTOBUF_ALLOCATOR(pa, ctx);

	init_reply(&raw);

	print_start_block(stdout, params);
	if (NO_JSON(params))
		printf("OpenConnect SSL VPN server\n");

	ret = send_cmd(ctx, CTL_CMD_STATUS, NULL, NULL, NULL, &raw);
	if (ret < 0) {
		goto error_status;
	}

	rep = status_rep__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error_status;


	print_single_value(stdout, params, "Status", rep->status != 0 ? "online" : "error", 1);

	t = rep->start_time;
	tm = localtime(&t);
	print_time_ival7(buf, time(0), t);
	strftime(str_since, sizeof(str_since), DATE_TIME_FMT, tm);

	print_single_value_ex(stdout, params, "Up since", str_since, buf, 1);
	print_single_value_int(stdout, params, "Clients", rep->active_clients, 1);
	print_single_value_int(stdout, params, "Sec-mod client entries", rep->secmod_client_entries, 1);
	print_single_value_int(stdout, params, "IPs in ban list", rep->banned_ips, 1);
	print_single_value_int(stdout, params, "TLS DB entries", rep->stored_tls_sessions, 1);
	print_separator(stdout, params);
	print_single_value_int(stdout, params, "Server PID", rep->pid, 1);
	print_single_value_int(stdout, params, "Sec-mod PID", rep->sec_mod_pid, 1);
	print_end_block(stdout, params, 0);

	status_rep__free_unpacked(rep, &pa);

	ret = 0;
	goto cleanup;

 error_status:
	print_single_value(stdout, params, "Status", "offline", 0);
	print_end_block(stdout, params, 0);
	ret = 1;

 cleanup:
 	free_reply(&raw);
	return ret;
}

int handle_reload_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	int ret;
	struct cmd_reply_st raw;
	BoolMsg *rep;
	unsigned status;
	PROTOBUF_ALLOCATOR(pa, ctx);
	
	init_reply(&raw);

	ret = send_cmd(ctx, CTL_CMD_RELOAD, NULL, NULL, NULL, &raw);
	if (ret < 0) {
		goto error_status;
	}

	rep = bool_msg__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error_status;

	status = rep->status;
	bool_msg__free_unpacked(rep, &pa);

	if (status != 0)
        	printf("Server scheduled to reload\n");
	else
		goto error_status;

	ret = 0;
	goto cleanup;

 error_status:
	printf("Error scheduling reload\n");
	ret = 1;

 cleanup:
	free_reply(&raw);

	return ret;
}

int handle_stop_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	int ret;
	struct cmd_reply_st raw;
	BoolMsg *rep;
	unsigned status;
	PROTOBUF_ALLOCATOR(pa, ctx);
	
	init_reply(&raw);

	ret = send_cmd(ctx, CTL_CMD_STOP, NULL, NULL, NULL, &raw);
	if (ret < 0) {
		goto error_status;
	}

	rep = bool_msg__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error_status;

	status = rep->status;
	bool_msg__free_unpacked(rep, &pa);

	if (status != 0)
        	printf("Server scheduled to stop\n");
	else
		goto error_status;

	ret = 0;
	goto cleanup;

 error_status:
	printf("Error scheduling server stop\n");
	ret = 1;
	goto cleanup;
 cleanup:
	free_reply(&raw);

	return ret;
}

int handle_unban_ip_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	int ret;
	struct cmd_reply_st raw;
	BoolMsg *rep;
	unsigned status;
	UnbanReq req = UNBAN_REQ__INIT;
	char txt[MAX_IP_STR];
	int af;
	struct sockaddr_storage st;
	PROTOBUF_ALLOCATOR(pa, ctx);

	if (arg == NULL || need_help(arg)) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}
	
	init_reply(&raw);

	/* convert the IP to the simplest form */
	if (strchr(arg, ':') != 0) {
		af = AF_INET6;
	} else {
		af = AF_INET;
	}

	ret = inet_pton(af, arg, &st);
	if (ret == 1) {
		inet_ntop(af, &st, txt, sizeof(txt));
		req.ip = txt;
	} else {
		req.ip = (char*)arg;
	}

	ret = send_cmd(ctx, CTL_CMD_UNBAN_IP, &req, 
		(pack_size_func)unban_req__get_packed_size, 
		(pack_func)unban_req__pack, &raw);
	if (ret < 0) {
		goto error;
	}

	rep = bool_msg__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error;

	status = rep->status;
	bool_msg__free_unpacked(rep, &pa);

	if (status != 0) {
		printf("IP '%s' was unbanned\n", arg);
	} else {
		printf("could not unban IP '%s'\n", arg);
	}

	ret = 0;
	goto cleanup;

 error:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	ret = 1;
 cleanup:
	free_reply(&raw);

	return ret;
}

int handle_disconnect_user_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	int ret;
	struct cmd_reply_st raw;
	BoolMsg *rep;
	unsigned status;
	UsernameReq req = USERNAME_REQ__INIT;
	PROTOBUF_ALLOCATOR(pa, ctx);

	if (arg == NULL || need_help(arg)) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}
	
	init_reply(&raw);

	req.username = (void*)arg;

	ret = send_cmd(ctx, CTL_CMD_DISCONNECT_NAME, &req, 
		(pack_size_func)username_req__get_packed_size, 
		(pack_func)username_req__pack, &raw);
	if (ret < 0) {
		goto error;
	}

	rep = bool_msg__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error;

	status = rep->status;
	bool_msg__free_unpacked(rep, &pa);

	if (status != 0) {
		printf("user '%s' was disconnected\n", arg);
	} else {
		printf("could not disconnect user '%s'\n", arg);
	}

	ret = 0;
	goto cleanup;

 error:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	ret = 1;
 cleanup:
	free_reply(&raw);

	return ret;
}

int handle_disconnect_id_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	int ret;
	struct cmd_reply_st raw;
	BoolMsg *rep;
	unsigned status;
	unsigned id;
	IdReq req = ID_REQ__INIT;
	PROTOBUF_ALLOCATOR(pa, ctx);

	if (arg != NULL)
		id = atoi(arg);

	if (arg == NULL || need_help(arg) || id == 0) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}
	
	init_reply(&raw);

	req.id = id;

	ret = send_cmd(ctx, CTL_CMD_DISCONNECT_ID, &req, 
		(pack_size_func)id_req__get_packed_size, 
		(pack_func)id_req__pack, &raw);
	if (ret < 0) {
		goto error;
	}

	rep = bool_msg__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error;

	status = rep->status;
	bool_msg__free_unpacked(rep, &pa);

	if (status != 0) {
		printf("connection ID '%s' was disconnected\n", arg);
		ret = 0;
	} else {
		printf("could not disconnect ID '%s'\n", arg);
		ret = 1;
	}

	goto cleanup;

 error:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	ret = 1;
 cleanup:
	free_reply(&raw);

	return ret;
}

int handle_list_users_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	int ret;
	struct cmd_reply_st raw;
	UserListRep *rep = NULL;
	unsigned i;
	const char *vpn_ip, *groupname, *username;
	const char *dtls_ciphersuite;
	char tmpbuf[MAX_TMPSTR_SIZE];
	FILE *out;
	time_t t;
	struct tm *tm;
	char str_since[64];
	PROTOBUF_ALLOCATOR(pa, ctx);

	init_reply(&raw);

	entries_clear();

	out = pager_start();

	ret = send_cmd(ctx, CTL_CMD_LIST, NULL, NULL, NULL, &raw);
	if (ret < 0) {
		goto error;
	}

	rep = user_list_rep__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error;

	if (HAVE_JSON(params)) {
		common_info_cmd(rep, out, params);
	} else for (i=0;i<rep->n_user;i++) {
		username = rep->user[i]->username;
		if (username == NULL || username[0] == 0)
			username = NO_USER;

		if (rep->user[i]->local_ip != NULL && rep->user[i]->local_ip[0] != 0)
			vpn_ip = rep->user[i]->local_ip;
		else
			vpn_ip = rep->user[i]->local_ip6;

		/* add header */
		if (i == 0) {
			fprintf(out, "%8s %8s %8s %14s %14s %6s %7s %14s %9s\n",
				"id", "user", "group", "ip", "vpn-ip", "device",
				"since", "dtls-cipher", "status");
		}

		t = rep->user[i]->conn_time;
		tm = localtime(&t);
		strftime(str_since, sizeof(str_since), DATE_TIME_FMT, tm);

		groupname = rep->user[i]->groupname;
		if (groupname == NULL || groupname[0] == 0)
			groupname = NO_GROUP;

		print_time_ival7(tmpbuf, time(0), t);

		fprintf(out, "%8d %8s %8s %14s %14s %6s ",
			(int)rep->user[i]->id, username, groupname, rep->user[i]->ip, vpn_ip, rep->user[i]->tun);

		dtls_ciphersuite = rep->user[i]->dtls_ciphersuite;
		if (dtls_ciphersuite != NULL && dtls_ciphersuite[0] != 0) {
			if (strlen(dtls_ciphersuite) > 16 && strncmp(dtls_ciphersuite, "(DTLS", 5) == 0 &&
			    strncmp(&dtls_ciphersuite[8], ")-(RSA)-", 8) == 0)
				dtls_ciphersuite += 16;
			fprintf(out, "%s %14s %9s\n", tmpbuf, dtls_ciphersuite, rep->user[i]->status);
		} else {
			fprintf(out, "%s %14s %9s\n", tmpbuf, "(no dtls)", rep->user[i]->status);
		}

		entries_add(ctx, username, strlen(username), rep->user[i]->id);
	}

	ret = 0;
	goto cleanup;

 error:
	ret = 1;
	fprintf(stderr, ERR_SERVER_UNREACHABLE);

 cleanup:
	if (rep != NULL)
		user_list_rep__free_unpacked(rep, &pa);

	free_reply(&raw);
	pager_stop(out);

	return ret;
}

static
int handle_list_banned_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params, unsigned points)
{
	int ret;
	struct cmd_reply_st raw;
	BanListRep *rep = NULL;
	unsigned i;
	char str_since[64];
	char tmpbuf[MAX_TMPSTR_SIZE];
	FILE *out;
	struct tm *tm;
	time_t t;
	PROTOBUF_ALLOCATOR(pa, ctx);

	init_reply(&raw);

	ip_entries_clear();

	out = pager_start();

	ret = send_cmd(ctx, CTL_CMD_LIST_BANNED, NULL, NULL, NULL, &raw);
	if (ret < 0) {
		goto error;
	}

	rep = ban_list_rep__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error;

	print_array_block(out, params);

	for (i=0;i<rep->n_info;i++) {
		if (rep->info[i]->ip == NULL)
			continue;


		/* add header */
		if (points == 0) {
			if (rep->info[i]->has_expires) {
				t = rep->info[i]->expires;
				tm = localtime(&t);
				strftime(str_since, sizeof(str_since), DATE_TIME_FMT, tm);
			} else {
				continue;
			}

			if (i == 0 && NO_JSON(params)) {
				fprintf(out, "%14s %14s %30s\n",
					"IP", "score", "expires");
			}
			print_start_block(out, params);

			print_time_ival7(tmpbuf, t, time(0));

			if (HAVE_JSON(params)) {
				print_single_value(out, params, "IP", rep->info[i]->ip, 1);
				print_single_value_ex(out, params, "Since", str_since, tmpbuf, 1);
				print_single_value_int(out, params, "Score", rep->info[i]->score, 0);
			} else {
				fprintf(out, "%14s %14u %30s (%s)\n",
					rep->info[i]->ip, (unsigned)rep->info[i]->score, str_since, tmpbuf);
			}
		} else {
			if (i == 0 && NO_JSON(params)) {
				fprintf(out, "%14s %14s\n",
					"IP", "score");
			}
			print_start_block(out, params);

			if (HAVE_JSON(params)) {
				print_single_value(out, params, "IP", rep->info[i]->ip, 1);
				print_single_value_int(out, params, "Score", rep->info[i]->score, 0);
			} else {
				fprintf(out, "%14s %14u\n",
					rep->info[i]->ip, (unsigned)rep->info[i]->score);
			}
		}

		print_end_block(out, params, i<(rep->n_info-1)?1:0);

		ip_entries_add(ctx, rep->info[i]->ip, strlen(rep->info[i]->ip));
	}

	print_end_array_block(out, params);

	ret = 0;
	goto cleanup;

 error:
	ret = 1;
	fprintf(stderr, ERR_SERVER_UNREACHABLE);

 cleanup:
	if (rep != NULL)
		ban_list_rep__free_unpacked(rep, &pa);

	free_reply(&raw);
	pager_stop(out);

	return ret;
}

int handle_list_banned_ips_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	return handle_list_banned_cmd(ctx, arg, params, 0);
}

int handle_list_banned_points_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	return handle_list_banned_cmd(ctx, arg, params, 1);
}


static char *int2str(char tmpbuf[MAX_TMPSTR_SIZE], int i)
{
	tmpbuf[0] = 0;
	snprintf(tmpbuf, MAX_TMPSTR_SIZE, "%d", i);
	return tmpbuf;
}

static
int common_info_cmd(UserListRep * args, FILE *out, cmd_params_st *params)
{
	char *username = "";
	char *groupname = "";
	char str_since[64];
	char tmpbuf[MAX_TMPSTR_SIZE];
	struct tm *tm;
	time_t t;
	unsigned at_least_one = 0;
	int ret = 1, r;
	unsigned i;
	unsigned init_pager = 0;

	if (out == NULL) {
		out = pager_start();
		init_pager = 1;
	}

	if (HAVE_JSON(params))
		fprintf(out, "[\n");

	for (i=0;i<args->n_user;i++) {
		if (at_least_one > 0)
			fprintf(out, "\n");

		print_start_block(out, params);

		print_single_value_int(out, params, "ID", args->user[i]->id, 1);

		t = args->user[i]->conn_time;
		tm = localtime(&t);
		strftime(str_since, sizeof(str_since), DATE_TIME_FMT, tm);

		username = args->user[i]->username;
		if (username == NULL || username[0] == 0)
			username = NO_USER;


		groupname = args->user[i]->groupname;
		if (groupname == NULL || groupname[0] == 0)
			groupname = NO_GROUP;

		print_pair_value(out, params, "Username", username, "Groupname", groupname, 1);
		print_pair_value(out, params, "State", args->user[i]->status, "Remote IP", args->user[i]->ip, 1);

		if (args->user[i]->local_ip != NULL && args->user[i]->local_ip[0] != 0 &&
		    args->user[i]->remote_ip != NULL && args->user[i]->remote_ip[0] != 0) {
			print_pair_value(out, params, "IPv4", args->user[i]->local_ip, "P-t-P IPv4", args->user[i]->remote_ip, 1);
		}
		if (args->user[i]->local_ip6 != NULL && args->user[i]->local_ip6[0] != 0 &&
		    args->user[i]->remote_ip6 != NULL && args->user[i]->remote_ip6[0] != 0) {
			print_pair_value(out, params, "IPv6", args->user[i]->local_ip6, "P-t-P IPv6", args->user[i]->remote_ip6, 1);
		}

		if (args->user[i]->has_mtu != 0)
			print_pair_value(out, params, "Device", args->user[i]->tun, "MTU", int2str(tmpbuf, args->user[i]->mtu), 1);
		else
			print_single_value(out, params, "Device", args->user[i]->tun, 1);

		print_single_value(out, params, "User-Agent", args->user[i]->user_agent, 1);

		if (args->user[i]->rx_per_sec > 0 || args->user[i]->tx_per_sec > 0) {
			/* print limits */
			char buf1[32];
			char buf2[32];

			if (args->user[i]->rx_per_sec > 0 && args->user[i]->tx_per_sec > 0) {
				bytes2human(args->user[i]->rx_per_sec, buf1, sizeof(buf1), "/sec");
				bytes2human(args->user[i]->tx_per_sec, buf2, sizeof(buf2), "/sec");

				print_pair_value(out, params, "Limit RX", buf1, "TX", buf2, 1);
			} else if (args->user[i]->tx_per_sec > 0) {
				bytes2human(args->user[i]->tx_per_sec, buf1, sizeof(buf1), "/sec");
				print_single_value(out, params, "Limit TX", buf1, 1);
			} else if (args->user[i]->rx_per_sec > 0) {
				bytes2human(args->user[i]->rx_per_sec, buf1, sizeof(buf1), "/sec");
				print_single_value(out, params, "Limit RX", buf1, 1);
			}
		}

		print_iface_stats(args->user[i]->tun, args->user[i]->conn_time, out, params, 1);

		print_single_value(out, params, "Hostname", args->user[i]->hostname, 1);

		print_time_ival7(tmpbuf, time(0), t);
		print_single_value_ex(out, params, "Connected at", str_since, tmpbuf, 1);

		print_single_value(out, params, "TLS ciphersuite", args->user[i]->tls_ciphersuite, 1);
		print_single_value(out, params, "DTLS cipher", args->user[i]->dtls_ciphersuite, 1);
		print_pair_value(out, params, "CSTP compression", args->user[i]->cstp_compr, "DTLS compression", args->user[i]->dtls_compr, 1);

		print_separator(out, params);
		/* user network info */
		if (print_list_entries(out, params, "DNS", args->user[i]->dns, args->user[i]->n_dns, 1) < 0)
			goto error_parse;

		if (print_list_entries(out, params, "NBNS", args->user[i]->nbns, args->user[i]->n_nbns, 1) < 0)
			goto error_parse;

		if ((r = print_list_entries(out, params, "Routes", args->user[i]->routes, args->user[i]->n_routes, 1)) < 0)
			goto error_parse;
		if (r == 0) {
			print_single_value(out, params, "Routes", "defaultroute", 1);
		}

		if ((r = print_list_entries(out, params, "No-routes", args->user[i]->no_routes, args->user[i]->n_no_routes, 1)) < 0)
			goto error_parse;

		if (print_list_entries(out, params, "iRoutes", args->user[i]->iroutes, args->user[i]->n_iroutes, 0) < 0)
			goto error_parse;

		print_end_block(out, params, i<(args->n_user-1)?1:0);

		at_least_one = 1;
	}

	if (HAVE_JSON(params))
		fprintf(out, "]\n");

	ret = 0;
	goto cleanup;

 error_parse:
	fprintf(stderr, "%s: message parsing error\n", __func__);
	goto cleanup;
 cleanup:
	if (at_least_one == 0) {
		if (NO_JSON(params))
			fprintf(out, "user or ID not found\n");
		ret = 2;
	}
	if (init_pager)
		pager_stop(out);

	return ret;
}

int handle_show_user_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	int ret;
	struct cmd_reply_st raw;
	UserListRep *rep = NULL;
	UsernameReq req = USERNAME_REQ__INIT;
	PROTOBUF_ALLOCATOR(pa, ctx);

	if (arg == NULL || need_help(arg)) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}

	init_reply(&raw);

	req.username = (void*)arg;

	ret = send_cmd(ctx, CTL_CMD_USER_INFO, &req, 
		(pack_size_func)username_req__get_packed_size, 
		(pack_func)username_req__pack, &raw);
	if (ret < 0) {
		goto error;
	}

	rep = user_list_rep__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error;

	ret = common_info_cmd(rep, NULL, params);
	if (ret < 0)
		goto error;

	goto cleanup;

 error:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	ret = 1;
 cleanup:
	if (rep != NULL)
		user_list_rep__free_unpacked(rep, &pa);
	free_reply(&raw);

	return ret;
}

int handle_show_id_cmd(struct unix_ctx *ctx, const char *arg, cmd_params_st *params)
{
	int ret;
	struct cmd_reply_st raw;
	UserListRep *rep = NULL;
	unsigned id;
	IdReq req = ID_REQ__INIT;
	PROTOBUF_ALLOCATOR(pa, ctx);

	if (arg != NULL)
		id = atoi(arg);

	if (arg == NULL || need_help(arg) || id == 0) {
		check_cmd_help(rl_line_buffer);
		return 1;
	}

	init_reply(&raw);

	req.id = id;

	ret = send_cmd(ctx, CTL_CMD_ID_INFO, &req, 
		(pack_size_func)id_req__get_packed_size, 
		(pack_func)id_req__pack, &raw);
	if (ret < 0) {
		goto error;
	}

	rep = user_list_rep__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error;

	ret = common_info_cmd(rep, NULL, params);
	if (ret < 0)
		goto error;

	goto cleanup;

 error:
	fprintf(stderr, ERR_SERVER_UNREACHABLE);
	ret = 1;
 cleanup:
	if (rep != NULL)
		user_list_rep__free_unpacked(rep, &pa);
	free_reply(&raw);

	return ret;
}

int conn_prehandle(struct unix_ctx *ctx)
{
	ctx->fd = connect_to_ocserv(ctx->socket_file);
	if (ctx->fd != -1)
		ctx->is_open = 1;

	return ctx->fd;
}

void conn_posthandle(struct unix_ctx *ctx)
{
	if (ctx->is_open) {
		close(ctx->fd);
		ctx->is_open = 0;
	}
}

struct unix_ctx *conn_init(void *pool, const char *file)
{
struct unix_ctx *ctx;
	ctx = talloc_zero(pool, struct unix_ctx);
	if (ctx == NULL)
		return NULL;
	ctx->socket_file = file;

	return ctx;
}

void conn_close(struct unix_ctx* conn)
{
	talloc_free(conn);
}
