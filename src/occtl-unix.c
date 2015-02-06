/*
 * Copyright (C) 2014 Red Hat
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

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
        [CTL_CMD_USER_INFO] = CTL_CMD_LIST_REP,
        [CTL_CMD_ID_INFO] = CTL_CMD_LIST_REP,
        [CTL_CMD_DISCONNECT_NAME] = CTL_CMD_DISCONNECT_NAME_REP,
        [CTL_CMD_DISCONNECT_ID] = CTL_CMD_DISCONNECT_ID_REP,
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

int handle_status_cmd(struct unix_ctx *ctx, const char *arg)
{
	int ret;
	struct cmd_reply_st raw;
	StatusRep *rep;
	char str_since[64];
	time_t t;
	struct tm *tm;
	PROTOBUF_ALLOCATOR(pa, ctx);

	init_reply(&raw);

	ret = send_cmd(ctx, CTL_CMD_STATUS, NULL, NULL, NULL, &raw);
	if (ret < 0) {
		goto error_status;
	}

	rep = status_rep__unpack(&pa, raw.data_size, raw.data);
	if (rep == NULL)
		goto error_status;

	printf("OpenConnect SSL VPN server\n");
	printf("         Status: %s\n", rep->status != 0 ? "online" : "error");

	t = rep->start_time;
	tm = localtime(&t);
	strftime(str_since, sizeof(str_since), DATE_TIME_FMT, tm);
	printf("       Up since: %s\n", str_since);

	printf("        Clients: %u\n", (unsigned)rep->active_clients);
	printf("        Cookies: %u\n", (unsigned)rep->stored_cookies);
	printf(" TLS DB entries: %u\n", (unsigned)rep->stored_tls_sessions);
	printf("\n");
	printf("     Server PID: %u\n", (unsigned)rep->pid);
	printf("    Sec-mod PID: %u\n", (unsigned)rep->sec_mod_pid);

	status_rep__free_unpacked(rep, &pa);

	ret = 0;
	goto cleanup;

 error_status:
	printf("OpenConnect SSL VPN server\n");
	printf("         Status: offline\n");
	ret = 1;

 cleanup:
 	free_reply(&raw);
	return ret;
}

int handle_reload_cmd(struct unix_ctx *ctx, const char *arg)
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

int handle_stop_cmd(struct unix_ctx *ctx, const char *arg)
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

int handle_disconnect_user_cmd(struct unix_ctx *ctx, const char *arg)
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

int handle_disconnect_id_cmd(struct unix_ctx *ctx, const char *arg)
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

int handle_list_users_cmd(struct unix_ctx *ctx, const char *arg)
{
	int ret;
	struct cmd_reply_st raw;
	UserListRep *rep = NULL;
	unsigned i;
	const char *vpn_ip, *groupname, *username;
	const char *dtls_ciphersuite;
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

	for (i=0;i<rep->n_user;i++) {
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

		username = rep->user[i]->username;
		if (username == NULL || username[0] == 0)
			username = NO_USER;

		fprintf(out, "%8d %8s %8s %14s %14s %6s ",
			(int)rep->user[i]->id, username, groupname, rep->user[i]->ip, vpn_ip, rep->user[i]->tun);

		print_time_ival7(t, out);

		dtls_ciphersuite = rep->user[i]->dtls_ciphersuite;
		if (dtls_ciphersuite != NULL && dtls_ciphersuite[0] != 0) {
			if (strlen(dtls_ciphersuite) > 16 && strncmp(dtls_ciphersuite, "(DTLS", 5) == 0 &&
			    strncmp(&dtls_ciphersuite[8], ")-(RSA)-", 8) == 0)
				dtls_ciphersuite += 16;
			fprintf(out, " %14s %9s\n", dtls_ciphersuite, rep->user[i]->status);
		} else {
			fprintf(out, " %14s %9s\n", "(no dtls)", rep->user[i]->status);
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

int print_list_entries(FILE* out, const char* name, char **val, unsigned vsize)
{
	const char * tmp;
	unsigned int i = 0;

	for (i=0;i<vsize;i++) {
		tmp = val[i];
		if (tmp != NULL) {
			if (i==0)
				fprintf(out, "%s %s\n", name, tmp);
			else
				fprintf(out, "\t\t%s\n", tmp);
		}
	}

	return i;
}

int common_info_cmd(UserListRep * args)
{
	char *username = "";
	char *groupname = "";
	char str_since[64];
	struct tm *tm;
	time_t t;
	FILE *out;
	unsigned at_least_one = 0;
	int ret = 1, r;
	unsigned i;

	out = pager_start();

	for (i=0;i<args->n_user;i++) {
		if (at_least_one > 0)
			fprintf(out, "\n");
		fprintf(out, "ID: %d\n", (int)args->user[i]->id);

		t = args->user[i]->conn_time;
		tm = localtime(&t);
		strftime(str_since, sizeof(str_since), DATE_TIME_FMT, tm);

		username = args->user[i]->username;
		if (username == NULL || username[0] == 0)
			username = NO_USER;

		fprintf(out, "\tUsername: %s  ", username);

		groupname = args->user[i]->groupname;
		if (groupname == NULL || groupname[0] == 0)
			groupname = NO_GROUP;

		fprintf(out, "Groupname: %s\n", groupname);
		fprintf(out, "\tState: %s  ", args->user[i]->status);
		fprintf(out, "Remote IP: %s\n", args->user[i]->ip);

		if (args->user[i]->local_ip != NULL && args->user[i]->local_ip[0] != 0 &&
		    args->user[i]->remote_ip != NULL && args->user[i]->remote_ip[0] != 0) {
			fprintf(out, "\tIPv4: %s  ", args->user[i]->local_ip);
			fprintf(out, "P-t-P IPv4: %s\n", args->user[i]->remote_ip);
		}
		if (args->user[i]->local_ip6 != NULL && args->user[i]->local_ip6[0] != 0 &&
		    args->user[i]->remote_ip6 != NULL && args->user[i]->remote_ip6[0] != 0) {
			fprintf(out, "\tIPv6: %s  ", args->user[i]->local_ip6);
			fprintf(out, "P-t-P IPv6: %s\n", args->user[i]->remote_ip6);
		}
		fprintf(out, "\tDevice: %s  ", args->user[i]->tun);

		if (args->user[i]->has_mtu != 0)
			fprintf(out, "MTU: %d\n", args->user[i]->mtu);
		else
			fprintf(out, "\n");

		if (args->user[i]->user_agent != NULL && args->user[i]->user_agent[0] != 0)
			fprintf(out, "\tUser-Agent: %s\n", args->user[i]->user_agent);

		if (args->user[i]->rx_per_sec > 0 || args->user[i]->tx_per_sec > 0) {
			/* print limits */
			char buf[32];

			if (args->user[i]->rx_per_sec > 0 && args->user[i]->tx_per_sec > 0) {
				bytes2human(args->user[i]->rx_per_sec, buf, sizeof(buf), NULL);
				fprintf(out, "\tLimit RX: %s/sec  ", buf);

				bytes2human(args->user[i]->tx_per_sec, buf, sizeof(buf), NULL);
				fprintf(out, "TX: %s/sec\n", buf);
			} else if (args->user[i]->tx_per_sec > 0) {
				bytes2human(args->user[i]->tx_per_sec, buf, sizeof(buf), NULL);
				fprintf(out, "\tLimit TX: %s/sec\n", buf);
			} else if (args->user[i]->rx_per_sec > 0) {
				bytes2human(args->user[i]->rx_per_sec, buf, sizeof(buf), NULL);
				fprintf(out, "\tLimit RX: %s/sec\n", buf);
			}
		}

		print_iface_stats(args->user[i]->tun, args->user[i]->conn_time, out);

		if (args->user[i]->hostname != NULL && args->user[i]->hostname[0] != 0)
			fprintf(out, "\tHostname: %s\n", args->user[i]->hostname);

		fprintf(out, "\tConnected at: %s (", str_since);
		print_time_ival7(t, out);
		fprintf(out, ")\n");

		fprintf(out, "\tTLS ciphersuite: %s\n", args->user[i]->tls_ciphersuite);
		if (args->user[i]->dtls_ciphersuite != NULL && args->user[i]->dtls_ciphersuite[0] != 0)
			fprintf(out, "\tDTLS cipher: %s\n", args->user[i]->dtls_ciphersuite);

		if (args->user[i]->cstp_compr && args->user[i]->cstp_compr[0] != 0)
			fprintf(out, "\tCSTP compression: %s\n", args->user[i]->cstp_compr);
		if (args->user[i]->dtls_compr != NULL && args->user[i]->dtls_compr[0] != 0)
			fprintf(out, "\tDTLS compression: %s\n", args->user[i]->dtls_compr);

		/* user network info */
		fputs("\n", out);
		if (print_list_entries(out, "\tDNS:", args->user[i]->dns, args->user[i]->n_dns) < 0)
			goto error_parse;

		if (print_list_entries(out, "\tNBNS:", args->user[i]->nbns, args->user[i]->n_nbns) < 0)
			goto error_parse;

		if ((r = print_list_entries(out, "\tRoutes:", args->user[i]->routes, args->user[i]->n_routes)) < 0)
			goto error_parse;
		if (r == 0) {
			fprintf(out, "Routes: defaultroute\n");
		}

		if ((r = print_list_entries(out, "\tNo-routes:", args->user[i]->no_routes, args->user[i]->n_no_routes)) < 0)
			goto error_parse;

		if (print_list_entries(out, "\tiRoutes:", args->user[i]->iroutes, args->user[i]->n_iroutes) < 0)
			goto error_parse;

		at_least_one = 1;
	}

	ret = 0;
	goto cleanup;

 error_parse:
	fprintf(stderr, "%s: message parsing error\n", __func__);
	goto cleanup;
 cleanup:
	if (at_least_one == 0) {
		fprintf(out, "user or ID not found\n");
		ret = 2;
	}
	pager_stop(out);

	return ret;
}

int handle_show_user_cmd(struct unix_ctx *ctx, const char *arg)
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

	ret = common_info_cmd(rep);
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

int handle_show_id_cmd(struct unix_ctx *ctx, const char *arg)
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

	ret = common_info_cmd(rep);
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
