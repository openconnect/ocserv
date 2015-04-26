/*
 * Copyright (C) 2014 Red Hat
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <main.h>
#include <vpn.h>
#include <ip-lease.h>

#include <errno.h>
#include <main-ctl.h>
#include <main-ban.h>
#include <dbus/dbus.h>
#include <str.h>

#define OCSERV_DBUS_NAME "org.infradead.ocserv"

struct ctl_list_st {
	struct list_head head;
};

struct dbus_ctx {
	struct ctl_list_st ctl_list;
	DBusConnection *conn;
};

static void method_status(main_server_st * s, struct dbus_ctx *ctx,
			  DBusMessage * msg);
static void method_list_users(main_server_st * s, struct dbus_ctx *ctx,
			      DBusMessage * msg);
static void method_unban_ip(main_server_st * s,
					struct dbus_ctx *ctx,
					DBusMessage * msg);
static void method_disconnect_user_name(main_server_st * s,
					struct dbus_ctx *ctx,
					DBusMessage * msg);
static void method_disconnect_user_id(main_server_st * s, struct dbus_ctx *ctx,
				      DBusMessage * msg);
static void method_introspect(main_server_st * s, struct dbus_ctx *ctx,
			      DBusMessage * msg);
static void method_stop(main_server_st * s, struct dbus_ctx *ctx,
			DBusMessage * msg);
static void method_reload(main_server_st * s, struct dbus_ctx *ctx,
			  DBusMessage * msg);
static void method_user_info(main_server_st * s, struct dbus_ctx *ctx,
			     DBusMessage * msg);
static void method_id_info(main_server_st * s, struct dbus_ctx *ctx,
			   DBusMessage * msg);
static void method_list_banned(main_server_st * s, struct dbus_ctx *ctx,
			      DBusMessage * msg);

typedef void (*method_func) (main_server_st * s, struct dbus_ctx *ctx,
			     DBusMessage * msg);
#define CTL_READ 1
#define CTL_WRITE 2

struct ctl_handler_st {
	struct list_node list;
	int fd;
	unsigned type;		/* CTL_READ/WRITE */
	unsigned enabled;
	void *watch;
};

typedef struct {
	char *name;
	unsigned name_size;
	char *iface;
	unsigned iface_size;
	char *desc;
	unsigned desc_size;
	method_func func;
} ctl_method_st;

#define ENTRY(name, iface, desc, func) \
	{name, sizeof(name)-1, iface, sizeof(iface)-1, desc, sizeof(desc)-1, func}

#define COMMON_USERS_SIG       "issssssssusssss"

#define LIST_USERS_SIG       "("COMMON_USERS_SIG")"
#define LIST_SINGLE_USER_SIG "("COMMON_USERS_SIG"ssuuuasasasasas)"
#define LIST_BANNED_SIG "(usu)"

#define DESC_LIST \
		"    <method name=\"list\">\n" \
		"      <arg name=\"user-info\" direction=\"out\" type=\"a"LIST_USERS_SIG"\"/>\n" \
		"    </method>\n"

#define DESC_LIST_BANNED \
		"    <method name=\"list\">\n" \
		"      <arg name=\"banned-info\" direction=\"out\" type=\"a"LIST_BANNED_SIG"\"/>\n" \
		"    </method>\n"

#define DESC_USER_INFO \
		"    <method name=\"user_info\">\n" \
		"      <arg name=\"user-info\" direction=\"out\" type=\"a"LIST_SINGLE_USER_SIG"\"/>\n" \
		"    </method>\n"

/* ID-INFO returns an array of 0 or 1 elements */
#define DESC_ID_INFO \
		"    <method name=\"id_info\">\n" \
		"      <arg name=\"id-info\" direction=\"out\" type=\"a"LIST_SINGLE_USER_SIG"\"/>\n" \
		"    </method>\n"

#define DESC_DISC_NAME \
		"    <method name=\"disconnect_name\">\n" \
		"      <arg name=\"user-name\" direction=\"in\" type=\"s\"/>\n" \
		"      <arg name=\"status\" direction=\"out\" type=\"b\"/>\n" \
        	"    </method>\n"

#define DESC_RELOAD \
		"    <method name=\"reload\">\n" \
		"      <arg name=\"status\" direction=\"out\" type=\"b\"/>\n" \
        	"    </method>\n"

#define DESC_STOP \
		"    <method name=\"stop\">\n" \
		"      <arg name=\"status\" direction=\"out\" type=\"b\"/>\n" \
        	"    </method>\n"

#define DESC_DISC_ID \
		"    <method name=\"disconnect_id\">\n" \
		"      <arg name=\"user-id\" direction=\"in\" type=\"u\"/>\n" \
		"      <arg name=\"status\" direction=\"out\" type=\"b\"/>\n" \
		"    </method>\n"

#define DESC_UNBAN_IP \
		"    <method name=\"unban_ip\">\n" \
		"      <arg name=\"user-ip\" direction=\"in\" type=\"s\"/>\n" \
		"      <arg name=\"status\" direction=\"out\" type=\"b\"/>\n" \
		"    </method>\n"

#define DESC_STATUS \
		"    <method name=\"status\">\n" \
		"      <arg name=\"status\" direction=\"out\" type=\"b\"/>\n" \
		"      <arg name=\"pid\" direction=\"out\" type=\"u\"/>\n" \
		"      <arg name=\"sec-mod-pid\" direction=\"out\" type=\"u\"/>\n" \
		"      <arg name=\"clients\" direction=\"out\" type=\"u\"/>\n" \
		"      <arg name=\"secmod-client-entries\" direction=\"out\" type=\"u\"/>\n" \
		"      <arg name=\"tls-sessions\" direction=\"out\" type=\"u\"/>\n" \
		"      <arg name=\"banned-ips\" direction=\"out\" type=\"u\"/>\n" \
		"    </method>\n"

static const ctl_method_st methods[] = {
	ENTRY("Introspect", "org.freedesktop.DBus.Introspectable", NULL,
	      method_introspect),
	ENTRY("status", "org.infradead.ocserv", DESC_STATUS, method_status),
	ENTRY("reload", "org.infradead.ocserv", DESC_RELOAD, method_reload),
	ENTRY("stop", "org.infradead.ocserv", DESC_RELOAD, method_stop),
	ENTRY("list", "org.infradead.ocserv", DESC_LIST, method_list_users),
	ENTRY("list_banned", "org.infradead.ocserv", DESC_LIST_BANNED, method_list_banned),
	ENTRY("user_info2", "org.infradead.ocserv", DESC_USER_INFO,
	      method_user_info),
	ENTRY("id_info2", "org.infradead.ocserv", DESC_ID_INFO, method_id_info),
	ENTRY("disconnect_name", "org.infradead.ocserv", DESC_DISC_NAME,
	      method_disconnect_user_name),
	ENTRY("unban_ip", "org.infradead.ocserv", DESC_UNBAN_IP,
	      method_unban_ip),
	ENTRY("disconnect_id", "org.infradead.ocserv", DESC_DISC_ID,
	      method_disconnect_user_id),
	{NULL, 0, NULL, 0, NULL}
};

static void add_ctl_fd(struct dbus_ctx *ctx, int fd, void *watch, unsigned type)
{
	struct ctl_handler_st *tmp;

	tmp = talloc_zero(ctx, struct ctl_handler_st);
	if (tmp == NULL)
		return;

	tmp->fd = fd;
	if (dbus_watch_get_enabled(watch))
		tmp->enabled = 1;
	else
		tmp->enabled = 0;
	tmp->watch = watch;
	tmp->type = type;

	syslog(LOG_DEBUG, "dbus: adding %s %swatch for fd: %d",
	      (type == CTL_READ) ? "read" : "write",
	      (tmp->enabled) ? "" : "(disabled) ", fd);

	list_add(&ctx->ctl_list.head, &(tmp->list));
}

static dbus_bool_t add_watch(DBusWatch * watch, void *data)
{
	int fd = dbus_watch_get_unix_fd(watch);
	struct dbus_ctx *ctx = data;
	unsigned flags;

	flags = dbus_watch_get_flags(watch);

	if (flags & DBUS_WATCH_READABLE) {
		add_ctl_fd(ctx, fd, watch, CTL_READ);
	} else {
		add_ctl_fd(ctx, fd, watch, CTL_WRITE);
	}

	return 1;
}

static void remove_watch(DBusWatch * watch, void *data)
{
	struct dbus_ctx *ctx = data;
	struct ctl_handler_st *btmp = NULL, *bpos;

	list_for_each_safe(&ctx->ctl_list.head, btmp, bpos, list) {
		if (btmp->watch == watch) {
			syslog(LOG_DEBUG,
			      "dbus: removing %s watch for fd: %d",
			      (btmp->type == CTL_READ) ? "read" : "write",
			      btmp->fd);

			list_del(&btmp->list);
			talloc_free(btmp);
			return;
		}
	}
}

static void toggle_watch(DBusWatch * watch, void *data)
{
	struct dbus_ctx *ctx = data;
	struct ctl_handler_st *btmp = NULL;

	list_for_each(&ctx->ctl_list.head, btmp, list) {
		if (btmp->watch == watch) {
			if (dbus_watch_get_enabled(watch)) {
				btmp->enabled = 1;
			} else
				btmp->enabled = 0;

			syslog(LOG_DEBUG,
			      "dbus: %s %s watch for fd: %d",
			      (btmp->enabled) ? "enabling" : "disabling",
			      (btmp->type == CTL_READ) ? "read" : "write",
			      btmp->fd);
			return;
		}
	}
}


static void method_status(main_server_st * s, struct dbus_ctx *ctx,
			  DBusMessage * msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	dbus_bool_t status = true;
	dbus_uint32_t tmp;

	mslog(s, NULL, LOG_DEBUG, "ctl: status");

	/* no arguments needed */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		return;
	}

	dbus_message_iter_init_append(reply, &args);

	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &status) ==
	    0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	tmp = getpid();
	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &tmp) == 0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	tmp = s->sec_mod_pid;
	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &tmp) == 0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	tmp = s->active_clients;
	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &tmp) == 0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	tmp = s->secmod_client_entries;
	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &tmp) == 0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	tmp = s->tls_db.entries;
	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &tmp) == 0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_UINT32, &tmp) == 0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	dbus_message_unref(reply);

	return;
}

static void method_reload(main_server_st * s, struct dbus_ctx *ctx,
			  DBusMessage * msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	dbus_bool_t status = true;

	mslog(s, NULL, LOG_DEBUG, "ctl: reload");

	/* no arguments needed */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		return;
	}

	dbus_message_iter_init_append(reply, &args);

	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &status) ==
	    0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	request_reload(0);

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	dbus_message_unref(reply);

	return;
}

static void method_stop(main_server_st * s, struct dbus_ctx *ctx,
			DBusMessage * msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	dbus_bool_t status = true;

	mslog(s, NULL, LOG_DEBUG, "ctl: stop");

	/* no arguments needed */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		return;
	}

	dbus_message_iter_init_append(reply, &args);

	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &status) ==
	    0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	request_stop(0);

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	dbus_message_unref(reply);

	return;
}

static int append_list(DBusMessageIter * subs, char **list, unsigned list_size)
{
	DBusMessageIter suba;
	unsigned i;

	if (dbus_message_iter_open_container
	    (subs, DBUS_TYPE_ARRAY, "s", &suba) == 0) {
		return -1;
	}

	for (i = 0; i < list_size; i++) {
		if (dbus_message_iter_append_basic
		    (&suba, DBUS_TYPE_STRING, &list[i]) == 0) {
			return -1;
		}
	}

	if (dbus_message_iter_close_container(subs, &suba) == 0) {
		return -1;
	}

	return 0;
}

static int append_user_info(main_server_st * s, DBusMessageIter * subs,
			    struct proc_st *ctmp, unsigned single)
{
	dbus_uint32_t tmp;
	dbus_int32_t stmp;
	char ipbuf[128];
	const char *strtmp;
	char **list;
	unsigned list_size;
	int ret;

	/* ID: pid */
	stmp = ctmp->pid;
	if (dbus_message_iter_append_basic(subs, DBUS_TYPE_INT32, &stmp) == 0) {
		return -1;
	}

	strtmp = ctmp->username;
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	strtmp = ctmp->groupname;
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	strtmp =
	    human_addr2((struct sockaddr *)&ctmp->remote_addr,
			ctmp->remote_addr_len, ipbuf, sizeof(ipbuf), 0);
	if (strtmp == NULL)
		strtmp = "";
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}
	strtmp = ctmp->tun_lease.name;
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	strtmp = NULL;
	if (ctmp->ipv4 != NULL)
		strtmp =
		    human_addr2((struct sockaddr *)&ctmp->ipv4->rip,
				ctmp->ipv4->rip_len, ipbuf, sizeof(ipbuf), 0);
	if (strtmp == NULL)
		strtmp = "";
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	strtmp = NULL;
	if (ctmp->ipv4 != NULL)
		strtmp =
		    human_addr2((struct sockaddr *)&ctmp->ipv4->lip,
				ctmp->ipv4->lip_len, ipbuf, sizeof(ipbuf), 0);
	if (strtmp == NULL)
		strtmp = "";
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	strtmp = NULL;
	if (ctmp->ipv6 != NULL)
		strtmp =
		    human_addr2((struct sockaddr *)&ctmp->ipv6->rip,
				ctmp->ipv6->rip_len, ipbuf, sizeof(ipbuf), 0);
	if (strtmp == NULL)
		strtmp = "";
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	strtmp = NULL;
	if (ctmp->ipv6 != NULL)
		strtmp =
		    human_addr2((struct sockaddr *)&ctmp->ipv6->lip,
				ctmp->ipv6->lip_len, ipbuf, sizeof(ipbuf), 0);
	if (strtmp == NULL)
		strtmp = "";
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}
	tmp = ctmp->conn_time;
	if (dbus_message_iter_append_basic(subs, DBUS_TYPE_UINT32, &tmp) == 0) {
		return -1;
	}

	strtmp = ctmp->hostname;
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	strtmp = ctmp->user_agent;
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	if (ctmp->status == PS_AUTH_COMPLETED)
		strtmp = "connected";
	else if (ctmp->status == PS_AUTH_INIT)
		strtmp = "auth";
	else if (ctmp->status == PS_AUTH_INACTIVE)
		strtmp = "pre-auth";
	else if (ctmp->status == PS_AUTH_FAILED)
		strtmp = "auth failed";
	else
		strtmp = "unknown";
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	strtmp = ctmp->tls_ciphersuite;
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}

	strtmp = ctmp->dtls_ciphersuite;
	if (dbus_message_iter_append_basic
	    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
		return -1;
	}


	if (single > 0) {
		strtmp = ctmp->cstp_compr;
		if (dbus_message_iter_append_basic
		    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
			return -1;
		}

		strtmp = ctmp->dtls_compr;
		if (dbus_message_iter_append_basic
		    (subs, DBUS_TYPE_STRING, &strtmp) == 0) {
			return -1;
		}

		tmp = ctmp->mtu;
		if (dbus_message_iter_append_basic
		    (subs, DBUS_TYPE_UINT32, &tmp) == 0) {
			return -1;
		}

		if (ctmp->config.rx_per_sec > 0)
			tmp = ctmp->config.rx_per_sec;
		else
			tmp = s->config->rx_per_sec;
		tmp *= 1000;
		if (dbus_message_iter_append_basic(subs, DBUS_TYPE_UINT32, &tmp)
		    == 0) {
			return -1;
		}

		if (ctmp->config.tx_per_sec > 0)
			tmp = ctmp->config.tx_per_sec;
		else
			tmp = s->config->tx_per_sec;
		tmp *= 1000;
		if (dbus_message_iter_append_basic(subs, DBUS_TYPE_UINT32, &tmp)
		    == 0) {
			return -1;
		}

		if (ctmp->config.dns_size > 0) {
			list = ctmp->config.dns;
			list_size = ctmp->config.dns_size;
		} else {
			list = s->config->network.dns;
			list_size = s->config->network.dns_size;
		}
		ret = append_list(subs, list, list_size);
		if (ret < 0)
			return ret;

		if (ctmp->config.nbns_size > 0) {
			list = ctmp->config.nbns;
			list_size = ctmp->config.nbns_size;
		} else {
			list = s->config->network.nbns;
			list_size = s->config->network.nbns_size;
		}
		ret = append_list(subs, list, list_size);
		if (ret < 0)
			return ret;

		if (ctmp->config.routes_size > 0) {
			list = ctmp->config.routes;
			list_size = ctmp->config.routes_size;
		} else {
			list = s->config->network.routes;
			list_size = s->config->network.routes_size;
		}
		ret = append_list(subs, list, list_size);
		if (ret < 0)
			return ret;

		if (ctmp->config.no_routes_size > 0) {
			list = ctmp->config.no_routes;
			list_size = ctmp->config.no_routes_size;
		} else {
			list = s->config->network.no_routes;
			list_size = s->config->network.no_routes_size;
		}
		ret = append_list(subs, list, list_size);
		if (ret < 0)
			return ret;

		if (ctmp->config.iroutes_size > 0) {
			list = ctmp->config.iroutes;
			list_size = ctmp->config.iroutes_size;
		} else {
			list = NULL;
			list_size = 0;
		}
		ret = append_list(subs, list, list_size);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static void method_list_users(main_server_st * s, struct dbus_ctx *ctx,
			      DBusMessage * msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	DBusMessageIter suba;
	DBusMessageIter subs;
	struct proc_st *ctmp = NULL;
	int ret;

	mslog(s, NULL, LOG_DEBUG, "ctl: list-users");

	/* no arguments needed */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		return;
	}

	dbus_message_iter_init_append(reply, &args);
	if (dbus_message_iter_open_container
	    (&args, DBUS_TYPE_ARRAY, LIST_USERS_SIG, &suba) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "error appending container to dbus reply");
		goto error;
	}

	list_for_each(&s->proc_list.head, ctmp, list) {

		if (dbus_message_iter_open_container
		    (&suba, DBUS_TYPE_STRUCT, NULL, &subs) == 0) {
			mslog(s, NULL, LOG_ERR,
			      "error appending container to dbus reply");
			goto error;
		}

		ret = append_user_info(s, &subs, ctmp, 0);
		if (ret < 0) {
			mslog(s, NULL, LOG_ERR,
			      "error appending container to dbus reply");
			goto error;
		}

		if (dbus_message_iter_close_container(&suba, &subs) == 0) {
			mslog(s, NULL, LOG_ERR,
			      "error closing container in dbus reply");
			goto error;
		}
	}

	if (dbus_message_iter_close_container(&args, &suba) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "error closing container in dbus reply");
		goto error;
	}

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	dbus_message_unref(reply);

	return;
}

static int append_ban_info(main_server_st *s,
			    DBusMessageIter *suba,
			    struct ban_entry_st *e)
{
	DBusMessageIter subs;
	dbus_uint32_t t;
	char *ip;

	if (dbus_message_iter_open_container
	    (suba, DBUS_TYPE_STRUCT, NULL, &subs) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "error appending container to dbus reply");
		return -1;
	}

	t = e->score;
	if (dbus_message_iter_append_basic(&subs, DBUS_TYPE_UINT32, &t) == 0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		return -1;
	}

	ip = e->ip;
	if (dbus_message_iter_append_basic(&subs, DBUS_TYPE_STRING, &ip) == 0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		return -1;
	}

	if (s->config->max_ban_score > 0 && e->score >= s->config->max_ban_score) {
		t = e->expires;
	} else {
		t = 0;
	}

	if (dbus_message_iter_append_basic(&subs, DBUS_TYPE_UINT32, &t) == 0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		return -1;
	}

	if (dbus_message_iter_close_container(suba, &subs) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "error closing container in dbus reply");
		return -1;
	}

	return 0;
}

static void method_list_banned(main_server_st * s, struct dbus_ctx *ctx,
			      DBusMessage * msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	DBusMessageIter suba;
	int ret;
	struct ban_entry_st *e = NULL;
	struct htable *db = s->ban_db;
	struct htable_iter iter;

	mslog(s, NULL, LOG_DEBUG, "ctl: list-banned");

	/* no arguments needed */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		return;
	}

	dbus_message_iter_init_append(reply, &args);
	if (dbus_message_iter_open_container
	    (&args, DBUS_TYPE_ARRAY, LIST_BANNED_SIG, &suba) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "error appending container to dbus reply");
		goto error;
	}

	e = htable_first(db, &iter);
	while (e != NULL) {
		ret = append_ban_info(s, &suba, e);
		if (ret < 0) {
			mslog(s, NULL, LOG_ERR,
			      "error appending ban info to reply");
			goto error;
		}
		e = htable_next(db, &iter);
	}

	if (dbus_message_iter_close_container(&args, &suba) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "error closing container in dbus reply");
		goto error;
	}

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	dbus_message_unref(reply);

	return;
}

static void single_info_common(main_server_st * s, struct dbus_ctx *ctx,
			       DBusMessage * msg, const char *user, unsigned id)
{
	DBusMessage *reply;
	DBusMessageIter args;
	DBusMessageIter suba;
	DBusMessageIter subs;
	int ret;
	unsigned found_user = 0;
	struct proc_st *ctmp = NULL;

	if (user != NULL)
		mslog(s, NULL, LOG_DEBUG, "providing info for user '%s'", user);
	else
		mslog(s, NULL, LOG_DEBUG, "providing info for ID '%u'", id);

	/* no arguments needed */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		return;
	}

	dbus_message_iter_init_append(reply, &args);
	if (dbus_message_iter_open_container
	    (&args, DBUS_TYPE_ARRAY, LIST_SINGLE_USER_SIG, &suba) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "error appending container to dbus reply");
		goto error;
	}

	list_for_each(&s->proc_list.head, ctmp, list) {
		if (user == NULL) {	/* id */
			if (id == 0 || id == -1 || id != ctmp->pid) {
				continue;
			}
		} else {	/* username */
			if (strcmp(ctmp->username, user) != 0) {
				continue;
			}
		}

		if (dbus_message_iter_open_container
		    (&suba, DBUS_TYPE_STRUCT, NULL, &subs) == 0) {
			mslog(s, NULL, LOG_ERR,
			      "error appending container to dbus reply");
			goto error;
		}

		ret = append_user_info(s, &subs, ctmp, 1);
		if (ret < 0) {
			mslog(s, NULL, LOG_ERR,
			      "error appending to dbus reply");
			goto error;
		}

		if (dbus_message_iter_close_container(&suba, &subs) == 0) {
			mslog(s, NULL, LOG_ERR,
			      "error closing container in dbus reply");
			goto error;
		}

		found_user = 1;

		if (id != 0)	/* id -> one a single element */
			break;
	}

	if (dbus_message_iter_close_container(&args, &suba) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "error closing container in dbus reply");
		goto error;
	}

	if (found_user == 0) {
		if (user != NULL)
			mslog(s, NULL, LOG_DEBUG, "could not find user '%s'",
			      user);
		else
			mslog(s, NULL, LOG_DEBUG, "could not find ID '%u'", id);
	}

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	dbus_message_unref(reply);

	return;
}

static void method_user_info(main_server_st * s, struct dbus_ctx *ctx,
			     DBusMessage * msg)
{
	DBusMessageIter args;
	const char *name;

	mslog(s, NULL, LOG_DEBUG, "ctl: user_info (name)");

	if (dbus_message_iter_init(msg, &args) == 0) {
		mslog(s, NULL, LOG_ERR, "no arguments provided in user_info");
		return;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		mslog(s, NULL, LOG_ERR, "wrong argument provided in user_info");
		return;
	}

	dbus_message_iter_get_basic(&args, &name);

	single_info_common(s, ctx, msg, name, 0);

	return;
}

static void method_id_info(main_server_st * s, struct dbus_ctx *ctx,
			   DBusMessage * msg)
{
	DBusMessageIter args;
	dbus_uint32_t id;

	mslog(s, NULL, LOG_DEBUG, "ctl: user_info (id)");

	if (dbus_message_iter_init(msg, &args) == 0) {
		mslog(s, NULL, LOG_ERR, "no arguments provided in user_info");
		return;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_UINT32) {
		mslog(s, NULL, LOG_ERR, "wrong argument provided in user_info");
		return;
	}

	dbus_message_iter_get_basic(&args, &id);

	single_info_common(s, ctx, msg, NULL, id);

	return;
}

static void method_unban_ip(main_server_st * s,
			    struct dbus_ctx *ctx,
			    DBusMessage * msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	dbus_bool_t status = 0;
	char *ip = "";

	mslog(s, NULL, LOG_DEBUG, "ctl: unban_ip");

	if (dbus_message_iter_init(msg, &args) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "no arguments provided in unban_ip");
		return;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		mslog(s, NULL, LOG_ERR,
		      "wrong argument provided in unban_ip");
		return;
	}

	dbus_message_iter_get_basic(&args, &ip);

	if (remove_ip_from_ban_list(s, ip) != 0) {
		if (ip)
			mslog(s, NULL, LOG_INFO,
				      "unbanning IP '%s' due to ctl request", ip);
		status = 1;
	}

	/* reply */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		return;
	}

	dbus_message_iter_init_append(reply, &args);

	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &status) ==
	    0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	dbus_message_unref(reply);

	return;
}

static void method_disconnect_user_name(main_server_st * s,
					struct dbus_ctx *ctx,
					DBusMessage * msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	dbus_bool_t status = 0;
	struct proc_st *ctmp = NULL, *cpos;
	char *name = "";

	mslog(s, NULL, LOG_DEBUG, "ctl: disconnect_name");

	if (dbus_message_iter_init(msg, &args) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "no arguments provided in disconnect_name");
		return;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		mslog(s, NULL, LOG_ERR,
		      "wrong argument provided in disconnect_name");
		return;
	}

	dbus_message_iter_get_basic(&args, &name);

	/* got the name. Try to disconnect */
	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		if (strcmp(ctmp->username, name) == 0) {
			terminate_proc(s, ctmp);
			status = 1;
		}
	}

	/* reply */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		return;
	}

	dbus_message_iter_init_append(reply, &args);

	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &status) ==
	    0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	dbus_message_unref(reply);

	return;
}

static void method_disconnect_user_id(main_server_st * s, struct dbus_ctx *ctx,
				      DBusMessage * msg)
{
	DBusMessage *reply;
	DBusMessageIter args;
	dbus_bool_t status = 0;
	struct proc_st *ctmp = NULL, *cpos;
	dbus_uint32_t id = 0;

	mslog(s, NULL, LOG_DEBUG, "ctl: disconnect_id");

	if (dbus_message_iter_init(msg, &args) == 0) {
		mslog(s, NULL, LOG_ERR,
		      "no arguments provided in disconnect_id");
		return;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_UINT32) {
		mslog(s, NULL, LOG_ERR,
		      "wrong argument provided in disconnect_id");
		return;
	}

	dbus_message_iter_get_basic(&args, &id);

	/* got the ID. Try to disconnect */
	list_for_each_safe(&s->proc_list.head, ctmp, cpos, list) {
		if (ctmp->pid == id) {
			terminate_proc(s, ctmp);
			status = 1;
			if (id != -1)
				break;
		}
	}

	/* reply */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		return;
	}

	dbus_message_iter_init_append(reply, &args);

	if (dbus_message_iter_append_basic(&args, DBUS_TYPE_BOOLEAN, &status) ==
	    0) {
		mslog(s, NULL, LOG_ERR, "error appending to dbus reply");
		goto error;
	}

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	dbus_message_unref(reply);

	return;
}

#define XML_HEAD \
	"<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n" \
	"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n" \
        "<node name=\"/org/infradead/ocserv\">\n" \
	"<interface name=\"org.infradead.ocserv\">\n"

#define XML_FOOT \
	"</interface>" \
	"</node>\n"

static void method_introspect(main_server_st * s, struct dbus_ctx *ctx,
			      DBusMessage * msg)
{
	DBusMessage *reply = NULL;
	const char *xml;
	str_st buf;
	int ret;
	unsigned i;

	mslog(s, NULL, LOG_DEBUG, "ctl: introspect");

	str_init(&buf, ctx);

	ret = str_append_data(&buf, XML_HEAD, sizeof(XML_HEAD) - 1);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		goto error;
	}

	for (i = 0; methods[i].name != NULL; i++) {
		if (methods[i].desc == NULL) continue;

		ret =
		    str_append_data(&buf, methods[i].desc,
				    methods[i].desc_size);
		if (ret < 0) {
			mslog(s, NULL, LOG_ERR, "error generating dbus reply");
			goto error;
		}
	}

	ret = str_append_data(&buf, XML_FOOT, sizeof(XML_FOOT) - 1);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		goto error;
	}

	/* no arguments needed */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		mslog(s, NULL, LOG_ERR, "error generating dbus reply");
		goto error;
	}

	xml = (char *)buf.data;
	if (dbus_message_append_args
	    (reply, DBUS_TYPE_STRING, &xml, DBUS_TYPE_INVALID) == 0) {
		mslog(s, NULL, LOG_ERR, "error in introspect to dbus reply");
		goto error;
	}

	if (!dbus_connection_send(ctx->conn, reply, NULL)) {
		mslog(s, NULL, LOG_ERR, "error sending dbus reply");
		goto error;
	}

 error:
	str_clear(&buf);
	if (reply)
		dbus_message_unref(reply);

	return;

}

static void ctl_handle_commands(main_server_st * s, struct ctl_handler_st *ctl)
{
	struct dbus_ctx *ctx = s->ctl_ctx;
	DBusConnection *conn;
	DBusMessage *msg;
	int ret;
	unsigned flags, i;

	if (s->config->use_dbus == 0 || ctx == NULL) {
		return;
	}

	conn = ctx->conn;

	if (ctl->type == CTL_READ)
		flags = DBUS_WATCH_READABLE;
	else
		flags = DBUS_WATCH_WRITABLE;

	dbus_connection_ref(conn);
	ret = dbus_watch_handle(ctl->watch, flags);
	dbus_connection_unref(conn);

	if (ret == 0) {
		mslog(s, NULL, LOG_ERR, "error handling watch");
		return;
	}

	do {
		if (dbus_connection_read_write(conn, 0) == 0) {
			mslog(s, NULL, LOG_ERR,
			      "error handling dbus_connection_read_write");
			return;
		}

		msg = dbus_connection_pop_message(conn);
		if (msg == NULL)
			return;

		for (i = 0;; i++) {
			if (methods[i].name == NULL) {
				mslog(s, NULL, LOG_DEBUG,
				      "unknown D-BUS message: %s.%s: %s",
				      dbus_message_get_interface(msg),
				      dbus_message_get_member(msg),
				      dbus_message_get_path(msg));
				break;
			}
			if (dbus_message_is_method_call
			    (msg, methods[i].iface, methods[i].name)) {
				methods[i].func(s, ctx, msg);
				break;
			}
		}

		dbus_message_unref(msg);
	} while (msg != NULL);
}

int ctl_handler_set_fds(main_server_st * s, fd_set * rd_set, fd_set * wr_set)
{
	struct ctl_handler_st *ctl_tmp = NULL;
	struct dbus_ctx *ctx = s->ctl_ctx;
	int n = -1;

	if (ctx == NULL)
		return -1;

	list_for_each(&ctx->ctl_list.head, ctl_tmp, list) {
		if (ctl_tmp->enabled) {
			if (ctl_tmp->type == CTL_READ)
				FD_SET(ctl_tmp->fd, rd_set);
			else
				FD_SET(ctl_tmp->fd, wr_set);
			n = MAX(n, ctl_tmp->fd);
		}
	}

	return n;
}

void ctl_handler_run_pending(main_server_st* s, fd_set *rd_set, fd_set *wr_set)
{
	struct ctl_handler_st *ctl_tmp = NULL, *ctl_pos;
	struct dbus_ctx *ctx = s->ctl_ctx;

	if (ctx == NULL)
		return;

	list_for_each_safe(&ctx->ctl_list.head, ctl_tmp, ctl_pos, list) {
		if (ctl_tmp->enabled == 0)
			continue;
		if (ctl_tmp->type == CTL_READ) {
			if (FD_ISSET(ctl_tmp->fd, rd_set))
				ctl_handle_commands(s, ctl_tmp);
		} else {
			if (FD_ISSET(ctl_tmp->fd, wr_set))
				ctl_handle_commands(s, ctl_tmp);
		}
	}
}

void ctl_handler_deinit(main_server_st * s)
{
	struct dbus_ctx *ctx = s->ctl_ctx;

	if (s->config->use_dbus != 0 && ctx != NULL && ctx->conn != NULL) {
		mslog(s, NULL, LOG_DEBUG, "closing DBUS connection");
		dbus_connection_close(ctx->conn);
		dbus_bus_release_name(ctx->conn, OCSERV_DBUS_NAME, NULL);
		dbus_connection_unref(ctx->conn);
	}
}

/* Initializes unix socket and stores the fd.
 */
int ctl_handler_init(main_server_st * s)
{
	int ret;
	DBusError err;
	DBusConnection *conn;
	struct dbus_ctx *ctx;

	if (s->config->use_dbus == 0)
		return 0;

	ctx = talloc_zero(s, struct dbus_ctx);
	if (ctx == NULL)
		return ERR_CTL;

	list_head_init(&ctx->ctl_list.head);
	dbus_error_init(&err);

	conn = dbus_bus_get_private(DBUS_BUS_SYSTEM, &err);
	if (conn == NULL) {
		mslog(s, NULL, LOG_DEBUG, "error initializing DBUS connection");
		goto error;
	}

	ret = dbus_bus_request_name(conn, OCSERV_DBUS_NAME,
				    DBUS_NAME_FLAG_REPLACE_EXISTING, &err);
	if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		mslog(s, NULL, LOG_DEBUG, "error requesting DBUS name");
		goto error;
	}

	ctx->conn = conn;
	s->ctl_ctx = ctx;

	if (!dbus_connection_set_watch_functions(conn,
						 add_watch, remove_watch,
						 toggle_watch, ctx, NULL)) {
		mslog(s, NULL, LOG_DEBUG, "error setting DBUS watchers");
		goto error;
	}
	mslog(s, NULL, LOG_DEBUG, "initialized DBUS connection");


	return 0;

 error:
	if (dbus_error_is_set(&err)) {
		fprintf(stderr, "DBUS connection error (%s)", err.message);
		dbus_error_free(&err);
	}
	ctl_handler_deinit(s);

	return ERR_CTL;
}

