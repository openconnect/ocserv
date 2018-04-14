/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#ifndef SEC_MOD_H
# define SEC_MOD_H

#include <gnutls/abstract.h>
#include <ccan/htable/htable.h>
#include <nettle/base64.h>
#include <tlslib.h>
#include "common/common.h"

#include "vhost.h"

#define SESSION_STR "(session: %.6s)"
#define MAX_GROUPS 32

typedef struct sec_mod_st {
	struct list_head *vconfig;
	void *config_pool;
	void *sec_mod_pool;

	struct htable *client_db;
	int cmd_fd;
	int cmd_fd_sync;

	tls_sess_db_st tls_db;
	uint64_t auth_failures; /* auth failures since the last update (SECM_CLI_STATS) we sent to main */
	uint32_t max_auth_time; /* the maximum time spent in (sucessful) authentication */
	uint32_t avg_auth_time; /* the average time spent in (sucessful) authentication */
	uint32_t total_authentications; /* successful authentications: to calculate the average above */
	time_t last_stats_reset;
} sec_mod_st;

typedef struct stats_st {
	uint64_t bytes_in;
	uint64_t bytes_out;
	time_t uptime;
} stats_st;

typedef struct common_auth_init_st {
	const char *username;
	const char *ip;
	const char *our_ip;
	const char *user_agent;
	unsigned id;
} common_auth_init_st;

typedef struct common_acct_info_st {
	char username[MAX_USERNAME_SIZE*2];
	char groupname[MAX_GROUPNAME_SIZE]; /* the owner's group */
	char safe_id[SAFE_ID_SIZE]; /* an ID to be sent to external apps - printable */
	char remote_ip[MAX_IP_STR];
	char user_agent[MAX_AGENT_NAME];
	char our_ip[MAX_IP_STR];
	char ipv4[MAX_IP_STR];
	char ipv6[MAX_IP_STR];
	unsigned id;
} common_acct_info_st;

#define IS_CLIENT_ENTRY_EXPIRED_FULL(sec, e, now, clean) (e->exptime != -1 && now >= e->exptime && e->in_use == 0)
#define IS_CLIENT_ENTRY_EXPIRED(sec, e, now) IS_CLIENT_ENTRY_EXPIRED_FULL(sec, e, now, 0)

typedef struct client_entry_st {
	/* A unique session identifier used to distinguish sessions
	 * prior to authentication. It is sent as cookie to the client
	 * who re-uses it when it performs authentication in multiple
	 * sessions.
	 */
	uint8_t sid[SID_SIZE];

	void *auth_ctx; /* the context of authentication */
	unsigned session_is_open; /* whether open_session was done */
	unsigned in_use; /* counter of users of this structure */
	unsigned tls_auth_ok;

	char *msg_str;
	unsigned passwd_counter; /* if msg_str is for a password this indicates the passwrd number (0,1,2) */

	stats_st saved_stats; /* saved from previous cookie usage */
	stats_st stats; /* current */

	unsigned status; /* PS_AUTH_ */

	uint8_t dtls_session_id[GNUTLS_MAX_SESSION_ID];

	/* The time this client entry was created */
	time_t created;
	/* The time this client entry is supposed to expire */
	time_t exptime;

	/* the auth type associated with the user */
	unsigned auth_type;
	unsigned discon_reason; /* reason for disconnection */

	struct common_acct_info_st acct_info;

	/* saved during authentication; used after successful auth */
	char req_group_name[MAX_GROUPNAME_SIZE]; /* the requested by the user group */
	char *cert_group_names[MAX_GROUPS];
	unsigned cert_group_names_size;
	char cert_user_name[MAX_USERNAME_SIZE];

	/* the module this entry is using */
	const struct auth_mod_st *module;
	void *vhost_auth_ctx;
	void *vhost_acct_ctx;

	/* the vhost this user is associated with */
	vhost_cfg_st *vhost;
} client_entry_st;

void *sec_mod_client_db_init(sec_mod_st *sec);
void sec_mod_client_db_deinit(sec_mod_st *sec);
unsigned sec_mod_client_db_elems(sec_mod_st *sec);
client_entry_st * new_client_entry(sec_mod_st *sec, struct vhost_cfg_st *, const char *ip, unsigned pid);
client_entry_st * find_client_entry(sec_mod_st *sec, uint8_t sid[SID_SIZE]);
void del_client_entry(sec_mod_st *sec, client_entry_st * e);
void expire_client_entry(sec_mod_st *sec, client_entry_st * e);
void cleanup_client_entries(sec_mod_st *sec);

#ifdef __GNUC__
# define seclog(sec, prio, fmt, ...) \
	if (prio != LOG_DEBUG || GETPCONFIG(sec)->debug >= 3) { \
		syslog(prio, "sec-mod: "fmt, ##__VA_ARGS__); \
	}
#else
# define seclog(sec,prio,...) \
	if (prio != LOG_DEBUG || GETPCONFIG(sec)->debug >= 3) { \
		 syslog(prio, __VA_ARGS__); \
	}
#endif

void  seclog_hex(const struct sec_mod_st* sec, int priority,
		const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64);

void sec_auth_init(struct vhost_cfg_st *vhost);

void handle_secm_list_cookies_reply(void *pool, int fd, sec_mod_st *sec);
void handle_sec_auth_ban_ip_reply(sec_mod_st *sec, const BanIpReplyMsg *msg);
int handle_sec_auth_init(int cfd, sec_mod_st *sec, const SecAuthInitMsg * req, pid_t pid);
int handle_sec_auth_cont(int cfd, sec_mod_st *sec, const SecAuthContMsg * req);
int handle_secm_session_open_cmd(sec_mod_st *sec, int fd, const SecmSessionOpenMsg *req);
int handle_secm_session_close_cmd(sec_mod_st *sec, int fd, const SecmSessionCloseMsg *req);
int handle_sec_auth_stats_cmd(sec_mod_st * sec, const CliStatsMsg * req, pid_t pid);
void sec_auth_user_deinit(sec_mod_st *sec, client_entry_st *e);

void sec_mod_server(void *main_pool, void *config_pool, struct list_head *vconfig,
		    const char *socket_file,
		    int cmd_fd, int cmd_fd_sync);

#endif
