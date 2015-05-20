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

#include <cookies.h>
#include <gnutls/abstract.h>
#include <ccan/htable/htable.h>
#include <base64.h>

#define SESSION_STR "(session: %.5s)"

typedef struct sec_mod_st {
	gnutls_datum_t dcookie_key; /* the key to generate cookies */
	uint8_t cookie_key[COOKIE_KEY_SIZE];

	struct cfg_st *config;
	struct perm_cfg_st *perm_config;
	gnutls_privkey_t *key;
	unsigned key_size;
	struct htable *client_db;
	int cmd_fd;
	int cmd_fd_sync;

	struct config_mod_st *config_module;
} sec_mod_st;

typedef struct stats_st {
	uint64_t bytes_in;
	uint64_t bytes_out;
	time_t uptime;
} stats_st;

typedef struct common_auth_info_st {
	char username[MAX_USERNAME_SIZE*2];
	char groupname[MAX_GROUPNAME_SIZE]; /* the owner's group */
	char psid[BASE64_LENGTH(SID_SIZE) + 1]; /* printable */
	char remote_ip[MAX_IP_STR];
	char our_ip[MAX_IP_STR];
	char ipv4[MAX_IP_STR];
	char ipv6[MAX_IP_STR];
	unsigned id;
} common_auth_info_st;

typedef struct client_entry_st {
	/* A unique session identifier used to distinguish sessions
	 * prior to authentication. It is sent as cookie to the client
	 * who re-uses it when it performs authentication in multiple
	 * sessions.
	 */
	uint8_t sid[SID_SIZE];

	void * auth_ctx; /* the context of authentication */
	unsigned session_is_open; /* whether open_session was done */
	unsigned in_use; /* counter of users of this structure */
	unsigned tls_auth_ok;

	char *msg_str;
	unsigned passwd_counter; /* if msg_str is for a password this indicates the passwrd number (0,1,2) */

	stats_st saved_stats; /* saved from previous cookie usage */
	stats_st stats; /* current */

	unsigned status; /* PS_AUTH_ */

	char hostname[MAX_HOSTNAME_SIZE]; /* the requested hostname */
	uint8_t *cookie; /* the cookie associated with the session */
	unsigned cookie_size;

	uint8_t dtls_session_id[GNUTLS_MAX_SESSION_ID];

	/* The time this client entry was last modified (created or closed) */
	time_t time;

	/* the auth type associated with the user */
	unsigned auth_type;
	unsigned discon_reason; /* reason for disconnection */

	struct common_auth_info_st auth_info;

	/* the module this entry is using */
	const struct auth_mod_st *module;
} client_entry_st;

void *sec_mod_client_db_init(sec_mod_st *sec);
void sec_mod_client_db_deinit(sec_mod_st *sec);
unsigned sec_mod_client_db_elems(sec_mod_st *sec);
client_entry_st * new_client_entry(sec_mod_st *sec, const char *ip, unsigned pid);
client_entry_st * find_client_entry(sec_mod_st *sec, uint8_t sid[SID_SIZE]);
void del_client_entry(sec_mod_st *sec, client_entry_st * e);
void expire_client_entry(sec_mod_st *sec, client_entry_st * e);
void cleanup_client_entries(sec_mod_st *sec);

#ifdef __GNUC__
# define seclog(sec, prio, fmt, ...) \
	if (prio != LOG_DEBUG || sec->config->debug >= 3) { \
		syslog(prio, "sec-mod: "fmt, ##__VA_ARGS__); \
	}
#else
# define seclog(sec,prio,...) \
	if (prio != LOG_DEBUG || sec->config->debug >= 3) { \
		 syslog(prio, __VA_ARGS__); \
	}
#endif

void  seclog_hex(const struct sec_mod_st* sec, int priority,
		const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64);

void sec_auth_init(sec_mod_st *sec, struct perm_cfg_st *config);

void handle_sec_auth_ban_ip_reply(sec_mod_st *sec, const BanIpReplyMsg *msg);
int handle_sec_auth_init(int cfd, sec_mod_st *sec, const SecAuthInitMsg * req, pid_t pid);
int handle_sec_auth_cont(int cfd, sec_mod_st *sec, const SecAuthContMsg * req);
int handle_sec_auth_session_cmd(sec_mod_st *sec, int fd, const SecAuthSessionMsg *req, unsigned cmd);
int handle_sec_auth_stats_cmd(sec_mod_st * sec, const CliStatsMsg * req);
void sec_auth_user_deinit(sec_mod_st * sec, client_entry_st * e);

void sec_mod_server(void *main_pool, struct perm_cfg_st *config, const char *socket_file,
		    uint8_t cookie_key[COOKIE_KEY_SIZE], int cmd_fd, int cmd_fd_sync);

#endif
