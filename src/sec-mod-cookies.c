/*
 * Copyright (C) 2016 Nikos Mavrogiannopoulos
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
#include <vpn.h>
#include <main.h>
#include <sec-mod.h>
#include <ccan/hash/hash.h>
#include <ccan/htable/htable.h>

static void send_empty_reply(void *pool, int fd, sec_mod_st *sec)
{
	SecmListCookiesReplyMsg msg = SECM_LIST_COOKIES_REPLY_MSG__INIT;
	int ret;
	
	ret = send_msg(pool, fd, CMD_SECM_LIST_COOKIES_REPLY, &msg,
		(pack_size_func) secm_list_cookies_reply_msg__get_packed_size,
		(pack_func) secm_list_cookies_reply_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "Error sending empty show cookies reply to main");
	}
}

void handle_secm_list_cookies_reply(void *pool, int fd, sec_mod_st *sec)
{
	SecmListCookiesReplyMsg msg = SECM_LIST_COOKIES_REPLY_MSG__INIT;
	struct htable *db = sec->client_db;
	client_entry_st *t;
	struct htable_iter iter;
	CookieIntMsg *cookies;
	int ret;
	time_t now = time(0);

	if (db == NULL) {
		send_empty_reply(pool, fd, sec);
		return;
	}

	seclog(sec, LOG_DEBUG, "sending list cookies reply to main");

	msg.cookies = talloc_size(pool, sizeof(CookieIntMsg*)*db->elems);
	if (msg.cookies == NULL) {
		send_empty_reply(pool, fd, sec);
		return;
	}

	cookies = talloc_size(pool, sizeof(CookieIntMsg)*db->elems);
	if (cookies == NULL) {
		send_empty_reply(pool, fd, sec);
		return;
	}

	t = htable_first(db, &iter);
	while (t != NULL) {
		if IS_CLIENT_ENTRY_EXPIRED(sec, t, now)
			goto cont;

		if (msg.n_cookies >= db->elems)
			break;

		cookie_int_msg__init(&cookies[msg.n_cookies]);
		cookies[msg.n_cookies].safe_id.data = (void*)t->acct_info.safe_id;
		cookies[msg.n_cookies].safe_id.len = sizeof(t->acct_info.safe_id);

		cookies[msg.n_cookies].session_is_open = t->session_is_open;
		cookies[msg.n_cookies].tls_auth_ok = t->tls_auth_ok;

		if (t->created > 0)
			cookies[msg.n_cookies].created = t->created;
		else
			cookies[msg.n_cookies].created = 0;

		/* a session which is in use, does not expire */
		if (t->exptime > 0 && t->in_use == 0)
			cookies[msg.n_cookies].expires = t->exptime;
		else
			cookies[msg.n_cookies].expires = 0;
		cookies[msg.n_cookies].username = t->acct_info.username;
		cookies[msg.n_cookies].groupname = t->acct_info.groupname;
		cookies[msg.n_cookies].user_agent = t->acct_info.user_agent;
		cookies[msg.n_cookies].remote_ip = t->acct_info.remote_ip;
		cookies[msg.n_cookies].status = t->status;
		cookies[msg.n_cookies].in_use = t->in_use;
		cookies[msg.n_cookies].vhost = VHOSTNAME(t->vhost);

		msg.cookies[msg.n_cookies] = &cookies[msg.n_cookies];
		msg.n_cookies++;

 cont:
		t = htable_next(db, &iter);
	}

	ret = send_msg(pool, fd, CMD_SECM_LIST_COOKIES_REPLY, &msg,
		(pack_size_func) secm_list_cookies_reply_msg__get_packed_size,
		(pack_func) secm_list_cookies_reply_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "Error sending show cookies reply to main");
	}

	talloc_free(msg.cookies);
	talloc_free(cookies);
}

