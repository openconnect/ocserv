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

#include <proc-search.h>
#include <main.h>
#include <common.h>

struct find_ip_st {
	struct sockaddr_storage *sockaddr;
	unsigned sockaddr_size;
	unsigned found_ips;
};

struct find_sid_st {
	const uint8_t *sid;
	unsigned sid_size;
};


static size_t rehash_ip(const void* _p, void* unused)
{
const struct proc_st * proc = _p;

	return hash_any(
		SA_IN_P_GENERIC(&proc->remote_addr, proc->remote_addr_len),
		SA_IN_SIZE(proc->remote_addr_len), 0);
}

static size_t rehash_sid(const void* _p, void* unused)
{
const struct proc_st * proc = _p;

	return hash_any(proc->dtls_session_id, proc->dtls_session_id_size, 0);
}

void proc_table_init(main_server_st *s)
{
	s->proc_table.db_ip = talloc(s, struct htable);
	s->proc_table.db_sid = talloc(s, struct htable);
	htable_init(s->proc_table.db_ip, rehash_ip, NULL);
	htable_init(s->proc_table.db_sid, rehash_sid, NULL);
	s->proc_table.total = 0;
}

void proc_table_deinit(main_server_st *s)
{
	htable_clear(s->proc_table.db_ip);
	htable_clear(s->proc_table.db_sid);
	talloc_free(s->proc_table.db_sid);
	talloc_free(s->proc_table.db_ip);
}

void proc_table_add(main_server_st *s, struct proc_st *proc)
{
	size_t ip_hash = rehash_ip(proc, NULL);

	if (htable_add(s->proc_table.db_ip, ip_hash, proc) == 0) {
		return;
	}

	if (htable_add(s->proc_table.db_sid, rehash_sid(proc, NULL), proc) == 0) {
		htable_del(s->proc_table.db_ip, ip_hash, proc);
		return;
	}

	s->proc_table.total++;

	return;
}

void proc_table_del(main_server_st *s, struct proc_st *proc)
{
	htable_del(s->proc_table.db_ip, rehash_ip(proc, NULL), proc);
	htable_del(s->proc_table.db_sid, rehash_sid(proc, NULL), proc);
}

static bool local_ip_cmp(const void* _c1, void* _c2)
{
const struct proc_st* c1 = _c1;
struct find_ip_st* c2 = _c2;

	if (c1->remote_addr_len != c2->sockaddr_size)
		return 0;

	if (memcmp(SA_IN_P_GENERIC(&c1->remote_addr, c1->remote_addr_len),
		   SA_IN_P_GENERIC(c2->sockaddr, c2->sockaddr_size),
		   SA_IN_SIZE(c1->remote_addr_len)) == 0) {
		c2->found_ips++;
		return 1;
	}

	return 0;
}

struct proc_st *proc_search_ip(struct main_server_st *s,
			       struct sockaddr_storage *sockaddr,
			       unsigned sockaddr_size)
{
	struct proc_st *proc;
	struct find_ip_st fip;
	size_t h;

	fip.sockaddr = sockaddr;
	fip.sockaddr_size = sockaddr_size;
	fip.found_ips = 0;

	h = hash_any(SA_IN_P_GENERIC(sockaddr, sockaddr_size),
			SA_IN_SIZE(sockaddr_size), 0);
	proc = htable_get(s->proc_table.db_ip, h, local_ip_cmp, &fip);

	if (fip.found_ips > 1)
		return NULL;
	return proc;
}

static bool sid_cmp(const void* _c1, void* _c2)
{
const struct proc_st* c1 = _c1;
struct find_sid_st* c2 = _c2;

	if (c1->dtls_session_id_size != c2->sid_size)
		return 0;

	if (memcmp(c1->dtls_session_id,
		   c2->sid,
		   c1->dtls_session_id_size) == 0) {
		return 1;
	}

	return 0;
}
struct proc_st *proc_search_sid(struct main_server_st *s,
			        const uint8_t *id, unsigned id_size)
{
	struct find_sid_st fsid;

	fsid.sid = id;
	fsid.sid_size = id_size;

	return htable_get(s->proc_table.db_sid, hash_any(id, id_size, 0), sid_cmp, &fsid);
}

