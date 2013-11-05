/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include <vpn.h>
#include <worker.h>
#include "ipc.h"
#include <cookies.h>
#include <tlslib.h>


static int send_resume_fetch_req(worker_st * ws, 
				const struct cmd_resume_fetch_req_st* r,
				int delete)
{
	struct iovec iov[2];
	uint8_t cmd;
	struct msghdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	
	if (delete != 0)
		cmd = RESUME_DELETE_REQ;
	else
		cmd = RESUME_FETCH_REQ;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = (void*)r;
	iov[1].iov_len = sizeof(*r);
	
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	return(sendmsg(ws->cmd_fd, &hdr, 0));
}

static int send_resume_store_req(worker_st * ws, const struct cmd_resume_store_req_st* r)
{
	struct iovec iov[2];
	uint8_t cmd;
	struct msghdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	
	cmd = RESUME_STORE_REQ;

	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = (void*)r;
	iov[1].iov_len = sizeof(*r);
	
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	return(sendmsg(ws->cmd_fd, &hdr, 0));
}

static int recv_resume_fetch_reply(worker_st *ws, struct cmd_resume_fetch_reply_st* resp)
{
	struct iovec iov[2];
	uint8_t cmd = 0;
	struct msghdr hdr;
	int ret;
	
	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = resp;
	iov[1].iov_len = sizeof(*resp);

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;

	ret = recvmsg( ws->cmd_fd, &hdr, 0);
	if (ret <= sizeof(*resp)) {
		int e = errno;
		oclog(ws, LOG_ERR, "resume_fetch_reply: incorrect data (%d, expected %d) from main: %s", ret, (int)sizeof(*resp)+1, strerror(e));
		return -1;
	}

	if (cmd != RESUME_FETCH_REP) {
		oclog(ws, LOG_ERR, "resume_fetch_reply: unexpected response (%d, expected %d) from main", (int)cmd, (int)RESUME_FETCH_REP);
		return -1;
	}

	switch(resp->reply) {
		case REP_RESUME_OK:
			return 0;
		default:
			return -1;
	}
}

/* sends an authentication request to main thread and waits for
 * a reply.
 * Returns 0 on success.
 */
static gnutls_datum_t resume_db_fetch(void *dbf, gnutls_datum_t key)
{
worker_st *ws = dbf;
struct cmd_resume_fetch_req_st areq;
struct cmd_resume_fetch_reply_st *arep;
gnutls_datum_t r = { NULL, 0 };
int ret;

	if (key.size > GNUTLS_MAX_SESSION_ID) {
		oclog(ws, LOG_DEBUG, "Session ID size exceeds the maximum %u", key.size);
		return r;
	}

	areq.session_id_size = key.size;
	memcpy(areq.session_id, key.data, key.size);

	oclog(ws, LOG_DEBUG, "sending resumption request (fetch)");

	ret = send_resume_fetch_req(ws, &areq, 0);
	if (ret < 0)
		return r;

	arep = malloc(sizeof(*arep));
	if (arep == NULL)
		return r;

	ret = recv_resume_fetch_reply(ws, arep);
	if (ret < 0) {
		goto cleanup;
	}
		
	r.data = gnutls_malloc(arep->session_data_size);
	if (r.data == NULL)
		goto cleanup;

	r.size = arep->session_data_size;
	memcpy(r.data, arep->session_data, r.size);

cleanup:
	free(arep);
	return r;
}


static int
resume_db_store (void *dbf, gnutls_datum_t key, gnutls_datum_t data)
{
worker_st *ws = dbf;
struct cmd_resume_store_req_st areq;
int ret;

	if (data.size > MAX_SESSION_DATA_SIZE) {
		oclog(ws, LOG_DEBUG, "session data size exceeds the maximum %u", data.size);
		return GNUTLS_E_DB_ERROR;
	}

	if (key.size > GNUTLS_MAX_SESSION_ID) {
		oclog(ws, LOG_DEBUG, "session ID size exceeds the maximum %u", key.size);
		return GNUTLS_E_DB_ERROR;
	}

	areq.session_id_size = key.size;
	areq.session_data_size = data.size;

	memcpy(areq.session_id, key.data, key.size);
	memcpy(areq.session_data, data.data, data.size);

	ret = send_resume_store_req(ws, &areq);
	if (ret < 0) {
		return GNUTLS_E_DB_ERROR;
	}

	return 0;
}

/* sends an authentication request to main thread and waits for
 * a reply.
 * Returns 0 on success.
 */
static int resume_db_delete(void *dbf, gnutls_datum_t key)
{
worker_st *ws = dbf;
struct cmd_resume_fetch_req_st areq;
int ret;

	if (key.size > GNUTLS_MAX_SESSION_ID) {
		oclog(ws, LOG_DEBUG, "Session ID size exceeds the maximum %u", key.size);
		return GNUTLS_E_DB_ERROR;
	}

	areq.session_id_size = key.size;
	memcpy(areq.session_id, key.data, key.size);

	oclog(ws, LOG_DEBUG, "sending resumption request (delete)");

	ret = send_resume_fetch_req(ws, &areq, 1);
	if (ret < 0)
		return GNUTLS_E_DB_ERROR;

	return 0;
}

void set_resume_db_funcs(gnutls_session_t session)
{
	gnutls_db_set_retrieve_function (session, resume_db_fetch);
	gnutls_db_set_remove_function (session, resume_db_delete);
	gnutls_db_set_store_function (session, resume_db_store);
}
