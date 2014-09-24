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
 * ocserv is distributed in the hope that it will be useful, but
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
#include "common.h"
#include "ipc.pb-c.h"
#include <cookies.h>
#include <tlslib.h>


static int recv_resume_fetch_reply(worker_st *ws, gnutls_datum_t *sdata)
{
	int ret;
	SessionResumeReplyMsg *resp;
	PROTOBUF_ALLOCATOR(pa, ws);

	ret = recv_msg(ws, ws->cmd_fd, RESUME_FETCH_REP, (void*)&resp, 
		(unpack_func)session_resume_reply_msg__unpack);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error receiving resumption reply (fetch)");
		return ret;
	}

	if (resp->reply != SESSION_RESUME_REPLY_MSG__RESUME__REP__OK) {
		ret = -1;
		goto cleanup;
	}
		
	sdata->data = gnutls_malloc(resp->session_data.len);
	if (sdata->data == NULL) {
		ret = -1;
		goto cleanup;
	}

	sdata->size = resp->session_data.len;
	memcpy(sdata->data, resp->session_data.data, sdata->size);

	ret = 0;
cleanup:
	session_resume_reply_msg__free_unpacked(resp, &pa);
	
	return ret;
}

/* sends an authentication request to main thread and waits for
 * a reply.
 * Returns 0 on success.
 */
static gnutls_datum_t resume_db_fetch(void *dbf, gnutls_datum_t key)
{
worker_st *ws = dbf;
gnutls_datum_t r = { NULL, 0 };
int ret;
SessionResumeFetchMsg msg = SESSION_RESUME_FETCH_MSG__INIT;

	if (key.size > GNUTLS_MAX_SESSION_ID) {
		oclog(ws, LOG_DEBUG, "session ID size exceeds the maximum %u", key.size);
		return r;
	}

	msg.session_id.len = key.size;
	msg.session_id.data = key.data;

	ret = send_msg_to_main(ws, RESUME_FETCH_REQ, &msg,
		(pack_size_func)session_resume_fetch_msg__get_packed_size,
		(pack_func)session_resume_fetch_msg__pack);
	if (ret < 0)
		return r;

	recv_resume_fetch_reply(ws, &r);
	
	return r;
}


static int
resume_db_store (void *dbf, gnutls_datum_t key, gnutls_datum_t data)
{
worker_st *ws = dbf;
SessionResumeStoreReqMsg msg = SESSION_RESUME_STORE_REQ_MSG__INIT;
int ret;

	if (data.size > MAX_SESSION_DATA_SIZE) {
		oclog(ws, LOG_DEBUG, "session data size exceeds the maximum %u", data.size);
		return GNUTLS_E_DB_ERROR;
	}

	if (key.size > GNUTLS_MAX_SESSION_ID) {
		oclog(ws, LOG_DEBUG, "session ID size exceeds the maximum %u", key.size);
		return GNUTLS_E_DB_ERROR;
	}

	msg.session_id.len = key.size;
	msg.session_data.len = data.size;

	msg.session_id.data = key.data;
	msg.session_data.data = data.data;

	ret = send_msg_to_main(ws, RESUME_STORE_REQ, &msg,
		(pack_size_func)session_resume_store_req_msg__get_packed_size,
		(pack_func)session_resume_store_req_msg__pack);
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
int ret;
SessionResumeFetchMsg msg = SESSION_RESUME_FETCH_MSG__INIT;

	if (key.size > GNUTLS_MAX_SESSION_ID) {
		oclog(ws, LOG_DEBUG, "Session ID size exceeds the maximum %u", key.size);
		return GNUTLS_E_DB_ERROR;
	}

	msg.session_id.len = key.size;
	msg.session_id.data = key.data;

	ret = send_msg_to_main(ws, RESUME_DELETE_REQ, &msg,
		(pack_size_func)session_resume_fetch_msg__get_packed_size,
		(pack_func)session_resume_fetch_msg__pack);
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
