/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or
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
#ifndef DEFS_H
#define DEFS_H

#include <syslog.h>

/* syslog value extensions */
#define LOG_HTTP_DEBUG 2048
#define LOG_TRANSFER_DEBUG 2049
#define LOG_SENSITIVE 2050


/* User Disconnect reasons (must be > 0) */
#define REASON_ANY 1
#define REASON_USER_DISCONNECT 2
#define REASON_SERVER_DISCONNECT 3
#define REASON_IDLE_TIMEOUT 4
#define REASON_DPD_TIMEOUT 5
#define REASON_ERROR 6
#define REASON_SESSION_TIMEOUT 7
#define REASON_TEMP_DISCONNECT 8
#define REASON_HEALTH_PROBE 9

/* Timeout (secs) for communication between main and sec-mod */
#define MAIN_SEC_MOD_TIMEOUT 120
#define MAX_WAIT_SECS 3

/* Debug definitions for logger */
#define DEBUG_BASIC 1
#define DEBUG_INFO  2
#define DEBUG_DEBUG 3
#define DEBUG_HTTP  4
#define DEBUG_TRANSFERRED 5
#define DEBUG_SENSITIVE 8
#define DEBUG_TLS   9

/* Authentication states */
enum {
	PS_AUTH_INACTIVE, /* no comm with worker */
	PS_AUTH_FAILED, /* tried authentication but failed */
	PS_AUTH_INIT, /* worker has sent an auth init msg */
	PS_AUTH_CONT, /* worker has sent an auth cont msg */
	PS_AUTH_COMPLETED /* successful authentication */
};

/* IPC protocol commands */
typedef enum {
	AUTH_COOKIE_REP = 2,
	AUTH_COOKIE_REQ = 4,
	RESUME_STORE_REQ = 6,
	RESUME_DELETE_REQ = 7,
	RESUME_FETCH_REQ = 8,
	RESUME_FETCH_REP = 9,
	CMD_UDP_FD = 10,
	CMD_TUN_MTU = 11,
	CMD_TERMINATE = 12,
	CMD_SESSION_INFO = 13,
	CMD_BAN_IP = 16,
	CMD_BAN_IP_REPLY = 17,
	CMD_LATENCY_STATS_DELTA = 18,	

	/* from worker to sec-mod */
	CMD_SEC_AUTH_INIT = 120,
	CMD_SEC_AUTH_CONT,
	CMD_SEC_AUTH_REPLY,
	CMD_SEC_DECRYPT,
	CMD_SEC_SIGN,
	CMD_SEC_SIGN_DATA,
	CMD_SEC_SIGN_HASH,
	CMD_SEC_GET_PK,
	CMD_SEC_CLI_STATS,

	/* from main to sec-mod and vice versa */
	MIN_SECM_CMD=239,
	CMD_SECM_SESSION_OPEN, /* sync: reply is CMD_SECM_SESSION_REPLY */
	CMD_SECM_SESSION_CLOSE, /* sync: reply is CMD_SECM_CLI_STATS */
	CMD_SECM_SESSION_REPLY,
	CMD_SECM_BAN_IP,
	CMD_SECM_BAN_IP_REPLY,
	CMD_SECM_CLI_STATS,
	CMD_SECM_LIST_COOKIES,
	CMD_SECM_LIST_COOKIES_REPLY,
	CMD_SECM_STATS, /* sent periodically */
	CMD_SECM_RELOAD,
	CMD_SECM_RELOAD_REPLY,

	MAX_SECM_CMD,
} cmd_request_t;

/* Error codes */
#define ERR_SUCCESS 0
#define ERR_BAD_COMMAND -2
#define ERR_AUTH_FAIL -3
#define ERR_AUTH_CONTINUE -4
#define ERR_WAIT_FOR_SCRIPT -5
#define ERR_MEM -6
#define ERR_READ_CONFIG -7
#define ERR_NO_IP -8
#define ERR_PARSING -9
#define ERR_EXEC -10
#define ERR_PEER_TERMINATED -11
#define ERR_CTL -12
#define ERR_NO_CMD_FD -13

#define ERR_WORKER_TERMINATED ERR_PEER_TERMINATED

#endif
