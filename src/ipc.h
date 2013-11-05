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
#ifndef IPC_H
#define IPC_H

#include <config.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <vpn.h>
#include <tlslib.h>
#include <cookies.h>

#define MAX_MSG_SIZE 256

typedef enum {
	AUTH_INIT=1,
	AUTH_REP,
	AUTH_REQ,
	AUTH_COOKIE_REQ,
	AUTH_MSG,
	RESUME_STORE_REQ,
	RESUME_DELETE_REQ,
	RESUME_FETCH_REQ,
	RESUME_FETCH_REP,
	CMD_UDP_FD,
	CMD_TUN_MTU,
	CMD_TERMINATE,
} cmd_request_t;

typedef enum {
	REP_AUTH_OK = 1,
	REP_AUTH_MSG = 2,
	REP_AUTH_FAILED = 3,
} cmd_auth_reply_t;

typedef enum {
	REP_RESUME_OK = 0,
	REP_RESUME_FAILED = 1,
} cmd_resume_reply_t;

/* AUTH_INIT:
 *  Message sent by worker to main to initialize authentication process.
 */
struct __attribute__ ((__packed__)) cmd_auth_init_st {
	uint8_t user_present;
	char user[MAX_USERNAME_SIZE];
	uint8_t tls_auth_ok;
	char cert_user[MAX_USERNAME_SIZE];
	char cert_group[MAX_GROUPNAME_SIZE];
	char hostname[MAX_HOSTNAME_SIZE];
};

/* AUTH_COOKIE_REQ:
 *  Message sent by worker to main to follow up authentication (after AUTH_INIT).
 *  Sent if the client tried to authenticate using cookie.
 */
struct __attribute__ ((__packed__)) cmd_auth_cookie_req_st {
	uint8_t cookie[COOKIE_SIZE];
	uint8_t tls_auth_ok;
	char cert_user[MAX_USERNAME_SIZE];
	char cert_group[MAX_GROUPNAME_SIZE];
};

/* AUTH_REQ:
 *  Message sent by worker to main to follow up authentication (after AUTH_INIT).
 *  Sent if the client tried to authenticate using password.
 */
struct __attribute__ ((__packed__)) cmd_auth_req_st {
	uint8_t pass_size;
	char pass[MAX_PASSWORD_SIZE];
};


/* AUTH_REP:
 *  Message sent by main to worker to follow up authentication (after AUTH_*REQ).
 *  Sent if the client tried to authenticate using password.
 */
struct __attribute__ ((__packed__)) cmd_auth_reply_st {
	uint8_t reply; /* REP_AUTH_OK, REP_AUTH_MSG or REP_AUTH_FAILED */
};

/* REP_AUTH_OK */
struct __attribute__ ((__packed__)) cmd_auth_reply_info_st {
	uint8_t cookie[COOKIE_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	char vname[IFNAMSIZ]; /* interface name */
	char user[MAX_USERNAME_SIZE];
};

/* in case of REP_AUTH_MSG */
struct __attribute__ ((__packed__)) cmd_auth_reply_msg_st {
	char msg[MAX_MSG_SIZE]; 
};

/* RESUME_FETCH_REQ + RESUME_DELETE_REQ: 
 *  Message sent by worker to main to ask for TLS resumption data, or
 *  to delete such data. 
 */
struct __attribute__ ((__packed__)) cmd_resume_fetch_req_st {
	uint8_t session_id_size;
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
};

/* RESUME_STORE_REQ:
 *  Message sent by worker to main to store TLS resumption data.
 */
struct __attribute__ ((__packed__)) cmd_resume_store_req_st {
	uint8_t session_id_size;
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	uint16_t session_data_size;
	uint8_t session_data[MAX_SESSION_DATA_SIZE];
};

/* RESUME_FETCH_REP:
 *  Message sent by main to worker to return stored TLS resumption data.
 */
struct __attribute__ ((__packed__)) cmd_resume_fetch_reply_st {
	uint8_t reply;
	uint16_t session_data_size;
	uint8_t session_data[MAX_SESSION_DATA_SIZE];
};

/* TUN_MTU:
 *  Message sent by worker to main to alter the MTU of the TUN device.
 */
struct __attribute__ ((__packed__)) cmd_tun_mtu_st {
	uint16_t mtu;
};

#endif
