#ifndef WORKER_AUTH_H
#define WORKER_AUTH_H

#include <config.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <vpn.h>
#include <cookies.h>

typedef enum {
	AUTH_REQ = 1,
	AUTH_COOKIE_REQ,
	AUTH_REP,
	CMD_TERMINATE,
} cmd_request_t;

typedef enum {
	REP_AUTH_OK = 0,
	REP_AUTH_FAILED = 1,
} cmd_auth_reply_t;

/* AUTH_COOKIE_REQ */
struct __attribute__ ((__packed__)) cmd_auth_cookie_req_st {
	uint8_t cookie[COOKIE_SIZE];
	uint8_t tls_auth_ok;
	char cert_user[MAX_USERNAME_SIZE];
};

/* AUTH_REQ */
struct __attribute__ ((__packed__)) cmd_auth_req_st {
	uint8_t user_pass_present;
	char user[MAX_USERNAME_SIZE];
	char pass[MAX_PASSWORD_SIZE];
	uint8_t tls_auth_ok;
	char cert_user[MAX_USERNAME_SIZE];
};

/* AUTH_REP */
struct __attribute__ ((__packed__)) cmd_auth_reply_st {
	uint8_t reply;
	uint8_t cookie[COOKIE_SIZE];
	uint8_t master_secret[TLS_MASTER_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	char vname[IFNAMSIZ]; /* interface name */
	char user[MAX_USERNAME_SIZE];
};

int auth_cookie(worker_st *ws, void* cookie, size_t cookie_size);

int get_auth_handler(worker_st *server);
int post_old_auth_handler(worker_st *server);
int post_new_auth_handler(worker_st *server);

#endif
