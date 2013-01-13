#ifndef SERVER_H
#define SERVER_H

#include <gnutls/gnutls.h>
#include <http-parser/http_parser.h>

#define AUTH_TYPE_USERNAME_PASS (1<<0)
#define AUTH_TYPE_CERTIFICATE (1<<1)

struct cfg_st {
	const char *name;
	unsigned int port;
	const char *cert;
	const char *key;
	const char *ca;
	const char *crl;
	const char *cert_user_oid; /* The OID that will be used to extract the username */
	gnutls_certificate_request_t cert_req;
	const char *priorities;
	const char *root_dir; /* where the xml files are served from */
	unsigned int auth_types; /* or'ed sequence of AUTH_TYPE */
	time_t cookie_validity; /* in seconds */
	const char* db_file;
};

struct tls_st {
	gnutls_certificate_credentials_t xcred;
	gnutls_priority_t cprio;
};

typedef struct server_st {
	gnutls_session_t session;
	http_parser* parser;
	struct cfg_st *config;
	int tunfd;
} server_st;

#define MAX_USERNAME_SIZE 64
#define COOKIE_SIZE 32

struct req_data_st {
	char url[256];
	unsigned char cookie[COOKIE_SIZE];
	unsigned int cookie_set;
	char *body;
	unsigned int headers_complete;
	unsigned int message_complete;
};

void vpn_server(struct cfg_st *config, struct tls_st *creds, int tunfd, int fd);

#endif
