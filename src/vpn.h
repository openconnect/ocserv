#ifndef SERVER_H
#define SERVER_H

#include <config.h>
#include <gnutls/gnutls.h>
#include <http-parser/http_parser.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>

#define AC_PKT_DATA             0	/* Uncompressed data */
#define AC_PKT_DPD_OUT          3	/* Dead Peer Detection */
#define AC_PKT_DPD_RESP         4	/* DPD response */
#define AC_PKT_DISCONN          5	/* Client disconnection notice */
#define AC_PKT_KEEPALIVE        7	/* Keepalive */
#define AC_PKT_COMPRESSED       8	/* Compressed data */
#define AC_PKT_TERM_SERVER      9	/* Server kick */

extern int syslog_open;

#define MAX(x,y) ((x)>(y)?(x):(y))

#define AUTH_TYPE_USERNAME_PASS (1<<0)
#define AUTH_TYPE_CERTIFICATE (1<<1)

#define MAX_NETWORKS 24
#define MAX_ROUTES 64

struct vpn_st {
	const char *name;	/* device name */
	const char *ipv4_netmask;
	const char *ipv4;
	const char *ipv6_netmask;
	const char *ipv6;
	const char *ipv4_dns;
	const char *ipv6_dns;
	unsigned int mtu;
	const char *routes[MAX_ROUTES];
	unsigned int routes_size;
};

struct cfg_st {
	const char *name;
	unsigned workers;
	unsigned int port;
	const char *cert;
	const char *key;
	const char *ca;
	const char *crl;
	const char *cert_user_oid;	/* The OID that will be used to extract the username */
	gnutls_certificate_request_t cert_req;
	const char *priorities;
	const char *root_dir;	/* where the xml files are served from */
	unsigned int auth_types;	/* or'ed sequence of AUTH_TYPE */
	time_t cookie_validity;	/* in seconds */
	const char *db_file;

	uid_t uid;
	gid_t gid;

	/* the tun network */
	struct vpn_st network;
};

#include <tun.h>

struct tls_st {
	gnutls_certificate_credentials_t xcred;
	gnutls_priority_t cprio;
};

typedef struct worker_st {
	gnutls_session_t session;
	char tun_name[IFNAMSIZ];
	int tun_fd;

	int cmd_fd;
	http_parser *parser;
	struct cfg_st *config;

	struct sockaddr_storage remote_addr;	/* peer's address */
	socklen_t remote_addr_len;
} worker_st;

#define MAX_USERNAME_SIZE 64
#define MAX_PASSWORD_SIZE 64
#define COOKIE_SIZE 32

enum {
	HEADER_COOKIE = 1,
};

struct req_data_st {
	char url[256];
	unsigned int next_header;
	unsigned char cookie[COOKIE_SIZE];
	unsigned int cookie_set;
	char *body;
	unsigned int headers_complete;
	unsigned int message_complete;
};

typedef enum {
	AUTH_REQ = 1,
	AUTH_REP = 2,
} cmd_request_t;

typedef enum {
	REP_AUTH_OK = 0,
	REP_AUTH_FAILED = 1,
} cmd_auth_reply_t;

struct cmd_auth_req_st {
	uint8_t user_pass_present;
	char user[MAX_USERNAME_SIZE];
	char pass[MAX_PASSWORD_SIZE];
	uint8_t tls_auth_ok;
	char cert_user[MAX_USERNAME_SIZE];
};

struct cmd_auth_resp_st {
	uint8_t reply;
	char vname[IFNAMSIZ]; /* interface name */
};

void vpn_server(struct cfg_st *config, struct tls_st *creds, 
                struct sockaddr_storage* r_addr, socklen_t r_addr_len,
                int cmdfd, int fd);

const char *human_addr(const struct sockaddr *sa, socklen_t salen,
		       void *buf, size_t buflen);

int __attribute__ ((format(printf, 3, 4)))
    oclog(const worker_st * server, int priority, const char *fmt, ...);


#endif
