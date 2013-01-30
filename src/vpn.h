#ifndef VPN_H
#define VPN_H

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

/* the first is generic, for the methods that require a username password */
#define AUTH_TYPE_USERNAME_PASS (1<<0)
#define AUTH_TYPE_PAM (1<<1 | AUTH_TYPE_USERNAME_PASS)
#define AUTH_TYPE_CERTIFICATE (1<<2)

struct vpn_st {
	const char *name;	/* device name */
	const char *ipv4_netmask;
	const char *ipv4;
	const char *ipv4_local; /* local IPv4 address */
	const char *ipv6_netmask;
	const char *ipv6;
	const char *ipv6_local; /* local IPv6 address */
	const char *ipv4_dns;
	const char *ipv6_dns;
	unsigned int mtu;
	const char **routes;
	unsigned int routes_size;
};

struct cfg_st {
	const char *name;
	unsigned int port;
	unsigned int udp_port;
	const char *cert;
	const char *key;
	const char *ca;
	const char *crl;
	const char *cert_user_oid;	/* The OID that will be used to extract the username */
	unsigned int auth_types;	/* or'ed sequence of AUTH_TYPE */
	gnutls_certificate_request_t cert_req;
	const char *priorities;
	const char *chroot_dir;	/* where the xml files are served from */
	time_t cookie_validity;	/* in seconds */
	unsigned auth_timeout; /* timeout of HTTP auth */
	const char *db_file;
	unsigned foreground;

	uid_t uid;
	gid_t gid;

	/* the tun network */
	struct vpn_st network;
};

#include <tun.h>

#define MAX_USERNAME_SIZE 64
#define MAX_PASSWORD_SIZE 64
#define COOKIE_SIZE 32

struct tls_st {
	gnutls_certificate_credentials_t xcred;
	gnutls_priority_t cprio;
};

typedef struct worker_st {
	gnutls_session_t session;
	int cmd_fd;
	int conn_fd;
	
	http_parser *parser;
	struct cfg_st *config;

	struct sockaddr_storage remote_addr;	/* peer's address */
	socklen_t remote_addr_len;

	/* the following are set only if authentication is complete */
	char tun_name[IFNAMSIZ];
	char username[MAX_USERNAME_SIZE];
	uint8_t cookie[COOKIE_SIZE];
	unsigned auth_ok;
	int tun_fd;
} worker_st;


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

void vpn_server(struct worker_st* ws, struct tls_st *creds);

const char *human_addr(const struct sockaddr *sa, socklen_t salen,
		       void *buf, size_t buflen);

void __attribute__ ((format(printf, 3, 4)))
    oclog(const worker_st * server, int priority, const char *fmt, ...);

int cmd_parser (int argc, char **argv, struct cfg_st* config);

struct proc_list_st {
	struct list_head list;
	int fd;
	pid_t pid;
	struct sockaddr_storage remote_addr; /* peer address */
	socklen_t remote_addr_len;
	char username[MAX_USERNAME_SIZE]; /* the owner */
	uint8_t cookie[COOKIE_SIZE]; /* the cookie associate with the session */
	
	/* the tun lease this process has */
	struct lease_st* lease;
};

int handle_commands(const struct cfg_st *config, struct tun_st *tun, 
			   struct proc_list_st* proc);

/* Helper casts */
#define SA_IN_P(p) (&((struct sockaddr_in *)(p))->sin_addr)
#define SA_IN_U8_P(p) ((uint8_t*)(&((struct sockaddr_in *)(p))->sin_addr))
#define SA_IN6_P(p) (&((struct sockaddr_in6 *)(p))->sin6_addr)
#define SA_IN6_U8_P(p) ((uint8_t*)(&((struct sockaddr_in6 *)(p))->sin6_addr))

#endif
