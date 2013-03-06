#ifndef VPN_H
#define VPN_H

#include <config.h>
#include <gnutls/gnutls.h>
#include <http-parser/http_parser.h>
#include <ccan/htable/htable.h>
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
#define MIN(x,y) ((x)<(y)?(x):(y))

/* the first is generic, for the methods that require a username password */
#define AUTH_TYPE_USERNAME_PASS (1<<0)
#define AUTH_TYPE_PAM (1<<1 | AUTH_TYPE_USERNAME_PASS)
#define AUTH_TYPE_CERTIFICATE (1<<2)

typedef struct 
{
	struct htable ht;
	unsigned int entries;
} hash_db_st;


struct vpn_st {
	char *name;	/* device name */
	char *ipv4_netmask;
	char *ipv4;
	char *ipv4_local; /* local IPv4 address */
	char *ipv6_netmask;
	char *ipv6;
	char *ipv6_local; /* local IPv6 address */
	char *ipv4_dns;
	char *ipv6_dns;
	char *ipv4_nbns;
	char *ipv6_nbns;
	unsigned int mtu;
	char **routes;
	unsigned int routes_size;
};

struct cfg_st {
	char *name; /* server name */
	unsigned int port;
	unsigned int udp_port;
	char *pin_file;
	char *srk_pin_file;
	char *cert;

	char *key;
	char *ca;
	char *crl;
	char *dh_params_file;
	char *cert_user_oid;	/* The OID that will be used to extract the username */
	char *cert_group_oid;	/* The OID that will be used to extract the groupname */
	unsigned int auth_types;	/* or'ed sequence of AUTH_TYPE */
	gnutls_certificate_request_t cert_req;
	char *priorities;
	char *chroot_dir;	/* where the xml files are served from */
	char *banner;
	char *ocsp_response; /* file with the OCSP response */
	time_t cookie_validity;	/* in seconds */
	time_t min_reauth_time;	/* after a failed auth, how soon one can reauthenticate -> in seconds */
	unsigned auth_timeout; /* timeout of HTTP auth */
	unsigned keepalive;
	unsigned dpd;
	unsigned foreground;
	unsigned tls_debug;
	unsigned debug;
	unsigned max_clients;
	unsigned max_same_clients;
	unsigned use_utmp;
	unsigned try_mtu; /* MTU discovery enabled */
	unsigned force_cert_auth; /* always require client certificate */
	unsigned rate_limit_ms; /* if non zero force a connection every rate_limit milliseconds */

	/* if gdbm is there */
	char* cookie_db_name;

	char *connect_script;
	char *disconnect_script;

#ifdef ANYCONNECT_CLIENT_COMPAT
	char *xml_config_file;
	char *xml_config_hash;
	char *cert_hash;
#endif

	uid_t uid;
	gid_t gid;

	/* the tun network */
	struct vpn_st network;
};

/* generic thing to stop complaints */
struct worker_st;
struct main_server_st;

#include <tun.h>

#define MAX_BANNER_SIZE 256
#define MAX_USERNAME_SIZE 64
#define MAX_PASSWORD_SIZE 64
#define TLS_MASTER_SIZE 48
#define MAX_HOSTNAME_SIZE MAX_USERNAME_SIZE
#define MAX_GROUPNAME_SIZE MAX_USERNAME_SIZE
#define COOKIE_SIZE 32
#define MAX_SESSION_DATA_SIZE (4*1024)

const char *human_addr(const struct sockaddr *sa, socklen_t salen,
		       void *buf, size_t buflen);

/* Helper casts */
#define SA_IN_P(p) (&((struct sockaddr_in *)(p))->sin_addr)
#define SA_IN_U8_P(p) ((uint8_t*)(&((struct sockaddr_in *)(p))->sin_addr))
#define SA_IN6_P(p) (&((struct sockaddr_in6 *)(p))->sin6_addr)
#define SA_IN6_U8_P(p) ((uint8_t*)(&((struct sockaddr_in6 *)(p))->sin6_addr))

#define SA_IN_PORT(p) (((struct sockaddr_in *)(p))->sin_port)
#define SA_IN6_PORT(p) (((struct sockaddr_in6 *)(p))->sin6_port)

#define SA_IN_P_GENERIC(addr, size) ((size==sizeof(struct sockaddr_in))?SA_IN_U8_P(addr):SA_IN6_U8_P(addr))
#define SA_IN_SIZE(size) ((size==sizeof(struct sockaddr_in))?sizeof(struct in_addr):sizeof(struct in6_addr))
#endif
