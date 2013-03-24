#ifndef WORKER_H
#define WORKER_H

#include <config.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <vpn.h>
#include <cookies.h>
#include <tlslib.h>

typedef enum {
	UP_DISABLED,
	UP_WAIT_FD,
	UP_SETUP,
	UP_HANDSHAKE,
	UP_INACTIVE,
	UP_ACTIVE
} udp_port_state_t;

enum {
	HEADER_COOKIE = 1,
	HEADER_MASTER_SECRET,
	HEADER_HOSTNAME,
	HEADER_CSTP_MTU,
	HEADER_DTLS_MTU,
};

struct http_req_st {
	char url[256];
	char dbg_txt[256];

	char hostname[MAX_HOSTNAME_SIZE];
	unsigned int next_header;
	unsigned char cookie[COOKIE_SIZE];
	unsigned int cookie_set;
	unsigned char master_secret[TLS_MASTER_SIZE];
	unsigned int master_secret_set;

	char *body;
	unsigned int body_length;
	unsigned int headers_complete;
	unsigned int message_complete;
	unsigned dtls_mtu;
	unsigned cstp_mtu;
};

typedef struct worker_st {
	struct tls_st *creds;
	gnutls_session_t session;
	gnutls_session_t dtls_session;
	int cmd_fd;
	int conn_fd;
	
	http_parser *parser;
	struct cfg_st *config;

	struct sockaddr_storage remote_addr;	/* peer's address */
	socklen_t remote_addr_len;
	int proto; /* AF_INET or AF_INET6 */
	
	/* for dead peer detection */
	time_t last_msg_udp;
	time_t last_msg_tcp;
	time_t last_periodic_check;

	/* set after authentication */
	int udp_fd;
	udp_port_state_t udp_state;
	
	/* for mtu trials */
	unsigned last_good_mtu;
	unsigned last_bad_mtu;
	unsigned conn_mtu;
	
	/* Buffer used by worker */
	uint8_t * buffer;
	unsigned buffer_size;

	/* the following are set only if authentication is complete */
	char tun_name[IFNAMSIZ];
	char username[MAX_USERNAME_SIZE];
	char hostname[MAX_HOSTNAME_SIZE];
	uint8_t cookie[COOKIE_SIZE];
	uint8_t master_secret[TLS_MASTER_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	unsigned auth_ok;
	unsigned cert_auth_ok;
	int tun_fd;
	
	struct http_req_st req;
} worker_st;

void vpn_server(struct worker_st* ws);

int auth_cookie(worker_st *ws, void* cookie, size_t cookie_size);

int get_auth_handler(worker_st *server, unsigned http_ver);
int post_auth_handler(worker_st *server, unsigned http_ver);

void set_resume_db_funcs(gnutls_session_t);


void __attribute__ ((format(printf, 3, 4)))
    oclog(const worker_st * server, int priority, const char *fmt, ...);

int get_rt_vpn_info(worker_st * ws,
                    struct vpn_st* vinfo, char* buffer, size_t buffer_size);
ssize_t tun_write(int sockfd, const void *buf, size_t len);

int send_tun_mtu(worker_st *ws, unsigned int mtu);
int handle_worker_commands(struct worker_st *ws);
int disable_system_calls(struct worker_st *ws);

#endif
