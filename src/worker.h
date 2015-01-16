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
#include <common.h>
#include <str.h>
#include <worker-bandwidth.h>
#include <sys/un.h>
#include <sys/uio.h>

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
	HEADER_CSTP_BASE_MTU,
	HEADER_CSTP_ATYPE,
	HEADER_DEVICE_TYPE,
	HEADER_DTLS_CIPHERSUITE,
	HEADER_CONNECTION,
	HEADER_FULL_IPV6,
	HEADER_USER_AGENT,
	HEADER_CSTP_ENCODING,
	HEADER_DTLS_ENCODING
};

enum {
	HTTP_HEADER_INIT = 0,
	HTTP_HEADER_RECV,
	HTTP_HEADER_VALUE_RECV
};

enum {
	S_AUTH_INACTIVE = 0,
	S_AUTH_INIT,
	S_AUTH_REQ,
	S_AUTH_COOKIE,
	S_AUTH_COMPLETE
};

enum {
	AGENT_UNKNOWN,
	AGENT_OPENCONNECT_V3,
	AGENT_OPENCONNECT
};

typedef int (*decompress_fn)(void* dst, int maxDstSize, const void* src, int src_size);
typedef int (*compress_fn)(void* dst, int dst_size, const void* src, int src_size);

typedef struct compression_method_st {
	comp_type_t id;
	const char *name;
	decompress_fn decompress;
	compress_fn compress;
	unsigned server_prio; /* the highest the more we want to negotiate that */
} compression_method_st;

typedef struct dtls_ciphersuite_st {
	const char* oc_name;
	const char* gnutls_name; /* the gnutls priority string to set */
	unsigned server_prio; /* the highest the more we want to negotiate that */
	unsigned gnutls_cipher;
	unsigned gnutls_mac;
	unsigned gnutls_version;
} dtls_ciphersuite_st;

struct http_req_st {
	char url[256];

	str_st header;
	str_st value;
	unsigned int header_state;

	char hostname[MAX_HOSTNAME_SIZE];
	char user_agent[MAX_AGENT_NAME];
	unsigned user_agent_type;;

	unsigned int next_header;

	unsigned int is_mobile;

	unsigned char master_secret[TLS_MASTER_SIZE];
	unsigned int master_secret_set;

	char *body;
	unsigned int body_length;

	const dtls_ciphersuite_st *selected_ciphersuite;

	unsigned int headers_complete;
	unsigned int message_complete;
	unsigned base_mtu;
	
	unsigned no_ipv4;
	unsigned no_ipv6;
};

typedef struct dtls_transport_ptr {
	int fd;
	UdpFdMsg *msg; /* holds the data of the first client hello */
	int consumed;
} dtls_transport_ptr;

typedef struct worker_st {
	struct tls_st *creds;
	gnutls_session_t session;
	gnutls_session_t dtls_session;

	const compression_method_st *dtls_selected_comp;
	const compression_method_st *cstp_selected_comp;

	struct http_req_st req;

	/* inique session identifier */
	uint8_t sid[SID_SIZE];
	unsigned int sid_set;

	int cmd_fd;
	int conn_fd;
	sock_type_t conn_type; /* AF_UNIX or something else */
	
	http_parser *parser;
	struct cfg_st *config;
	unsigned int auth_state; /* S_AUTH */

	struct sockaddr_un secmod_addr;	/* sec-mod unix address */
	socklen_t secmod_addr_len;

	struct sockaddr_storage remote_addr;	/* peer's address */
	socklen_t remote_addr_len;
	int proto; /* AF_INET or AF_INET6 */

	time_t session_start_time;

	/* for dead peer detection */
	time_t last_msg_udp;
	time_t last_msg_tcp;

	time_t last_nc_msg; /* last message that wasn't control, on any channel */

	time_t last_periodic_check;

	/* set after authentication */
	dtls_transport_ptr dtls_tptr;
	udp_port_state_t udp_state;
	time_t udp_recv_time; /* time last udp packet was received */

	/* protection from multiple rehandshakes */
	time_t last_tls_rehandshake;
	time_t last_dtls_rehandshake;

	/* the time the last stats message was sent */
	time_t last_stats_msg;

	/* for mtu trials */
	unsigned last_good_mtu;
	unsigned last_bad_mtu;

	/* bandwidth stats */
	bandwidth_st b_tx;
	bandwidth_st b_rx;

	/* ws->conn_mtu: The MTU of the plaintext data we can send to the client.
	 *  It also matches the MTU of the TUN device. Note that this is
	 *  the same as the 'real' MTU of the connection, minus the IP+UDP+CSTP headers
	 *  and the DTLS crypto overhead. */
	unsigned conn_mtu;
	unsigned crypto_overhead; /* estimated overhead of DTLS ciphersuite + DTLS CSTP HEADER */
	
	/* Indicates whether the new IPv6 headers will
	 * be sent or the old */
	unsigned full_ipv6;

	/* Buffer used by worker */
	uint8_t buffer[16*1024];
	/* Buffer used for decompression */
	uint8_t decomp[16*1024];
	unsigned buffer_size;

	/* the following are set only if authentication is complete */

	char username[MAX_USERNAME_SIZE];
	char groupname[MAX_GROUPNAME_SIZE];

	char cert_username[MAX_USERNAME_SIZE];
	char **cert_groups;
	unsigned cert_groups_size;

	char hostname[MAX_HOSTNAME_SIZE];
	uint8_t *cookie;
	unsigned cookie_size;

	unsigned int cookie_set;

	uint8_t master_secret[TLS_MASTER_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	unsigned cert_auth_ok;
	int tun_fd;

	/* tun device stats */
	uint64_t tun_bytes_in;
	uint64_t tun_bytes_out;

	/* information on the tun device addresses and network */
	struct vpn_st vinfo;
	unsigned default_route;
	
	/* additional data - received per user or per group */
	unsigned routes_size;
	char** routes;
	unsigned dns_size;
	char** dns;
	unsigned nbns_size;
	char** nbns;

	void *main_pool; /* to be used only on deinitialization */
} worker_st;

void vpn_server(struct worker_st* ws);

int auth_cookie(worker_st *ws, void* cookie, size_t cookie_size);
int auth_user_deinit(worker_st *ws);

int get_auth_handler(worker_st *server, unsigned http_ver);
int post_auth_handler(worker_st *server, unsigned http_ver);

int get_empty_handler(worker_st *server, unsigned http_ver);
int get_config_handler(worker_st *ws, unsigned http_ver);
int get_string_handler(worker_st *ws, unsigned http_ver);
int get_dl_handler(worker_st *ws, unsigned http_ver);
int get_cert_names(worker_st * ws, const gnutls_datum_t * raw);

void set_resume_db_funcs(gnutls_session_t);


void __attribute__ ((format(printf, 3, 4)))
    _oclog(const worker_st * server, int priority, const char *fmt, ...);

#ifdef __GNUC__
# define oclog(server, prio, fmt, ...) \
	(prio==LOG_ERR)?_oclog(server, prio, "%s:%d: "fmt, __FILE__, __LINE__, ##__VA_ARGS__): \
	_oclog(server, prio, fmt, ##__VA_ARGS__)
#else
# define oclog _oclog
#endif

void  oclog_hex(const worker_st* ws, int priority,
		const char *prefix, uint8_t* bin, unsigned bin_size, unsigned b64);

typedef int (*url_handler_fn) (worker_st *, unsigned http_ver);
int http_url_cb(http_parser * parser, const char *at, size_t length);
int http_header_value_cb(http_parser * parser, const char *at, size_t length);
int http_header_field_cb(http_parser * parser, const char *at, size_t length);
int http_header_complete_cb(http_parser * parser);
int http_message_complete_cb(http_parser * parser);
int http_body_cb(http_parser * parser, const char *at, size_t length);
void http_req_deinit(worker_st * ws);
void http_req_reset(worker_st * ws);
void http_req_init(worker_st * ws);

url_handler_fn http_get_url_handler(const char *url);
url_handler_fn http_post_url_handler(const char *url);

int complete_vpn_info(worker_st * ws,
                    struct vpn_st* vinfo);
unsigned check_if_default_route(char **routes, unsigned routes_size);

int send_tun_mtu(worker_st *ws, unsigned int mtu);
int handle_worker_commands(struct worker_st *ws);
int disable_system_calls(struct worker_st *ws);
void ocsigaltstack(struct worker_st *ws);

int connect_to_secmod(worker_st * ws);
inline static
int send_msg_to_secmod(worker_st * ws, int sd, uint8_t cmd,
		       const void *msg, pack_size_func get_size, pack_func pack)
{
	oclog(ws, LOG_DEBUG, "sending message '%s' to secmod",
	      cmd_request_to_str(cmd));

	return send_msg(ws, sd, cmd, msg, get_size, pack);
}

inline static
int send_msg_to_main(worker_st *ws, uint8_t cmd, 
	    const void* msg, pack_size_func get_size, pack_func pack)
{
	oclog(ws, LOG_DEBUG, "sending message '%s' to main", cmd_request_to_str(cmd));
	return send_msg(ws, ws->cmd_fd, cmd, msg, get_size, pack);
}

/* after that time (secs) of inactivity in the UDP part, connection switches to 
 * TCP (if activity occurs there).
 */
#define UDP_SWITCH_TIME 15
#define ACTIVE_SESSION_TIMEOUT 30

#endif
