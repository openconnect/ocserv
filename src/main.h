#ifndef MAIN_H
# define MAIN_H

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <vpn.h>
#include <tlslib.h>
#include "ipc.h"

int cmd_parser (int argc, char **argv, struct cfg_st* config);

struct listener_st {
	struct list_node list;
	int fd;
	int socktype;

	struct sockaddr_storage addr; /* local socket address */
	socklen_t addr_len;
	int family;
	int protocol;
};

struct listen_list_st {
	struct list_head head;
	unsigned int total;
};

struct proc_st {
	struct list_node list;
	int fd;
	pid_t pid;
	unsigned udp_fd_received; /* if the corresponding process has received a UDP fd */

	/* the tun lease this process has */
	struct lease_st* lease;

	struct sockaddr_storage remote_addr; /* peer address */
	socklen_t remote_addr_len;

	/* The DTLS session ID associated with the TLS session 
	 * it is either generated or restored from a cookie.
	 */
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	unsigned session_id_size; /* would act as a flag if session_id is set */
	
	/* The following are set by the worker process (or by a stored cookie) */
	char username[MAX_USERNAME_SIZE]; /* the owner */
	char hostname[MAX_HOSTNAME_SIZE]; /* the requested hostname */
	uint8_t cookie[COOKIE_SIZE]; /* the cookie associated with the session */
};

struct proc_list_st {
	struct list_head head;
	unsigned int total;
};

typedef struct main_server_st {
	struct cfg_st *config;
	struct tun_st *tun;
	hash_db_st *tls_db;
	hash_db_st *cookie_db;

	/* tls credentials */
	struct tls_st creds;

	struct listen_list_st* llist;
	struct proc_list_st* clist;
} main_server_st;

void clear_lists(main_server_st *s);

int handle_commands(main_server_st *s, struct proc_st* cur);

int user_connected(main_server_st *s, struct proc_st* cur, struct lease_st*);
void user_disconnected(main_server_st *s, struct proc_st* cur);

void expire_tls_sessions(main_server_st *s);

int send_resume_fetch_reply(main_server_st* s, struct proc_st* proc,
		cmd_resume_reply_t r, struct cmd_resume_fetch_reply_st * reply);

int send_udp_fd(main_server_st* s, struct proc_st* proc, void* cli_addr, socklen_t cli_addr_size, int fd);

int handle_resume_delete_req(main_server_st* s, struct proc_st* proc,
  			   const struct cmd_resume_fetch_req_st * req);

int handle_resume_fetch_req(main_server_st* s, struct proc_st* proc,
  			   const struct cmd_resume_fetch_req_st * req, 
  			   struct cmd_resume_fetch_reply_st * rep);

int handle_resume_store_req(main_server_st* s, struct proc_st *proc,
  			   const struct cmd_resume_store_req_st * req);

void 
__attribute__ ((format(printf, 4, 5)))
    mslog(const main_server_st * s, const struct proc_st* proc,
    	int priority, const char *fmt, ...);

int open_tun(main_server_st* s, struct lease_st** l);
int set_tun_mtu(main_server_st* s, struct proc_st * proc, unsigned mtu);

int send_auth_reply(main_server_st* s, struct proc_st* proc,
			cmd_auth_reply_t r, struct lease_st* lease);
int handle_auth_cookie_req(main_server_st* s, struct proc_st* proc,
 			   const struct cmd_auth_cookie_req_st * req, struct lease_st **lease);
int generate_and_store_vals(main_server_st *s, struct proc_st* proc);
int handle_auth_req(main_server_st *s, struct proc_st* proc,
		   const struct cmd_auth_req_st * req, struct lease_st **lease);

#endif
