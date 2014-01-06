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
#ifndef MAIN_H
# define MAIN_H

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <vpn.h>
#include <tlslib.h>
#include "ipc.pb-c.h"
#include <cookies.h>
#include <common.h>

int cmd_parser (int argc, char **argv, struct cfg_st* config);
void reload_cfg_file(struct cfg_st* config);
void write_pid_file(void);
void remove_pid_file(void);

/* set to 1 to start cleaning up cookies, sessions etc. */
extern unsigned int need_maintenance;

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

struct script_wait_st {
	struct list_node list;

	pid_t pid;
	unsigned int up; /* connect or disconnect script */
	struct proc_st* proc;
};

enum {
	PS_AUTH_INACTIVE,
	PS_AUTH_INIT,
	PS_AUTH_COMPLETED,
};

/* Each worker process maps to a unique proc_st structure.
 */
struct proc_st {
	struct list_node list;
	int fd; /* the command file descriptor */
	pid_t pid;
	time_t udp_fd_receive_time; /* when the corresponding process has received a UDP fd */
	
	time_t conn_time; /* the time the user connected */

	/* the tun lease this process has */
	struct tun_lease_st tun_lease;
	struct ip_lease_st *ipv4;
	struct ip_lease_st *ipv6;

	struct sockaddr_storage remote_addr; /* peer address */
	socklen_t remote_addr_len;

	/* The DTLS session ID associated with the TLS session 
	 * it is either generated or restored from a cookie.
	 */
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	unsigned session_id_size; /* would act as a flag if session_id is set */
	
	/* The following are set by the worker process (or by a stored cookie) */
	char username[MAX_USERNAME_SIZE]; /* the owner */
	char groupname[MAX_GROUPNAME_SIZE]; /* the owner's group */
	char hostname[MAX_HOSTNAME_SIZE]; /* the requested hostname */
	uint8_t cookie[COOKIE_SIZE]; /* the cookie associated with the session */

	/* if the session is initiated by a cookie the following two are set
	 * and are considered when generating an IP address.
	 */
	uint8_t seeds_are_set; /* non zero if the following two elements are set */
	uint8_t ipv4_seed[4];

	void * auth_ctx; /* the context of authentication */
	unsigned auth_status; /* PS_AUTH_ */
	unsigned auth_reqs; /* the number of requests received */
	
	unsigned applied_iroutes; /* whether the iroutes in the config have been successfully applied */
	struct group_cfg_st config; /* custom user/group config */
};

struct ip_lease_db_st {
	struct htable ht;
};

struct proc_list_st {
	struct list_head head;
	unsigned int total;
};

struct script_list_st {
	struct list_head head;
};

struct banned_st {
	struct list_node list;
	time_t failed_time;	/* The time authentication failed */
	struct sockaddr_storage addr; /* local socket address */
	socklen_t addr_len;
};

struct ban_list_st {
	struct list_head head;
};

#define CTL_READ 1
#define CTL_WRITE 2

struct ctl_handler_st {
	struct list_node list;
	int fd;
	unsigned type; /* CTL_READ/WRITE */
	unsigned enabled;
	void* watch;
};

struct ctl_list_st {
	struct list_head head;
};

typedef struct main_server_st {
	struct cfg_st *config;
	
	struct ip_lease_db_st ip_leases;

	hash_db_st *tls_db;
	
	uint8_t cookie_key[16];

	/* tls credentials */
	struct tls_st creds;

	struct listen_list_st llist;
	struct proc_list_st clist;
	struct script_list_st script_list;
	struct ban_list_st ban_list;
	
	char socket_file[_POSIX_PATH_MAX];
	pid_t sec_mod_pid;
	
	unsigned active_clients;

	void * auth_extra;

	struct ctl_list_st ctl_list;
	void * ctl_ctx;
} main_server_st;

void clear_lists(main_server_st *s);

int handle_commands(main_server_st *s, struct proc_st* cur);

int user_connected(main_server_st *s, struct proc_st* cur);
void user_disconnected(main_server_st *s, struct proc_st* cur);

void expire_tls_sessions(main_server_st *s);

int send_udp_fd(main_server_st* s, struct proc_st * proc, int fd);

int handle_resume_delete_req(main_server_st* s, struct proc_st * proc,
  			   const SessionResumeFetchMsg * req);

int handle_resume_fetch_req(main_server_st* s, struct proc_st * proc,
  			   const SessionResumeFetchMsg * req, 
  			   SessionResumeReplyMsg* rep);

int handle_resume_store_req(main_server_st* s, struct proc_st *proc,
  			   const SessionResumeStoreReqMsg *);

void 
__attribute__ ((format(printf, 4, 5)))
    _mslog(const main_server_st * s, const struct proc_st* proc,
    	int priority, const char *fmt, ...);

#ifdef __GNUC__
# define mslog(s, proc, prio, fmt, ...) \
	(prio==LOG_ERR)?_mslog(s, proc, prio, "%s:%d: "fmt, __func__, __LINE__, ##__VA_ARGS__): \
	_mslog(s, proc, prio, fmt, ##__VA_ARGS__)
#else
# define mslog _mslog
#endif

void  mslog_hex(const main_server_st * s, const struct proc_st* proc,
    	int priority, const char *prefix, uint8_t* bin, unsigned bin_size);

int open_tun(main_server_st* s, struct proc_st* proc);
int set_tun_mtu(main_server_st* s, struct proc_st * proc, unsigned mtu);

int send_auth_reply_msg(main_server_st* s, struct proc_st* proc);

int send_auth_reply(main_server_st* s, struct proc_st* proc,
			AuthReplyMsg__AUTHREP r);

int handle_auth_cookie_req(main_server_st* s, struct proc_st* proc,
 			   const AuthCookieRequestMsg * req);
int generate_cookie(main_server_st *s, struct proc_st* proc);
int handle_auth_init(main_server_st *s, struct proc_st* proc,
		     const AuthInitMsg * req);
int handle_auth_req(main_server_st *s, struct proc_st* proc,
		     const AuthRequestMsg * req);

int check_multiple_users(main_server_st *s, struct proc_st* proc);

void add_to_ip_ban_list(main_server_st* s, struct sockaddr_storage *addr, socklen_t addr_len);
void expire_banned(main_server_st* s);
int check_if_banned(main_server_st* s, struct sockaddr_storage *addr, socklen_t addr_len);

int handle_script_exit(main_server_st *s, struct proc_st* proc, int code);

void run_sec_mod(main_server_st * s);

int parse_group_cfg_file(main_server_st* s, const char* file, struct group_cfg_st *config);

void del_additional_config(struct group_cfg_st* config);
void remove_proc(main_server_st* s, struct proc_st *proc, unsigned k);

void put_into_cgroup(main_server_st * s, const char* cgroup, pid_t pid);

inline static
int send_msg_to_worker(main_server_st* s, struct proc_st* proc, uint8_t cmd, 
	    const void* msg, pack_size_func get_size, pack_func pack)
{
	mslog(s, proc, LOG_DEBUG, "sending message %u to worker", (unsigned)cmd);
	return send_msg(proc->fd, cmd, msg, get_size, pack);
}

inline static
int send_socket_msg_to_worker(main_server_st* s, struct proc_st* proc, uint8_t cmd, 
		int socketfd, const void* msg, pack_size_func get_size, pack_func pack)
{
	mslog(s, proc, LOG_DEBUG, "sending (socket) message %u to worker", (unsigned)cmd);
	return send_socket_msg(proc->fd, cmd, socketfd, msg, get_size, pack);
}

void ctl_handle_commands(main_server_st* s, struct ctl_handler_st* ctl);
int ctl_handler_init(main_server_st* s);
void ctl_handler_deinit(main_server_st* s);

#endif
