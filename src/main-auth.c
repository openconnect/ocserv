/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#include <script-list.h>
#include "ipc.h"
#include "str.h"

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>
#include <main-auth.h>
#include <plain.h>
#include <common.h>
#include <pam.h>

static const struct auth_mod_st *module = NULL;

void main_auth_init(main_server_st *s)
{
#ifdef HAVE_PAM
	if ((s->config->auth_types & pam_auth_funcs.type) == pam_auth_funcs.type)
		module = &pam_auth_funcs;
	else
#endif
	if ((s->config->auth_types & plain_auth_funcs.type) == plain_auth_funcs.type) {
		module = &plain_auth_funcs;
		s->auth_extra = s->config->plain_passwd;
	}
}

static int send_value_length(main_server_st* s, struct proc_st* proc, const void* data, size_t _len)
{
	uint16_t len = _len;
	int ret;

	if (len > 0) {
		ret = force_write(proc->fd, &len, 2);
		if (ret < 0)
			return ret;

		ret = force_write(proc->fd, data, len);
		if (ret < 0)
			return ret;
	} else {
		len = 0;
		ret = force_write(proc->fd, &len, 2);
		if (ret < 0)
			return ret;
	}
	
	return 0;
}

static
int serialize_additional_config(main_server_st* s, struct proc_st* proc)
{
int ret;
unsigned i;
uint8_t len;
uint32_t t;
str_st buffer;

	str_init(&buffer);

	/* IPv4 DNS */
	if (proc->config.ipv4_dns)
		mslog(s, proc, LOG_DEBUG, "sending DNS '%s'", proc->config.ipv4_dns);

	ret = str_append_str_prefix1(&buffer, proc->config.ipv4_dns);
	if (ret < 0)
		goto cleanup;

	/* IPv6 DNS */
	if (proc->config.ipv6_dns)
		mslog(s, proc, LOG_DEBUG, "sending DNS '%s'", proc->config.ipv6_dns);
	ret = str_append_str_prefix1(&buffer, proc->config.ipv6_dns);
	if (ret < 0)
		goto cleanup;

	/* IPv4 NBNS */
	if (proc->config.ipv4_nbns)
		mslog(s, proc, LOG_DEBUG, "sending NBNS '%s'", proc->config.ipv4_nbns);
	ret = str_append_str_prefix1(&buffer, proc->config.ipv4_nbns);
	if (ret < 0)
		goto cleanup;

	/* IPv6 NBNS */
	if (proc->config.ipv6_nbns)
		mslog(s, proc, LOG_DEBUG, "sending NBNS '%s'", proc->config.ipv6_nbns);
	ret = str_append_str_prefix1(&buffer, proc->config.ipv6_nbns);
	if (ret < 0)
		goto cleanup;

	/* IPv4 netmask */
	if (proc->config.ipv4_netmask)
		mslog(s, proc, LOG_DEBUG, "sending netmask '%s'", proc->config.ipv4_netmask);
	ret = str_append_str_prefix1(&buffer, proc->config.ipv4_netmask);
	if (ret < 0)
		goto cleanup;

	/* IPv6 netmask */
	if (proc->config.ipv6_netmask)
		mslog(s, proc, LOG_DEBUG, "sending netmask '%s'", proc->config.ipv6_netmask);
	ret = str_append_str_prefix1(&buffer, proc->config.ipv6_netmask);
	if (ret < 0)
		goto cleanup;

	t = proc->config.rx_per_sec;
	ret = str_append_data(&buffer, &t, sizeof(t));
	if (ret < 0)
		goto cleanup;

	t = proc->config.tx_per_sec;
	ret = str_append_data(&buffer, &t, sizeof(t));
	if (ret < 0)
		goto cleanup;

	t = proc->config.net_priority;
	ret = str_append_data(&buffer, &t, sizeof(t));
	if (ret < 0)
		goto cleanup;

	/* routes */
	len = proc->config.routes_size;
	ret = str_append_data(&buffer, &len, 1);
	if (ret < 0)
		goto cleanup;

	for (i=0;i<proc->config.routes_size;i++) {
		mslog(s, proc, LOG_DEBUG, "sending route '%s'", proc->config.routes[i]);
		ret = str_append_str_prefix1(&buffer, proc->config.routes[i]);
		if (ret < 0)
			return ret;
	}

	ret = send_value_length(s, proc, buffer.data, buffer.length);
	if (ret < 0)
		goto cleanup;

	
	ret = 0;

cleanup:
	str_clear(&buffer);
	return ret;
}

int send_auth_reply(main_server_st* s, struct proc_st* proc,
			cmd_auth_reply_t r)
{
	struct iovec iov[1];
	uint8_t cmd[2];
	struct msghdr hdr;
	union {
		struct cmsghdr    cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr  *cmptr;
	int ret;

	if (proc->config.routes_size > MAX_ROUTES) {
		mslog(s, proc, LOG_INFO, "Note that the routes sent to the client (%d) exceed the maximum allowed (%d). Truncating.", (int)proc->config.routes_size, (int)MAX_ROUTES);
		proc->config.routes_size = MAX_ROUTES;
	}

	memset(&control_un, 0, sizeof(control_un));
	memset(&hdr, 0, sizeof(hdr));
	
	hdr.msg_iov = iov;

	if (r == REP_AUTH_OK && proc->tun_lease.name[0] != 0) {
		cmd[0] = AUTH_REP;
		cmd[1] = REP_AUTH_OK;
		
		iov[0].iov_base = cmd;
		iov[0].iov_len = 2;
		hdr.msg_iovlen = 1;

		/* Send the tun fd */
		hdr.msg_control = control_un.control;
		hdr.msg_controllen = sizeof(control_un.control);
	
		cmptr = CMSG_FIRSTHDR(&hdr);
		cmptr->cmsg_len = CMSG_LEN(sizeof(int));
		cmptr->cmsg_level = SOL_SOCKET;
		cmptr->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmptr), &proc->tun_lease.fd, sizeof(int));
	} else {
		cmd[0] = AUTH_REP;
		cmd[1] = REP_AUTH_FAILED;
	
		iov[0].iov_base = cmd;
		iov[0].iov_len = 2;
		hdr.msg_iovlen = 1;
	}
	
	ret = sendmsg(proc->fd, &hdr, 0);
	if (ret < 0) {
		int e = errno;
		mslog(s, proc, LOG_ERR, "auth_reply: sendmsg: %s", strerror(e));
		return ret;
	}

	if (cmd[1] == REP_AUTH_OK) {
		struct cmd_auth_reply_info_st resp;

		memcpy(resp.cookie, proc->cookie, COOKIE_SIZE);
		memcpy(resp.session_id, proc->session_id, sizeof(resp.session_id));
		memcpy(resp.vname, proc->tun_lease.name, sizeof(resp.vname));
		memcpy(resp.user, proc->username, sizeof(resp.user));

		ret = force_write(proc->fd, &resp, sizeof(resp));
		if (ret < 0) {
			int e = errno;
			mslog(s, proc, LOG_ERR, "auth_reply: write: %s", strerror(e));
		}

		ret = serialize_additional_config(s, proc);
		if (ret < 0) {
			mslog(s, proc, LOG_ERR, "auth_reply: error serializing config");
			return ret;
		}
	}

	return 0;
}

int send_auth_reply_msg(main_server_st* s, struct proc_st* proc)
{
	struct iovec iov[2];
	uint8_t cmd[2];
	struct msghdr hdr;
	struct cmd_auth_reply_msg_st resp;
	int ret;

	if (proc->auth_ctx == NULL)
		return -1;

	memset(&resp, 0, sizeof(resp));
	ret = module->auth_msg(proc->auth_ctx, resp.msg, sizeof(resp.msg));
	if (ret < 0)
		return ret;

	memset(&hdr, 0, sizeof(hdr));
	
	hdr.msg_iov = iov;

	cmd[0] = AUTH_REP;
	cmd[1] = REP_AUTH_MSG;

	iov[0].iov_base = cmd;
	iov[0].iov_len = 2;
	hdr.msg_iovlen++;

	ret = sendmsg(proc->fd, &hdr, 0);
	if (ret < 0) {
		int e = errno;
		mslog(s, proc, LOG_ERR, "auth_reply_msg: sendmsg: %s", strerror(e));
	}

	ret = force_write(proc->fd, &resp, sizeof(resp));
	if (ret < 0) {
		int e = errno;
		mslog(s, proc, LOG_ERR, "auth_reply_msg: write: %s", strerror(e));
	}

	return ret;
}

static int check_user_group_status(main_server_st *s, struct proc_st* proc,
		     int tls_auth_ok, const char* cert_user, const char* cert_group)
{
	if (s->config->auth_types & AUTH_TYPE_CERTIFICATE) {
		if (tls_auth_ok == 0 && s->config->force_cert_auth != 0) {
			mslog(s, proc, LOG_INFO, "user '%s' presented no certificate", proc->username);
			return -1;
		}
		
		if (tls_auth_ok != 0) {
			if (proc->username[0] == 0) {
				memcpy(proc->username, cert_user, sizeof(proc->username));
				memcpy(proc->groupname, cert_group, sizeof(proc->groupname));
				proc->username[sizeof(proc->username)-1] = 0;
				proc->groupname[sizeof(proc->groupname)-1] = 0;
			} else {
				if (strcmp(proc->username, cert_user) != 0) {
					mslog(s, proc, LOG_INFO, "user '%s' presented a certificate from user '%s'", proc->username, cert_user);
					return -1;
				}

				if (s->config->cert_group_oid != NULL && strcmp(proc->groupname, cert_group) != 0) {
					mslog(s, proc, LOG_INFO, "user '%s' presented a certificate from group '%s' but he is member of '%s'", proc->username, cert_group, proc->groupname);
					return -1;
				}
			}
		}
	}
	
	return 0;
}

int handle_auth_cookie_req(main_server_st* s, struct proc_st* proc,
 			   const struct cmd_auth_cookie_req_st * req)
{
int ret;
struct stored_cookie_st sc;
time_t now = time(0);

	ret = decrypt_cookie(s, req->cookie, sizeof(req->cookie), &sc);
	if (ret < 0)
		return -1;

	if (sc.expiration < now)
		return -1;
	
	memcpy(proc->cookie, req->cookie, sizeof(proc->cookie));
	memcpy(proc->username, sc.username, sizeof(proc->username));
	memcpy(proc->groupname, sc.groupname, sizeof(proc->groupname));
	memcpy(proc->hostname, sc.hostname, sizeof(proc->hostname));
	memcpy(proc->session_id, sc.session_id, sizeof(proc->session_id));
	proc->session_id_size = sizeof(proc->session_id);

	proc->username[sizeof(proc->username)-1] = 0;
	proc->groupname[sizeof(proc->groupname)-1] = 0;
	proc->hostname[sizeof(proc->hostname)-1] = 0;

	ret = check_user_group_status(s, proc, req->tls_auth_ok, req->cert_user, req->cert_group);
	if (ret < 0)
		return ret;

	return 0;
}

int generate_cookie(main_server_st *s, struct proc_st* proc)
{
int ret;
struct stored_cookie_st sc;

        ret = gnutls_rnd(GNUTLS_RND_NONCE, proc->session_id, sizeof(proc->session_id));
        if (ret < 0)
                return -1;
        
        proc->session_id_size = sizeof(proc->session_id);

	memcpy(sc.username, proc->username, sizeof(proc->username));
	memcpy(sc.groupname, proc->groupname, sizeof(proc->groupname));
	memcpy(sc.hostname, proc->hostname, sizeof(proc->hostname));
	memcpy(sc.session_id, proc->session_id, sizeof(proc->session_id));
	
	sc.expiration = time(0) + s->config->cookie_validity;
	
	ret = encrypt_cookie(s, &sc, proc->cookie, sizeof(proc->cookie));
	if (ret < 0)
		return -1;

	return 0;
}

int handle_auth_init(main_server_st *s, struct proc_st* proc,
		     const struct cmd_auth_init_st * req)
{
int ret = -1;
char ipbuf[128];
const char* ip;

	ip = human_addr((void*)&proc->remote_addr, proc->remote_addr_len,
			ipbuf, sizeof(ipbuf));

	if (req->user_present == 0 && s->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
        	mslog(s, proc, LOG_DEBUG, "auth init from '%s' with no username present", ip);
	        return -1;
        }

	if (req->hostname[0] != 0) {
		memcpy(proc->hostname, req->hostname, MAX_HOSTNAME_SIZE);
		proc->hostname[sizeof(proc->hostname)-1] = 0;
	}

	if (req->user_present != 0 && s->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
		ret = module->auth_init(&proc->auth_ctx, req->user, ip, s->auth_extra);
		if (ret < 0)
			return ret;

		ret = module->auth_group(proc->auth_ctx, proc->groupname, sizeof(proc->groupname));
		if (ret != 0)
			return -1;
		proc->groupname[sizeof(proc->groupname)-1] = 0;

		/* a module is allowed to change the name of the user */
		ret = module->auth_user(proc->auth_ctx, proc->username, sizeof(proc->username));
		if (ret != 0)
			memcpy(proc->username, req->user, MAX_USERNAME_SIZE);
		proc->username[sizeof(proc->username)-1] = 0;
	}

	ret = check_user_group_status(s, proc, req->tls_auth_ok, req->cert_user, req->cert_group);
	if (ret < 0)
		return ret;


	mslog(s, proc, LOG_DEBUG, "auth init for user '%s' from '%s'", proc->username, ip);

	if (s->config->auth_types & AUTH_TYPE_USERNAME_PASS) {
                return ERR_AUTH_CONTINUE;
	}
	
	return 0;
}

int handle_auth_req(main_server_st *s, struct proc_st* proc,
		    struct cmd_auth_req_st * req)
{
	if (proc->auth_ctx == NULL) {
        	mslog(s, proc, LOG_ERR, "auth req but with no context!");
		return -1;
        }
	mslog(s, proc, LOG_DEBUG, "auth req for user '%s'", proc->username);
	
	if (req->pass_size >= sizeof(req->pass))
	        return -1;
	        
        req->pass[req->pass_size] = 0;

	return module->auth_pass(proc->auth_ctx, req->pass, req->pass_size);
}

/* Checks for multiple users. 
 * 
 * It returns a negative error code if more than the maximum allowed
 * users are found.
 * 
 * In addition this function will also check whether the cookie
 * used had been re-used before, and then disconnect the old session
 * (cookies are unique). 
 */
int check_multiple_users(main_server_st *s, struct proc_st* proc)
{
struct proc_st *ctmp = NULL, *cpos;
unsigned int entries = 1; /* that one */

	list_for_each_safe(&s->clist.head, ctmp, cpos, list) {
		if (ctmp != proc) {
			if (memcmp(proc->cookie, ctmp->cookie, sizeof(proc->cookie)) == 0) {
				mslog(s, ctmp, LOG_DEBUG, "disconnecting '%s' due to new cookie connection", ctmp->username);

				/* steal its leases */
				proc->ipv4 = ctmp->ipv4;
				proc->ipv6 = ctmp->ipv6;
				ctmp->ipv4 = ctmp->ipv6 = NULL;

				kill(ctmp->pid, SIGTERM);
			} else if (strcmp(proc->username, ctmp->username) == 0) {
				entries++;
			}
		}
	}
	
	if (s->config->max_same_clients && entries > s->config->max_same_clients)
		return -1;
	
	return 0;
}

void proc_auth_deinit(main_server_st* s, struct proc_st* proc)
{
	mslog(s, proc, LOG_DEBUG, "auth deinit for user '%s'", proc->username);
	if (proc->auth_ctx != NULL) {
		module->auth_deinit(proc->auth_ctx);
		proc->auth_ctx = NULL;
	}
}
