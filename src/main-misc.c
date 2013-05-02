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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#include <system.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <tlslib.h>
#include <sys/un.h>
#include <cloexec.h>
#include "ipc.h"
#include "setproctitle.h"
#include <sec-mod.h>

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <main.h>
#include <ccan/list/list.h>
#include "pam.h"

int set_tun_mtu(main_server_st* s, struct proc_st * proc, unsigned mtu)
{
int fd, ret, e;
struct ifreq ifr;
const char* name;

	if (proc->lease == NULL)
		return -1;

	name = proc->lease->name;

	mslog(s, proc, LOG_DEBUG, "setting %s MTU to %u", name, mtu);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
	ifr.ifr_mtu = mtu;
	
	ret = ioctl(fd, SIOCSIFMTU, &ifr);
	if (ret != 0) {
		e = errno;
		mslog(s, proc, LOG_INFO, "ioctl SIOCSIFMTU error: %s", strerror(e));
		ret = -1;
		goto fail;
	}
	
	ret = 0;
fail:
	close(fd);
	return ret;
}

int send_udp_fd(main_server_st* s, struct proc_st * proc, int fd)
{
	struct iovec iov[2];
	uint8_t cmd = CMD_UDP_FD;
	struct msghdr hdr;
	union {
		struct cmsghdr    cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr  *cmptr;	


	memset(&hdr, 0, sizeof(hdr));
	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;
	hdr.msg_iovlen++;

	hdr.msg_iov = iov;

	hdr.msg_control = control_un.control;
	hdr.msg_controllen = sizeof(control_un.control);
	
	cmptr = CMSG_FIRSTHDR(&hdr);
	cmptr->cmsg_len = CMSG_LEN(sizeof(int));
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmptr), &fd, sizeof(int));
	
	return(sendmsg(proc->fd, &hdr, 0));
}

int handle_script_exit(main_server_st *s, struct proc_st* proc, int code)
{
int ret;

	if (code == 0) {
		ret = send_auth_reply(s, proc, REP_AUTH_OK);
		if (ret < 0) {
			mslog(s, proc, LOG_ERR, "could not send reply auth cmd.");
			ret = ERR_BAD_COMMAND;
			goto fail;
		}
	} else {
		mslog(s, proc, LOG_INFO, "failed authentication attempt for user '%s'", proc->username);
		ret = send_auth_reply( s, proc, REP_AUTH_FAILED);
		if (ret < 0) {
			mslog(s, proc, LOG_ERR, "could not send reply auth cmd.");
			ret = ERR_BAD_COMMAND;
			goto fail;
		}
	}
	ret = 0;

fail:	
	/* we close the lease tun fd both on success and failure.
	 * The parent doesn't need to keep the tunfd.
	 */
	if (proc->lease) {
		if (proc->lease->fd >= 0)
			close(proc->lease->fd);
		proc->lease->fd = -1;
	}

	return ret;
}


int handle_commands(main_server_st *s, struct proc_st* proc)
{
	struct iovec iov[2];
	uint8_t cmd;
	struct msghdr hdr;
	union {
		struct cmd_auth_req_st auth;
		struct cmd_auth_cookie_req_st cauth;
		struct cmd_resume_store_req_st sresume;
		struct cmd_resume_fetch_req_st fresume;
		struct cmd_tun_mtu_st tmtu;
	} cmd_data;
	int ret, cmd_data_len, e;
	const char* group;

	memset(&cmd_data, 0, sizeof(cmd_data));
	
	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = &cmd_data;
	iov[1].iov_len = sizeof(cmd_data);
	
	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;
	
	ret = recvmsg( proc->fd, &hdr, 0);
	if (ret == -1) {
		e = errno;
		mslog(s, proc, LOG_ERR, "cannot obtain data from command socket: %s", strerror(e));
		return -1;
	}

	if (ret == 0) {
		return -1;
	}

	cmd_data_len = ret - 1;
	
	switch(cmd) {
		case CMD_TUN_MTU:
			if (cmd_data_len != sizeof(cmd_data.tmtu)) {
				mslog(s, proc, LOG_ERR, "error in received message (cmd %u) length.", (unsigned)cmd);
				return ERR_BAD_COMMAND;
			}
			
			set_tun_mtu(s, proc, cmd_data.tmtu.mtu);
			break;
		case RESUME_STORE_REQ:
			if (cmd_data_len <= sizeof(cmd_data.sresume)-MAX_SESSION_DATA_SIZE) {
				mslog(s, proc, LOG_ERR, "error in received message (cmd %u) length.", (unsigned)cmd);
				return ERR_BAD_COMMAND;
			}
			ret = handle_resume_store_req(s, proc, &cmd_data.sresume);
			if (ret < 0) {
				mslog(s, proc, LOG_DEBUG, "could not store resumption data.");
			}
			
			break;
			
		case RESUME_DELETE_REQ:
			if (cmd_data_len != sizeof(cmd_data.fresume)) {
				mslog(s, proc, LOG_ERR, "error in received message (cmd %u) length.", (unsigned)cmd);
				return ERR_BAD_COMMAND;
			}
			ret = handle_resume_delete_req(s, proc, &cmd_data.fresume);
			if (ret < 0) {
				mslog(s, proc, LOG_DEBUG, "could not delete resumption data.");
			}

			break;
		case RESUME_FETCH_REQ: {
			struct cmd_resume_fetch_reply_st reply;

			if (cmd_data_len != sizeof(cmd_data.fresume)) {
				mslog(s, proc, LOG_ERR, "error in received message (%u) length.", (unsigned)cmd);
				return ERR_BAD_COMMAND;
			}
			ret = handle_resume_fetch_req(s, proc, &cmd_data.fresume, &reply);
			if (ret < 0) {
				mslog(s, proc, LOG_DEBUG, "could not fetch resumption data.");
				ret = send_resume_fetch_reply(s, proc, REP_RESUME_FAILED, NULL);
			} else
				ret = send_resume_fetch_reply(s, proc, REP_RESUME_OK, &reply);
			}
			
			if (ret < 0) {
				mslog(s, proc, LOG_ERR, "could not send reply cmd %d.", (unsigned) cmd);
				return ERR_BAD_COMMAND;
			}
			
			break;

		case AUTH_REQ:
		case AUTH_COOKIE_REQ:
			if (cmd == AUTH_REQ) {
				if (cmd_data_len != sizeof(cmd_data.auth)) {
					mslog(s, proc, LOG_ERR, "error in received message (%u) length.", (unsigned)cmd);
					return ERR_BAD_COMMAND;
				}

				ret = handle_auth_req(s, proc, &cmd_data.auth);
			} else {
				if (cmd_data_len != sizeof(cmd_data.cauth)) {
					mslog(s, proc, LOG_ERR, "error in received message (%u) length.", (unsigned)cmd);
					return ERR_BAD_COMMAND;
				}

				ret = handle_auth_cookie_req(s, proc, &cmd_data.cauth);
			}

			if (ret == 0) {
				/* check for multiple connections */
				ret = check_multiple_users(s, proc);
				if (ret < 0) {
					mslog(s, proc, LOG_INFO, "user '%s' tried to connect more than %u times", proc->username, s->config->max_same_clients);
				}

				if (ret == 0) {
					if (proc->groupname[0] == 0)
						group = "[unknown]";
					else
						group = proc->groupname;

					if (cmd == AUTH_REQ) {
						/* generate and store cookie */
						ret = generate_and_store_vals(s, proc);
						if (ret < 0) {
							ret = ERR_BAD_COMMAND;
							goto cleanup;
						}
						mslog(s, proc, LOG_INFO, "user '%s' of group '%s' authenticated", proc->username, group);
					} else {
						mslog(s, proc, LOG_INFO, "user '%s' of group '%s' re-authenticated (using cookie)", proc->username, group);
					}
				}

				/* do scripts and utmp */
				if (ret == 0) {
					ret = user_connected(s, proc);
					if (ret == ERR_WAIT_FOR_SCRIPT) {
						return 0;
					}

					if (ret < 0) {
						mslog(s, proc, LOG_INFO, "user '%s' disconnected due to script", proc->username);
					}
				}
			} else {
				add_to_ip_ban_list(s, &proc->remote_addr, proc->remote_addr_len);
			}

cleanup:
			/* no script was called. Handle it as a successful script call. */
			return handle_script_exit(s, proc, ret);

		default:
			mslog(s, proc, LOG_ERR, "unknown CMD 0x%x.", (unsigned)cmd);
			return ERR_BAD_COMMAND;
	}
	
	return 0;
}

int check_if_banned(main_server_st* s, struct sockaddr_storage *addr, socklen_t addr_len)
{
time_t now = time(0);
struct banned_st *btmp, *bpos;

	if (s->config->min_reauth_time == 0)
		return 0;

	list_for_each_safe(&s->ban_list.head, btmp, bpos, list) {
		if (now-btmp->failed_time > s->config->min_reauth_time) {
			/* invalid entry. Clean it up */
			list_del(&btmp->list);
			free(btmp);
		} else {
			if (SA_IN_SIZE(btmp->addr_len) == SA_IN_SIZE(addr_len) &&
				memcmp(SA_IN_P_GENERIC(&btmp->addr, btmp->addr_len), 
					SA_IN_P_GENERIC(addr, addr_len), 
					SA_IN_SIZE(btmp->addr_len)) == 0) {
				return -1;
			}
		}
	}
	
	return 0;
}


void expire_banned(main_server_st* s)
{
time_t now = time(0);
struct banned_st *btmp, *bpos;

	if (s->config->min_reauth_time == 0)
		return;

	list_for_each_safe(&s->ban_list.head, btmp, bpos, list) {
		if (now-btmp->failed_time > s->config->min_reauth_time) {
			/* invalid entry. Clean it up */
			list_del(&btmp->list);
			free(btmp);
		}
	}

	return;
}

void add_to_ip_ban_list(main_server_st* s, struct sockaddr_storage *addr, socklen_t addr_len)
{
struct banned_st *btmp;

	if (s->config->min_reauth_time == 0)
		return;

	btmp = malloc(sizeof(*btmp));
	if (btmp == NULL)
		return;
	
	btmp->failed_time = time(0);
	memcpy(&btmp->addr, addr, addr_len);
	btmp->addr_len = addr_len;
	
	list_add(&s->ban_list.head, &(btmp->list));
}

void run_sec_mod(main_server_st * s)
{
int e;
pid_t pid;
char file[_POSIX_PATH_MAX];
const char *p;

	/* make socket name */
	snprintf(s->socket_file, sizeof(s->socket_file), "%s.%u", s->config->socket_file_prefix, (unsigned)getpid());
	p = s->socket_file;
	if (s->config->chroot_dir != NULL) {
		snprintf(file, sizeof(file), "%s/%s.%u", 
			s->config->chroot_dir, s->config->socket_file_prefix, (unsigned)getpid());
		p = file;
	}

	pid = fork();
	if (pid == 0) { /* child */
		clear_lists(s);
		kill_on_parent_kill(SIGTERM);
		setproctitle(PACKAGE_NAME"-secmod");

		sec_mod_server(s->config, p);
		exit(0);
	} else if (pid > 0) { /* parent */
		s->sec_mod_pid = pid;
	} else {
		e = errno;
		mslog(s, NULL, LOG_ERR, "error in fork(): %s", strerror(e));
		exit(1);
	}
}
