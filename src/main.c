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
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>

#include <gnutls/x509.h>
#include <tlslib.h>

#include <vpn.h>
#include <cookies.h>
#include <tun.h>
#include <list.h>

int syslog_open = 0;
static unsigned int need_to_expire_cookies = 0;

static int handle_commands(struct cfg_st *config, struct tun_st *tun, int fd);

struct listen_list_st {
	struct list_head list;
	int fd;
};

struct cmd_list_st {
	struct list_head list;
	int fd;
	pid_t pid;
};

static void tls_log_func(int level, const char *str)
{
	syslog(LOG_DEBUG, "Debug[<%d>]: %s", level, str);
}

static void tls_audit_log_func(gnutls_session_t session, const char *str)
{
	syslog(LOG_AUTH, "Warning: %s", str);
}

static struct cfg_st config = {
	.auth_types = AUTH_TYPE_USERNAME_PASS,
	.workers = 1,
	.name = NULL,
	.port = 3333,
	.cert = "./test.pem",
	.key = "./test.pem",
	.cert_req = GNUTLS_CERT_IGNORE,
	.cert_user_oid =
	    GNUTLS_OID_LDAP_UID /* or just GNUTLS_OID_X520_COMMON_NAME */ ,
	.root_dir = "root/",
	.cookie_validity = 3600,
	.db_file = "/tmp/db",
	.uid = 65534,
	.gid = 65534,
	.ca = NULL,
	.network = {
		      .name = "vpns",
		      .ipv4_netmask = "255.255.255.0",
		      .ipv4 = "192.168.55.1",
		      .ipv4_dns = "192.168.55.1",
		      }
};

/* Returns 0 on success or negative value on error.
 */
static int
listen_ports(struct listen_list_st *list, const char *node,
	     int listen_port, int socktype)
{
	struct addrinfo hints, *res, *ptr;
	char portname[6];
	int s, y;
	char buf[512];
	struct listen_list_st *tmp;

	INIT_LIST_HEAD(&list->list);

	snprintf(portname, sizeof(portname), "%d", listen_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_PASSIVE
#ifdef AI_ADDRCONFIG
	    | AI_ADDRCONFIG
#endif
	    ;

	s = getaddrinfo(node, portname, &hints, &res);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n",
			gai_strerror(s));
		return -1;
	}

	for (ptr = res; ptr != NULL; ptr = ptr->ai_next) {
#ifndef HAVE_IPV6
		if (ptr->ai_family != AF_INET)
			continue;
#endif
		fprintf(stderr, "listening on %s...\n",
			human_addr(ptr->ai_addr, ptr->ai_addrlen,
				   buf, sizeof(buf)));

		s = socket(ptr->ai_family, ptr->ai_socktype,
			   ptr->ai_protocol);
		if (s < 0) {
			perror("socket() failed");
			continue;
		}
#if defined(HAVE_IPV6) && !defined(_WIN32)
		if (ptr->ai_family == AF_INET6) {
			y = 1;
			/* avoid listen on ipv6 addresses failing
			 * because already listening on ipv4 addresses: */
			setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
				   (const void *) &y, sizeof(y));
		}
#endif

		if (socktype == SOCK_STREAM) {
			y = 1;
			if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
				       (const void *) &y, sizeof(y)) < 0) {
				perror("setsockopt() failed");
				close(s);
				continue;
			}
		} else {
#if defined(IP_DONTFRAG)
			y = 1;
			if (setsockopt(s, IPPROTO_IP, IP_DONTFRAG,
				       (const void *) &y, sizeof(y)) < 0)
				perror("setsockopt(IP_DF) failed");
#elif defined(IP_MTU_DISCOVER)
			y = IP_PMTUDISC_DO;
			if (setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER,
				       (const void *) &y, sizeof(y)) < 0)
				perror("setsockopt(IP_DF) failed");
#endif
		}

		if (bind(s, ptr->ai_addr, ptr->ai_addrlen) < 0) {
			perror("bind() failed");
			close(s);
			continue;
		}

		if (socktype == SOCK_STREAM) {
			if (listen(s, 10) < 0) {
				perror("listen() failed");
				exit(1);
			}
		}

		tmp = calloc(1, sizeof(struct listen_list_st));
		tmp->fd = s;
		list_add(&(tmp->list), &(list->list));
	}

	fflush(stderr);
	freeaddrinfo(res);

	return 0;
}

static void handle_children(int signo)
{
int status;

	while (waitpid(-1, &status, WNOHANG) > 0) {
		if (WEXITSTATUS(status) != 0 ||
			(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV)) {
			if (WIFSIGNALED(status))
				syslog(LOG_ERR, "Child died with sigsegv\n");
			else
				syslog(LOG_DEBUG, "Child died with status %d\n", WEXITSTATUS(status));
		} else
			syslog(LOG_DEBUG, "Child died peacefully\n");
	}
}

static void handle_alarm(int signo)
{
	need_to_expire_cookies = 1;
}



static int verify_certificate_cb(gnutls_session_t session)
{
	unsigned int status;
	int ret, type;
	gnutls_datum_t out;

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	ret = gnutls_certificate_verify_peers2(session, &status);
	if (ret < 0) {
		syslog(LOG_ERR, "Error verifying client certificate");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	type = gnutls_certificate_type_get(session);

	ret =
	    gnutls_certificate_verification_status_print(status, type,
							 &out, 0);
	if (ret < 0) {
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	syslog(LOG_INFO, "verification: %s", out.data);

	gnutls_free(out.data);

	if (status != 0)	/* Certificate is not trusted */
		return GNUTLS_E_CERTIFICATE_ERROR;

	/* notify gnutls to continue handshake normally */
	return 0;
}

static void drop_privileges(struct cfg_st *config)
{
	int ret, e;

	if (config->gid != -1 && (getgid() == 0 || getegid() == 0)) {
		ret = setgid(config->gid);
		if (ret < 0) {
			e = errno;
			syslog(LOG_ERR, "Cannot set gid to %d: %s\n",
			       (int) config->gid, strerror(e));
			exit(1);

		}
	}

	if (config->uid != -1 && (getuid() == 0 || geteuid() == 0)) {
		ret = setuid(config->uid);
		if (ret < 0) {
			e = errno;
			syslog(LOG_ERR, "Cannot set uid to %d: %s\n",
			       (int) config->uid, strerror(e));
			exit(1);

		}
	}
}

static void clear_listen_list(struct listen_list_st* llist)
{
	struct list_head *cq;
	struct list_head *pos;
	struct listen_list_st *ltmp;

	list_for_each_safe(pos, cq, &llist->list) {
		ltmp = list_entry(pos, struct listen_list_st, list);
		close(ltmp->fd);
		list_del(&ltmp->list);
	}
}

static void clear_cmd_list(struct cmd_list_st* clist)
{
	struct list_head *cq;
	struct list_head *pos;
	struct cmd_list_st *ctmp;

	list_for_each_safe(pos, cq, &clist->list) {
		ctmp = list_entry(pos, struct cmd_list_st, list);
		close(ctmp->fd);
		list_del(&ctmp->list);
	}
}

int main(void)
{

	int fd, pid, e;
	struct tls_st creds;
	struct listen_list_st llist;
	struct cmd_list_st clist;
	struct listen_list_st *ltmp;
	struct cmd_list_st *ctmp;
	struct list_head *cq;
	struct list_head *pos;
	struct tun_st tun;
	fd_set rd;
	int val, n = 0, ret;
	struct timeval tv;
	int cmd_fd[2];

	INIT_LIST_HEAD(&clist.list);

	/*signal(SIGINT, SIG_IGN); */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, handle_children);
	signal(SIGALRM, handle_alarm);

	/* XXX load configuration */

	/* Listen to network ports */
	ret = listen_ports(&llist, config.name, config.port, SOCK_STREAM);
	if (ret < 0) {
		fprintf(stderr, "Cannot listen to specified ports\n");
		exit(1);
	}


	/* Initialize GnuTLS */
	gnutls_global_set_log_function(tls_log_func);
	gnutls_global_set_audit_log_function(tls_audit_log_func);
	gnutls_global_set_log_level(0);

	ret = gnutls_global_init();
	GNUTLS_FATAL_ERR(ret);

	ret = gnutls_certificate_allocate_credentials(&creds.xcred);
	GNUTLS_FATAL_ERR(ret);

	ret =
	    gnutls_certificate_set_x509_key_file(creds.xcred, config.cert,
						 config.key,
						 GNUTLS_X509_FMT_PEM);
	GNUTLS_FATAL_ERR(ret);


	if (config.ca != NULL) {
		ret =
		    gnutls_certificate_set_x509_trust_file(creds.xcred,
							   config.ca,
							   GNUTLS_X509_FMT_PEM);
		GNUTLS_FATAL_ERR(ret);
		printf("Processed %d CA certificate(s).\n", ret);
	}

	if (config.crl != NULL) {
		ret =
		    gnutls_certificate_set_x509_crl_file(creds.xcred,
							 config.crl,
							 GNUTLS_X509_FMT_PEM);
		GNUTLS_FATAL_ERR(ret);
	}


	if (config.cert_req != GNUTLS_CERT_IGNORE) {
		gnutls_certificate_set_verify_function(creds.xcred,
						       verify_certificate_cb);
	}

	ret = gnutls_priority_init(&creds.cprio, config.priorities, NULL);
	GNUTLS_FATAL_ERR(ret);


	alarm(config.cookie_validity + 300);
	openlog("ocserv", LOG_PID, LOG_LOCAL0);
	syslog_open = 1;

	for (;;) {
		FD_ZERO(&rd);

		list_for_each(pos, &llist.list) {
			ltmp = list_entry(pos, struct listen_list_st, list);

			val = fcntl(ltmp->fd, F_GETFL, 0);
			if ((val == -1)
			    || (fcntl(ltmp->fd, F_SETFL, val | O_NONBLOCK) <
				0)) {
				perror("fcntl()");
				exit(1);
			}

			FD_SET(ltmp->fd, &rd);
			n = MAX(n, ltmp->fd);
		}

		list_for_each(pos, &clist.list) {
			ctmp = list_entry(pos, struct cmd_list_st, list);

			FD_SET(ctmp->fd, &rd);
			n = MAX(n, ctmp->fd);
		}

		tv.tv_usec = 0;
		tv.tv_sec = 10;
		ret = select(n + 1, &rd, NULL, NULL, &tv);
		if (ret == -1 && errno == EINTR)
			continue;

		if (ret < 0) {
			syslog(LOG_ERR, "Error in select(): %s",
			       strerror(errno));
			exit(1);
		}

		/* Check for new connections to accept */
		list_for_each(pos, &llist.list) {
			ltmp = list_entry(pos, struct listen_list_st, list);
			if (FD_ISSET(ltmp->fd, &rd)) {
				fd = accept(ltmp->fd, NULL, NULL);
				if (fd < 0) {
					syslog(LOG_ERR,
					       "Error in accept(): %s",
					       strerror(errno));
					continue;
				}

				/* Create a command socket */
				ret = socketpair(AF_UNIX, SOCK_STREAM, 0, cmd_fd);
				if (ret < 0) {
					syslog(LOG_ERR, "Error creating command socket");
					exit(1);
				}

				pid = fork();
				if (pid == 0) {	/* child */
					/* Drop privileges after this point */
					drop_privileges(&config);
					/* close any open descriptors before
					 * running the server
					 */
					close(cmd_fd[0]);
					clear_listen_list(&llist);
					clear_cmd_list(&clist);

					vpn_server(&config, &creds,
						   cmd_fd[1], fd);
					exit(0);
				} else if (pid == -1) {
fork_failed:
					close(cmd_fd[0]);
					free(ctmp);
				} else { /* parent */
					ctmp = calloc(1, sizeof(struct cmd_list_st));
					if (ctmp == NULL) {
						kill(pid, SIGTERM);
						goto fork_failed;
					}

					ctmp->pid = pid;
					ctmp->fd = cmd_fd[0];
					list_add(&(ctmp->list), &(clist.list));
				}
				close(cmd_fd[1]);
				close(fd);
				
			}
		}

		/* Check for any pending commands */
		list_for_each_safe(pos, cq, &clist.list) {
			ctmp = list_entry(pos, struct cmd_list_st, list);
			
			if (FD_ISSET(ctmp->fd, &rd)) {
				ret = handle_commands(&config, &tun, ctmp->fd);
				if (ret < 0) {
					close(ctmp->fd);
					kill(ctmp->pid, SIGTERM);
					list_del(&ctmp->list);
				}
			}
		}

		/* Check if we need to expire any cookies */
		if (need_to_expire_cookies != 0) {
			need_to_expire_cookies = 0;
			pid = fork();
			if (pid == 0) {	/* child */
				/* Drop privileges after this point */
				drop_privileges(&config);

				list_for_each(pos, &llist.list) {
					ltmp =
					    list_entry(pos,
						       struct
						       listen_list_st,
						       list);
					close(ltmp->fd);
				}

				expire_cookies(&config);
				exit(0);
			}
		}

	}

	return 0;
}

static int send_auth_reply(int fd, cmd_auth_reply_t r, struct tun_id_st* tunid)
{
	struct iovec iov[2];
	uint8_t cmd[2];
	struct msghdr hdr;
	union {
		struct cmd_auth_req_st auth;
	} cmd_data;
	int ret;
	union {
		struct cmsghdr    cm;
		char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr  *cmptr;	

	memset(&hdr, 0, sizeof(hdr));
	
	cmd[0] = AUTH_REP;
	cmd[1] = r;
	hdr.msg_iovlen++;

	iov[0].iov_base = cmd;
	iov[0].iov_len = 2;
	hdr.msg_iovlen++;
	
	iov[1].iov_len = sizeof(tunid->name);
	
	hdr.msg_iov = iov;

	if (r == REP_AUTH_OK && tunid != NULL) {
		iov[1].iov_base = tunid->name;
		hdr.msg_iovlen++;

		/* Send the tun fd */
		hdr.msg_control = control_un.control;
		hdr.msg_controllen = sizeof(control_un.control);
	
		cmptr = CMSG_FIRSTHDR(&hdr);
		cmptr->cmsg_len = CMSG_LEN(sizeof(int));
		cmptr->cmsg_level = SOL_SOCKET;
		cmptr->cmsg_type = SCM_RIGHTS;
		*((int *) CMSG_DATA(cmptr)) = tunid->fd;
	}
	
	return(sendmsg(fd, &hdr, 0));
}

static int handle_auth_req(struct cfg_st *config, struct tun_st *tun,
  			   struct cmd_auth_req_st * req, struct tun_id_st *tunid)
{
int ret;

	if (strcmp(req->user, "test") == 0 && strcmp(req->pass, "test") == 0)
		ret = 0;
	else
		ret = -1;

	if (ret == 0) { /* open tun */
		ret = open_tun(config, tun, tunid);
		if (ret < 0)
		  ret = -1; /* sorry */
	}
	
	return ret;
}

static int handle_commands(struct cfg_st *config, struct tun_st *tun, int fd)
{
	struct iovec iov[2];
	uint8_t cmd;
	struct msghdr hdr;
	struct tun_id_st tunid;
	union {
		struct cmd_auth_req_st auth;
	} cmd_data;
	int ret;
	
	iov[0].iov_base = &cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = &cmd_data;
	iov[1].iov_len = sizeof(cmd_data);
	
	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = iov;
	hdr.msg_iovlen = 2;
	
	ret = recvmsg( fd, &hdr, 0);
	if (ret == -1) {
		syslog(LOG_ERR, "Cannot obtain data from command socket.");
		return -1;
	}

	if (ret == 0) {
		return -1;
	}
	
	switch(cmd) {
		case AUTH_REQ:
			ret = handle_auth_req(config, tun, &cmd_data.auth, &tunid);
			if (ret == 0) {
				ret = send_auth_reply(fd, REP_AUTH_OK, &tunid);
				close(tunid.fd);
			} else
				ret = send_auth_reply(fd, REP_AUTH_FAILED, NULL);
			
			if (ret < 0) {
				syslog(LOG_ERR, "Could not send reply cmd.");
				return -1;
			}
			break;
		default:
			syslog(LOG_ERR, "Unknown CMD 0x%x.", (unsigned)cmd);
			return -1;
	}
	
	return 0;
}
