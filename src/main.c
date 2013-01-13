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
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <gnutls/x509.h>
#include <tlslib.h>

#include <vpn.h>
#include <cookies.h>
#include <vpn.h>
#include <list.h>

int syslog_open = 0;
static unsigned int need_to_expire_cookies = 0;

struct listen_list_st {
	struct list_head list;
	int fd;
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
	.name = NULL,
	.port = 3333,
	.cert = "./test.pem",
	.key = "./test.pem",
	.cert_req = GNUTLS_CERT_IGNORE,
	.cert_user_oid = GNUTLS_OID_LDAP_UID /* or just GNUTLS_OID_X520_COMMON_NAME */,
	.root_dir = "root/",
	.cookie_validity = 3600,
	.db_file = "/tmp/db",
	.ca = NULL,
	.networks_size = 1,
	.networks = {{
		.name = "vpns0",
		.ipv4_netmask = "255.255.255.0",
		.ipv4 = "192.168.55.1",
		.ipv4_dns = "192.168.55.1",
	}}
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
	while (waitpid(-1, NULL, WNOHANG) > 0);
}

static void handle_alarm(int signo)
{
	need_to_expire_cookies = 1;
}

static int open_tun(void)
{
int tunfd;
struct ifreq ifr;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd < 0) {
		int e = errno;
		syslog(LOG_ERR, "Can't open /dev/net/tun: %s\n",
		       strerror(e));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "vpns%d", 0);
	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0) {
		int e = errno;
		syslog(LOG_ERR, "TUNSETIFF: %s\n", strerror(e));
		exit(1);
	}

	return tunfd;
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



int main(void)
{

	int fd, pid;
	struct tls_st creds;
	struct listen_list_st llist;
	struct listen_list_st *tmp;
	struct list_head *pos;
	fd_set rd;
	int val, n = 0, ret, tunfd;
	struct timeval tv;

	/*signal(SIGINT, SIG_IGN); */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, handle_children);
	signal(SIGALRM, handle_alarm);

	/* XXX load configuration */

	ret = listen_ports(&llist, config.name, config.port, SOCK_STREAM);
	if (ret < 0) {
		exit(1);
	}

	tunfd = open_tun();
	if (tunfd < 0) {
		exit(1);
	}

	/* XXX drop any privileges */

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

	alarm(config.cookie_validity+300);
	openlog("ocserv", LOG_PID, LOG_LOCAL0);
	syslog_open = 1;

	for (;;) {
		FD_ZERO(&rd);

		list_for_each(pos, &llist.list) {
			tmp = list_entry(pos, struct listen_list_st, list);
#ifndef _WIN32
			val = fcntl(tmp->fd, F_GETFL, 0);
			if ((val == -1)
			    || (fcntl(tmp->fd, F_SETFL, val | O_NONBLOCK) <
				0)) {
				perror("fcntl()");
				exit(1);
			}
#endif

			FD_SET(tmp->fd, &rd);
			n = MAX(n, tmp->fd);
		}

		tv.tv_usec = 0;
		tv.tv_sec = 10;
		n = select(n + 1, &rd, NULL, NULL, &tv);
		if (n == -1 && errno == EINTR)
			continue;

		if (n < 0) {
			syslog(LOG_ERR, "Error in select(): %s", strerror(errno));
			exit(1);
		}

		if (need_to_expire_cookies != 0) {
			need_to_expire_cookies = 0;
			pid = fork();
			if (pid == 0) {	/* child */
				list_for_each(pos, &llist.list) {
					tmp = list_entry(pos, struct listen_list_st, list);
					close(tmp->fd);
				}

				expire_cookies(&config);
				exit(0);
			}
		}

		list_for_each(pos, &llist.list) {
			tmp = list_entry(pos, struct listen_list_st, list);
			if (FD_ISSET(tmp->fd, &rd)) {
				fd = accept(tmp->fd, NULL, NULL);
				if (fd < 0) {
					syslog(LOG_ERR, "Error in accept(): %s", strerror(errno));
					continue;
				}

				pid = fork();
				if (pid == 0) {	/* child */
					list_for_each(pos, &llist.list) {
						tmp = list_entry(pos, struct listen_list_st, list);
						close(tmp->fd);
					}

					vpn_server(&config, &creds,
						     tunfd, fd);
					exit(0);
				}
				close(fd);
			}
		}
	}

	return 0;
}
