#include <gnutls/gnutls.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define AC_PKT_DATA             0	/* Uncompressed data */
#define AC_PKT_DPD_OUT          3	/* Dead Peer Detection */
#define AC_PKT_DPD_RESP         4	/* DPD response */
#define AC_PKT_DISCONN          5	/* Client disconnection notice */
#define AC_PKT_KEEPALIVE        7	/* Keepalive */
#define AC_PKT_COMPRESSED       8	/* Compressed data */
#define AC_PKT_TERM_SERVER      9	/* Server kick */

#define CERTFILE "/tmp/test.pem"

static const char *const cookies[] = {
};

#define nr_cookies (sizeof(cookies) / sizeof(cookies[0]))

static int syslog_open = 0;

#define GNUTLS_FATAL_ERR(x) \
        if (x < 0 && gnutls_error_is_fatal (x) != 0) { \
                if (syslog_open) \
        		syslog(LOG_ERR, "GnuTLS error (at %d): %s", __LINE__, gnutls_strerror(x)); \
                else \
                        fprintf(stderr, "GnuTLS error (at %d): %s\n", __LINE__, gnutls_strerror(x)); \
                exit(1); \
        }

static ssize_t tls_send(gnutls_session_t session, const void *data,
			size_t data_size)
{
	int ret;

	do {
		ret = gnutls_record_send(session, data, data_size);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	
	return ret;
}

static ssize_t tls_recv(gnutls_session_t session, void *data,
			size_t data_size)
{
	int ret;

	do {
		ret = gnutls_record_recv(session, data, data_size);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	
	return ret;
}

static int tls_gets(gnutls_session_t session, char *buf, size_t len)
{
	int i = 0;
	int ret;

	if (len < 2)
		return -EINVAL;

	while ((ret = tls_recv(session, buf + i, 1)) == 1) {
		if (buf[i] == '\n') {
			buf[i] = 0;
			if (i && buf[i - 1] == '\r') {
				buf[i - 1] = 0;
				i--;
			}
			return i;
		}
		i++;

		if (i >= len - 1) {
			buf[i] = 0;
			return i;
		}
	}
	buf[i] = 0;
	return i ? : ret;
}

static int __attribute__ ((format(printf, 2, 3)))
    tls_printf(gnutls_session_t session, const char *fmt, ...)
{
	char buf[1024];
	va_list args;

	buf[1023] = 0;

	va_start(args, fmt);
	vsnprintf(buf, 1023, fmt, args);
	va_end(args);
	return tls_send(session, buf, strlen(buf));

}

static int hexnybble(char x)
{
	if (x >= '0' && x <= '9')
		return x - '0';

	if (x >= 'a' && x <= 'f')
		return 10 + x - 'a';

	if (x >= 'A' && x <= 'F')
		return 10 + x - 'A';

	return -1;
}

static void tls_close(gnutls_session_t session)
{
	gnutls_bye(session, GNUTLS_SHUT_WR);
	gnutls_deinit(session);
}

static void tls_fatal_close(gnutls_session_t session,
			    gnutls_alert_description_t a)
{
	gnutls_alert_send(session, GNUTLS_AL_FATAL, a);
	gnutls_deinit(session);
}



int main(void)
{
	int tun_nr = -1;
	struct ifreq ifr;
	unsigned char buf[2048];
	int tunfd;
	int i, ret;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t session;
	gnutls_priority_t priority_cache;

	ret = gnutls_global_init();
	GNUTLS_FATAL_ERR(ret);

	ret = gnutls_certificate_allocate_credentials(&x509_cred);
	GNUTLS_FATAL_ERR(ret);

	ret =
	    gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE,
						 CERTFILE,
						 GNUTLS_X509_FMT_PEM);
	GNUTLS_FATAL_ERR(ret);

	/*
	   ret = gnutls_certificate_set_x509_trust_file (x509_cred, TRUSTFILE,
	   GNUTLS_X509_FMT_PEM);
	   GNUTLS_FATAL_ERR(ret);
	 */

	ret = gnutls_priority_init(&priority_cache, "NORMAL", NULL);
	GNUTLS_FATAL_ERR(ret);

	/* initialize the session */
	ret = gnutls_init(&session, GNUTLS_SERVER);
	GNUTLS_FATAL_ERR(ret);

	ret = gnutls_priority_set(session, priority_cache);
	GNUTLS_FATAL_ERR(ret);

	ret =
	    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				   x509_cred);
	GNUTLS_FATAL_ERR(ret);

	gnutls_certificate_server_set_request(session, GNUTLS_CERT_IGNORE);

	gnutls_transport_set_ptr2(session, (gnutls_transport_ptr_t) 0,
				  (gnutls_transport_ptr_t) 1);

	openlog("ocserv", LOG_PID, LOG_LOCAL0);
	syslog_open = 1;

	do {
		ret = gnutls_handshake(session);
		GNUTLS_FATAL_ERR(ret);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	syslog(LOG_INFO, "Accepted connection\n");

      next:
	if (tls_gets(session, buf, sizeof(buf)) <= 0) {
		syslog(LOG_INFO, "Bad first line\n");
		exit(1);
	}

	if (!strcmp(buf, "GET / HTTP/1.1")) {
		syslog(LOG_INFO, "Initial login request\n");
		while ((i = tls_gets(session, buf, sizeof(buf))) > 0)
			syslog(LOG_INFO, "incoming hdr: '%s'\n", buf);
		if (i < 0)
			exit(1);
		tls_printf(session, "HTTP/1.1 200 OK\r\n");
		tls_printf(session, "Connection: close\r\n");
		tls_printf(session, "Content-Type: text/xml\r\n");
		tls_printf(session, "X-Transcend-Version: 1\r\n");
		tls_printf(session, "\r\n");
		tls_printf(session,
			   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
		tls_printf(session, "<auth id=\"main\">\r\n");
		tls_printf(session,
			   "<message>Please enter your login cookie.</message>\r\n");
		tls_printf(session,
			   "<form method=\"post\" action=\"/login.html\">\r\n");
		tls_printf(session,
			   "<input type=\"text\" name=\"cookie\" label=\"Cookie:\" />\r\n");
		tls_printf(session, "</form></auth>\r\n");

		tls_close(session);
		exit(0);
	} else if (!strcmp(buf, "POST /login.html HTTP/1.1")) {
		int len = 0;
		syslog(LOG_INFO, "Login post\n");
		while ((i = tls_gets(session, buf, sizeof(buf))) > 0) {
			syslog(LOG_INFO, "incoming hdr: '%s'\n", buf);
			if (!strncmp(buf, "Content-Length: ", 16))
				len = atoi(buf + 16);
		}
		syslog(LOG_INFO, "Len is %d\n", len);
		if (len >= sizeof(buf)) {
			tls_printf(session,
				   "HTTP/1/1 404 Response too long\r\n\r\n");
			tls_close(session);
			exit(1);
		}

		ret = tls_recv(session, buf, len);
		GNUTLS_FATAL_ERR(ret);

		buf[ret] = 0;
		syslog(LOG_INFO, "got post '%s'\n", buf);
		if (strncmp(buf, "cookie=", 7)) {
			tls_printf(session,
				   "HTTP/1.1 404 Not a cookie\r\n\r\n");
			tls_close(session);
			exit(1);
		}
		for (i = 0; i < nr_cookies; i++) {
			int j = 0, k = 7;

			while (cookies[i][j]) {
				int c = buf[k];
				if (c == '%' && buf[k + 1] && buf[k + 2]) {
					c = (hexnybble(buf[k + 1]) << 4) +
					    hexnybble(buf[k + 2]);
					k += 2;
				}
				if (c != cookies[i][j])
					break;
				j++;
				k++;
			}
			/* Break out of outer loop if it was a match */
			if (!cookies[i][j] && !buf[k])
				break;
		}
		if (i == nr_cookies) {
			syslog(LOG_INFO, "Cookie not recognised\n");
			tls_printf(session, "HTTP/1.1 200 OK\r\n");
			tls_printf(session, "Connection: close\r\n");
			tls_printf(session, "Content-Type: text/xml\r\n");
			tls_printf(session, "X-Transcend-Version: 1\r\n");
			tls_printf(session, "\r\n");
			tls_printf(session,
				   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
			tls_printf(session, "<auth id=\"main\">\r\n");
			tls_printf(session,
				   "<banner>Invalid cookie</banner>\r\n");
			tls_printf(session,
				   "<message>Please enter your login cookie.</message>\r\n");
			tls_printf(session,
				   "<form method=\"post\" action=\"/login.html\">\r\n");
			tls_printf(session,
				   "<input type=\"text\" name=\"cookie\" label=\"Cookie:\" />\r\n");
			tls_printf(session, "</form></auth>\r\n");
			tls_close(session);
			exit(0);
		}
		syslog(LOG_INFO, "Cookie OK\n");
		tls_printf(session, "HTTP/1.1 200 OK\r\n");
		tls_printf(session, "Content-Type: text/xml\r\n");
		tls_printf(session, "X-Transcend-Version: 1\r\n");
		tls_printf(session, "Set-Cookie: webvpn=%s\r\n",
			   cookies[i]);

		len = snprintf(buf, sizeof(buf),
			       "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
			       "<auth id=\"success\">\r\n"
			       "<banner>Success</banner>\r\n"
			       "</auth>\r\n");

		tls_printf(session, "Content-Length: %d\r\n", len);
		tls_printf(session, "\r\n");
		ret = tls_send(session, buf, len);
		GNUTLS_FATAL_ERR(ret);

		goto next;
	} else if (strcmp(buf, "CONNECT /CSCOSSLC/tunnel HTTP/1.1")) {
		syslog(LOG_INFO, "Bad request: '%s'\n", buf);
		tls_printf(session, "HTTP/1.1 404 Nah, go away\r\n\r\n");
		exit(1);
	}
	while ((i = tls_gets(session, buf, sizeof(buf))) > 0) {
		syslog(LOG_INFO, "incoming hdr: '%s'\n", buf);
		if (!strncmp(buf, "Cookie: webvpn=", 15)) {
			for (i = 0; i < nr_cookies; i++) {
				if (!strcmp(cookies[i], buf + 15)) {
					tun_nr = i;
					break;
				}
			}
		}
	}
	if (i < 0)
		exit(1);
	syslog(LOG_INFO, "tun_nr is %d\n", tun_nr);
	if (tun_nr < 0) {
		tls_printf(session, "HTTP/1.1 503 Bad cookie\r\n");
		tls_printf(session,
			   "X-Reason: I did not like your cookie\r\n\r\n");
		tls_fatal_close(session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}
	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd < 0) {
		int e = errno;
		syslog(LOG_INFO, "Can't open /dev/net/tun: %s\n",
		       strerror(e));
		tls_printf(session, "HTTP/1.1 503 no tun device\r\n");
		tls_printf(session,
			   "X-Reason: Could not open /dev/net/tun: %s\r\n\r\n",
			   strerror(e));
		tls_fatal_close(session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "vpns%d", tun_nr);
	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0) {
		int e = errno;
		syslog(LOG_INFO, "TUNSETIFF: %s\n", strerror(e));
		tls_printf(session, "HTTP/1.1 503 TUNSETIFF\r\n");
		tls_printf(session,
			   "X-Reason: TUNSETIFF failed: %s\r\n\r\n",
			   strerror(errno));
		tls_fatal_close(session, GNUTLS_A_ACCESS_DENIED);
		exit(1);
	}

	tls_printf(session, "HTTP/1.1 200 connected\r\n");
	tls_printf(session, "X-CSTP-MTU: 1500\r\n");
	tls_printf(session, "X-CSTP-DPD: 60\r\n");
	tls_printf(session, "X-CSTP-Address: 172.31.255.%d\r\n",
		   100 + tun_nr);
	tls_printf(session, "X-CSTP-Netmask: 255.255.255.255\r\n");
	tls_printf(session, "X-CSTP-DNS: 172.31.255.1\r\n");
	tls_printf(session, "X-CSTP-Address: 2001:770:15f::%x\r\n",
		   0x100 + tun_nr);
	tls_printf(session, "X-CSTP-Netmask: 2001:770:15f::%x/128\r\n",
		   0x100 + tun_nr);
	tls_printf(session,
		   "X-CSTP-Split-Include: 172.31.255.0/255.255.255.0\r\n");
	tls_printf(session, "X-CSTP-Banner: Hello there\r\n");
	tls_printf(session, "\r\n");
	while (1) {
		fd_set rfds;
		int l, pktlen;

		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(tunfd, &rfds);

		if (select(tunfd + 1, &rfds, NULL, NULL, NULL) <= 0)
			break;

		if (FD_ISSET(0, &rfds)) {
			l = tls_recv(session, buf, sizeof(buf));
			GNUTLS_FATAL_ERR(l);

			if (l < 8) {
				syslog(LOG_INFO,
				       "Can't read CSTP header\n");
				exit(1);
			}
			if (buf[0] != 'S' || buf[1] != 'T' ||
			    buf[2] != 'F' || buf[3] != 1 || buf[7]) {
				syslog(LOG_INFO,
				       "Can't recognise CSTP header\n");
				exit(1);
			}
			pktlen = (buf[4] << 8) + buf[5];
			if (l != 8 + pktlen) {
				syslog(LOG_INFO, "Unexpected length\n");
				exit(1);
			}
			switch (buf[6]) {
			case AC_PKT_DPD_RESP:
			case AC_PKT_KEEPALIVE:
				break;

			case AC_PKT_DPD_OUT:
				ret =
				    tls_send(session, "STF\x1\x0\x0\x4\x0",
					     8);
				GNUTLS_FATAL_ERR(ret);
				break;

			case AC_PKT_DISCONN:
				syslog(LOG_INFO, "Received BYE packet\n");
				break;

			case AC_PKT_DATA:
				write(tunfd, buf + 8, pktlen);
				break;
			}
		}
		if (FD_ISSET(tunfd, &rfds)) {
			int l = read(tunfd, buf + 8, sizeof(buf) - 8);
			buf[0] = 'S';
			buf[1] = 'T';
			buf[2] = 'F';
			buf[3] = 1;
			buf[4] = l >> 8;
			buf[5] = l & 0xff;
			buf[6] = 0;
			buf[7] = 0;

			ret = tls_send(session, buf, l + 8);
			GNUTLS_FATAL_ERR(ret);
		}


	}
}
