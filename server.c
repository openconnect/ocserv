
#include <openssl/ssl.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define AC_PKT_DATA             0       /* Uncompressed data */
#define AC_PKT_DPD_OUT          3       /* Dead Peer Detection */
#define AC_PKT_DPD_RESP         4       /* DPD response */
#define AC_PKT_DISCONN          5       /* Client disconnection notice */
#define AC_PKT_KEEPALIVE        7       /* Keepalive */
#define AC_PKT_COMPRESSED       8       /* Compressed data */
#define AC_PKT_TERM_SERVER      9       /* Server kick */

#define CERTFILE "/etc/pki/tls/certs/openconnect.pem"

static const char *const cookies[] = {
};
#define nr_cookies (sizeof(cookies) / sizeof(cookies[0]))

static int _SSL_gets(SSL *ssl, char *buf, size_t len)
{
        int i = 0;
        int ret;

        if (len < 2)
                return -EINVAL;

        while ( (ret = SSL_read(ssl, buf + i, 1)) == 1) {
                if (buf[i] == '\n') {
                        buf[i] = 0;
                        if (i && buf[i-1] == '\r') {
                                buf[i-1] = 0;
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
        if (ret == 0) {
                ret = -SSL_get_error(ssl, ret);
        }
        buf[i] = 0;
        return i ?: ret;
}

static int  __attribute__ ((format (printf, 2, 3)))
_SSL_printf(SSL *ssl, const char *fmt, ...)
{
        char buf[1024];
        va_list args;

        buf[1023] = 0;

        va_start(args, fmt);
        vsnprintf(buf, 1023, fmt, args);
        va_end(args);
        return SSL_write(ssl, buf, strlen(buf));

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

int main(void)
{
	const SSL_METHOD *tls_method;
	BIO *bio_in, *bio_out;
	SSL_CTX *ctx;
	SSL *ssl;
	int tun_nr = -1;
	struct ifreq ifr;
	unsigned char buf[2048];
	int tunfd;
	int i;

        SSL_library_init ();
        ERR_clear_error ();
        SSL_load_error_strings ();
        OpenSSL_add_all_algorithms ();

	tls_method = SSLv23_server_method();
	ctx = SSL_CTX_new(tls_method);
	if (!ctx) {
		ERR_print_errors_fp (stderr);
		exit(1);
	}
	SSL_CTX_use_certificate_chain_file (ctx, CERTFILE);
	SSL_CTX_use_PrivateKey_file (ctx, CERTFILE, SSL_FILETYPE_PEM);
	ssl = SSL_new (ctx);

	openlog ("ocserv", LOG_PID, LOG_LOCAL0);
	
	bio_in = BIO_new_fd(0, BIO_NOCLOSE);
	bio_out = BIO_new_fd(1, BIO_NOCLOSE);
	SSL_set_bio (ssl, bio_in, bio_out);
	SSL_accept (ssl);

	syslog(LOG_INFO, "Accepted connection\n");

 next:
	if (_SSL_gets(ssl, buf, sizeof(buf)) < 0) {
		syslog(LOG_INFO, "Bad first line\n");
		exit(1);
	}

	if (!strcmp(buf, "GET / HTTP/1.1")) {
		syslog(LOG_INFO, "Initial login request\n");
		while ( (i = _SSL_gets(ssl, buf, sizeof(buf))) > 0)
			syslog(LOG_INFO, "incoming hdr: '%s'\n", buf);
		if (i < 0)
			exit(1);
		_SSL_printf(ssl, "HTTP/1.1 200 OK\r\n");
		_SSL_printf(ssl, "Connection: close\r\n");
		_SSL_printf(ssl, "Content-Type: text/xml\r\n");
		_SSL_printf(ssl, "X-Transcend-Version: 1\r\n");
		_SSL_printf(ssl, "\r\n");
		_SSL_printf(ssl, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
		_SSL_printf(ssl, "<auth id=\"main\">\r\n");
		_SSL_printf(ssl, "<message>Please enter your login cookie.</message>\r\n");
		_SSL_printf(ssl, "<form method=\"post\" action=\"/login.html\">\r\n");
		_SSL_printf(ssl, "<input type=\"text\" name=\"cookie\" label=\"Cookie:\" />\r\n");
		_SSL_printf(ssl, "</form></auth>\r\n");
		SSL_shutdown(ssl);
		exit(0);
	} else if (!strcmp(buf, "POST /login.html HTTP/1.1")) {
		int len = 0;
		syslog(LOG_INFO, "Login post\n");
		while ( (i = _SSL_gets(ssl, buf, sizeof(buf))) > 0) {
			syslog(LOG_INFO, "incoming hdr: '%s'\n", buf);
			if (!strncmp(buf, "Content-Length: ", 16))
				len = atoi(buf + 16);
		}
		syslog(LOG_INFO, "Len is %d\n", len);
		if (len >= sizeof(buf)) {
			_SSL_printf(ssl, "HTTP/1/1 404 Response too long\r\n\r\n");
			SSL_shutdown(ssl);
			exit(1);
		}
		SSL_read(ssl, buf, len);
		buf[len] = 0;
		syslog(LOG_INFO, "got post '%s'\n", buf);
		if (strncmp(buf, "cookie=", 7)) {
			_SSL_printf(ssl, "HTTP/1.1 404 Not a cookie\r\n\r\n");
			SSL_shutdown(ssl);
			exit(1);
		}
		for (i = 0; i < nr_cookies; i++) {
			int j = 0, k = 7;

			while (cookies[i][j]) {
				int c = buf[k];
				if (c == '%' && buf[k+1] && buf[k+2]) {
					c = (hexnybble(buf[k+1]) << 4) +
						hexnybble(buf[k+2]);
					k+=2;
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
			_SSL_printf(ssl, "HTTP/1.1 200 OK\r\n");
			_SSL_printf(ssl, "Connection: close\r\n");
			_SSL_printf(ssl, "Content-Type: text/xml\r\n");
			_SSL_printf(ssl, "X-Transcend-Version: 1\r\n");
			_SSL_printf(ssl, "\r\n");
			_SSL_printf(ssl, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");
			_SSL_printf(ssl, "<auth id=\"main\">\r\n");
			_SSL_printf(ssl, "<banner>Invalid cookie</banner>\r\n");
			_SSL_printf(ssl, "<message>Please enter your login cookie.</message>\r\n");
			_SSL_printf(ssl, "<form method=\"post\" action=\"/login.html\">\r\n");
			_SSL_printf(ssl, "<input type=\"text\" name=\"cookie\" label=\"Cookie:\" />\r\n");
			_SSL_printf(ssl, "</form></auth>\r\n");
			SSL_shutdown(ssl);
			exit(0);
		}
		syslog(LOG_INFO, "Cookie OK\n");
		_SSL_printf(ssl, "HTTP/1.1 200 OK\r\n");
		_SSL_printf(ssl, "Content-Type: text/xml\r\n");
		_SSL_printf(ssl, "X-Transcend-Version: 1\r\n");
		_SSL_printf(ssl, "Set-Cookie: webvpn=%s\r\n", cookies[i]);

		len = snprintf(buf, sizeof(buf),
			       "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
			      "<auth id=\"success\">\r\n"
			      "<banner>Success</banner>\r\n"
			      "</auth>\r\n");

		_SSL_printf(ssl, "Content-Length: %d\r\n", len);
		_SSL_printf(ssl, "\r\n");
		SSL_write(ssl, buf, len);

		goto next;
	} else if (strcmp(buf, "CONNECT /CSCOSSLC/tunnel HTTP/1.1")) {
		syslog(LOG_INFO, "Bad request: '%s'\n", buf);
		_SSL_printf(ssl, "HTTP/1.1 404 Nah, go away\r\n\r\n");
		exit(1);
	}
	while ( (i = _SSL_gets(ssl, buf, sizeof(buf))) > 0) {
		syslog(LOG_INFO, "incoming hdr: '%s'\n", buf);
		if (!strncmp(buf, "Cookie: webvpn=", 15)) {
			for (i = 0; i < nr_cookies; i++) {
				if (!strcmp(cookies[i], buf+15)) {
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
		_SSL_printf(ssl, "HTTP/1.1 503 Bad cookie\r\n");
		_SSL_printf(ssl, "X-Reason: I did not like your cookie\r\n\r\n");
		exit(1);
	}
	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd < 0) {
		int e = errno;
		syslog(LOG_INFO, "Can't open /dev/net/tun: %s\n",
		       strerror (e));
		_SSL_printf(ssl, "HTTP/1.1 503 no tun device\r\n");
		_SSL_printf(ssl, "X-Reason: Could not open /dev/net/tun: %s\r\n\r\n", strerror(e));
		exit(1);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),
		 "vpns%d", tun_nr);
	if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0) {
		int e = errno;
		syslog(LOG_INFO, "TUNSETIFF: %s\n",
		       strerror (e));
		_SSL_printf(ssl, "HTTP/1.1 503 TUNSETIFF\r\n");
		_SSL_printf(ssl, "X-Reason: TUNSETIFF failed: %s\r\n\r\n", strerror(errno));
		exit(1);
	}

	_SSL_printf(ssl, "HTTP/1.1 200 connected\r\n");
	_SSL_printf(ssl, "X-CSTP-MTU: 1500\r\n");
	_SSL_printf(ssl, "X-CSTP-DPD: 60\r\n");
	_SSL_printf(ssl, "X-CSTP-Address: 172.31.255.%d\r\n", 100 + tun_nr);
	_SSL_printf(ssl, "X-CSTP-Netmask: 255.255.255.255\r\n");
	_SSL_printf(ssl, "X-CSTP-DNS: 172.31.255.1\r\n");
	_SSL_printf(ssl, "X-CSTP-Address: 2001:770:15f::%x\r\n", 0x100 + tun_nr);
	_SSL_printf(ssl, "X-CSTP-Netmask: 2001:770:15f::%x/128\r\n", 0x100 + tun_nr);
	_SSL_printf(ssl, "X-CSTP-Split-Include: 172.31.255.0/255.255.255.0\r\n");
	_SSL_printf(ssl, "X-CSTP-Banner: Hello there\r\n");
	_SSL_printf(ssl, "\r\n");
	while(1) {
		fd_set rfds;
		int l, pktlen;

		FD_ZERO (&rfds);
		FD_SET(0, &rfds);
		FD_SET(tunfd, &rfds);

		if (select (tunfd + 1, &rfds, NULL, NULL, NULL) <= 0)
			break;
		
		if (FD_ISSET (0, &rfds)) {
			l = SSL_read (ssl, buf, sizeof(buf));
			if (l < 8) {
				syslog(LOG_INFO, "Can't read CSTP header\n");
				exit (1);
			}
			if (buf[0] != 'S' || buf[1] != 'T' ||
			    buf[2] != 'F' || buf[3] != 1 || buf[7]) {
				syslog(LOG_INFO, "Can't recognise CSTP header\n");
				exit (1);
			}
			pktlen = (buf[4] << 8) + buf[5];
			if (l != 8 + pktlen) {
				syslog(LOG_INFO, "Unexpected length\n");
				exit (1);
			}
			switch (buf[6]) {
			case AC_PKT_DPD_RESP:
			case AC_PKT_KEEPALIVE:
				break;

			case AC_PKT_DPD_OUT:
				SSL_write (ssl, "STF\x1\x0\x0\x4\x0", 8);
				break;

			case AC_PKT_DISCONN:
				syslog(LOG_INFO, "Received BYE packet\n");
				break;
				
			case AC_PKT_DATA:
				write (tunfd, buf + 8, pktlen);
				break;
			}
		}
		if (FD_ISSET(tunfd, &rfds)) {
			int l = read (tunfd, buf + 8, sizeof(buf) - 8);
			buf[0] = 'S';
			buf[1] = 'T';
			buf[2] = 'F';
			buf[3] = 1;
			buf[4] = l >> 8;
			buf[5] = l & 0xff;
			buf[6] = 0;
			buf[7] = 0;

			if (SSL_write(ssl, buf, l + 8) <= 0) {
				syslog(LOG_INFO, "Failed to write data packet\n");
				exit(1);
			}
		}
				

	}
}
