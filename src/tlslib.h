#ifndef TLS_H
#define TLS_H

#include <gnutls/gnutls.h>

#define tls_print(s, str) tls_send(s, str, sizeof(str)-1)
	
int __attribute__ ((format(printf, 2, 3)))
    tls_printf(gnutls_session_t session, const char *fmt, ...);

ssize_t tls_recv(gnutls_session_t session, void *data, size_t data_size);
ssize_t tls_send(gnutls_session_t session, const void *data,
			size_t data_size);

ssize_t tls_send_file(gnutls_session_t session, const char *file);

#define GNUTLS_FATAL_ERR(x) \
        if (x < 0 && gnutls_error_is_fatal (x) != 0) { \
                if (syslog_open) \
        		syslog(LOG_ERR, "GnuTLS error (at %s:%d): %s", __FILE__, __LINE__, gnutls_strerror(x)); \
                else \
                        fprintf(stderr, "GnuTLS error (at %s:%d): %s\n", __FILE__, __LINE__, gnutls_strerror(x)); \
                exit(1); \
        }

void tls_close(gnutls_session_t session);

void tls_fatal_close(gnutls_session_t session,
			    gnutls_alert_description_t a);

#endif
