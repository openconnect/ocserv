#ifndef TLSLIB_H
#define TLSLIB_H

#include <gnutls/gnutls.h>
#include <vpn.h>
#include <ccan/htable/htable.h>

#define tls_puts(s, str) tls_send(s, str, sizeof(str)-1)
	
int __attribute__ ((format(printf, 2, 3)))
    tls_printf(gnutls_session_t session, const char *fmt, ...);

ssize_t tls_recv(gnutls_session_t session, void *data, size_t data_size);
ssize_t tls_send(gnutls_session_t session, const void *data,
			size_t data_size);

void tls_cork(gnutls_session_t session);
int tls_uncork(gnutls_session_t session);

void tls_global_init(struct main_server_st* s);
int tls_global_init_client(struct worker_st* ws);

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

struct tls_st {
	gnutls_certificate_credentials_t xcred;
	gnutls_priority_t cprio;
};

typedef struct
{
  /* does not allow resumption from different address
   * than the original */
  struct sockaddr_storage remote_addr;
  socklen_t remote_addr_len;

  char session_id[GNUTLS_MAX_SESSION_ID];
  unsigned int session_id_size;

  char session_data[MAX_SESSION_DATA_SIZE];
  unsigned int session_data_size;
} tls_cache_st;

#define TLS_SESSION_EXPIRATION_TIME 600
#define DEFAULT_MAX_CACHED_TLS_SESSIONS(db) 256

void tls_cache_init(hash_db_st** db);
void tls_cache_deinit(hash_db_st* db);

#endif
