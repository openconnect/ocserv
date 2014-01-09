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
#ifndef TLSLIB_H
#define TLSLIB_H

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>
#include <vpn.h>
#include <ccan/htable/htable.h>

#define tls_puts(s, str) tls_send(s, str, sizeof(str)-1)
	
int __attribute__ ((format(printf, 2, 3)))
    tls_printf(gnutls_session_t session, const char *fmt, ...);

ssize_t tls_recv(gnutls_session_t session, void *data, size_t data_size);
ssize_t tls_send(gnutls_session_t session, const void *data,
			size_t data_size);
ssize_t tls_send_nowait(gnutls_session_t session, const void *data,
			size_t data_size);

void tls_cork(gnutls_session_t session);
int tls_uncork(gnutls_session_t session);

void tls_global_init(struct main_server_st* s);
void tls_global_deinit(struct main_server_st* s);
void tls_global_init_certs(struct main_server_st* s);

ssize_t tls_send_file(gnutls_session_t session, const char *file);
size_t tls_get_overhead(gnutls_protocol_t, gnutls_cipher_algorithm_t, gnutls_mac_algorithm_t);

#define GNUTLS_FATAL_ERR(x) \
        if (x < 0 && gnutls_error_is_fatal (x) != 0) { \
                if (syslog_open) \
       			syslog(LOG_ERR, "GnuTLS error (at %s:%d): %s", __FILE__, __LINE__, gnutls_strerror(x)); \
                else \
                        fprintf(stderr, "GnuTLS error (at %s:%d): %s\n", __FILE__, __LINE__, gnutls_strerror(x)); \
                exit(1); \
        }

#define GNUTLS_S_FATAL_ERR(session, x) \
        if (x < 0 && gnutls_error_is_fatal (x) != 0) { \
                if (syslog_open) { \
	        	if (ret == GNUTLS_E_FATAL_ALERT_RECEIVED) { \
	        		syslog(LOG_ERR, "GnuTLS error (at %s:%d): %s: %s", __FILE__, __LINE__, gnutls_strerror(x), gnutls_alert_get_name(gnutls_alert_get(session))); \
        		} else { \
        			syslog(LOG_ERR, "GnuTLS error (at %s:%d): %s", __FILE__, __LINE__, gnutls_strerror(x)); \
			} \
                } else \
                        fprintf(stderr, "GnuTLS error (at %s:%d): %s\n", __FILE__, __LINE__, gnutls_strerror(x)); \
                exit(1); \
        }

void tls_close(gnutls_session_t session);

void tls_fatal_close(gnutls_session_t session,
			    gnutls_alert_description_t a);

struct tls_st {
	gnutls_certificate_credentials_t xcred;
	gnutls_priority_t cprio;
	gnutls_dh_params_t dh_params;
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
#define DEFAULT_MAX_CACHED_TLS_SESSIONS 64

void tls_cache_init(hash_db_st** db);
void tls_cache_deinit(hash_db_st* db);
void *calc_sha1_hash(char* file, unsigned cert);

#endif
