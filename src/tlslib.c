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

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <tlslib.h>
#include <ccan/hash/hash.h>
#include <vpn.h>
#include <main.h>
#include <worker.h>


ssize_t tls_send(gnutls_session_t session, const void *data,
			size_t data_size)
{
	int ret;
	int left = data_size;
	const uint8_t* p = data;

	while(left > 0) {
		ret = gnutls_record_send(session, p, data_size);
		if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
			return ret;
		}
	
		if (ret > 0) {
			left -= ret;
			p += ret;
		}
	}
	
	return data_size;
}

ssize_t tls_send_file(gnutls_session_t session, const char *file)
{
FILE* fp;
char buf[512];
ssize_t len, total = 0;
int ret;

	fp = fopen(file, "r");
	
	while (	(len = fread( buf, 1, sizeof(buf), fp)) > 0) {
		ret = tls_send(session, buf, len);
		GNUTLS_FATAL_ERR(ret);
		
		total += ret;
	}
	
	fclose(fp);
	
	return total;
}

ssize_t tls_recv(gnutls_session_t session, void *data, size_t data_size)
{
	int ret;

	do {
		ret = gnutls_record_recv(session, data, data_size);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	
	return ret;
}

int __attribute__ ((format(printf, 2, 3)))
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

void tls_close(gnutls_session_t session)
{
	gnutls_bye(session, GNUTLS_SHUT_WR);
	gnutls_deinit(session);
}

void tls_fatal_close(gnutls_session_t session,
			    gnutls_alert_description_t a)
{
	gnutls_alert_send(session, GNUTLS_AL_FATAL, a);
	gnutls_deinit(session);
}

static size_t rehash(const void *_e, void *unused)
{
const tls_cache_st *e = _e;

	return hash_stable_8(e->session_id, e->session_id_size, 0);
}

void tls_cache_init(hash_db_st** _db)
{
hash_db_st * db;

	db = malloc(sizeof(*db));
	if (db == NULL)
		exit(1);

	htable_init(&db->ht, rehash, NULL);
	db->entries = 0;

	*_db = db;
}

void tls_cache_deinit(hash_db_st* db)
{
tls_cache_st* cache;
struct htable_iter iter;

	cache = htable_first(&db->ht, &iter);
	while(cache != NULL) {
		if (cache->session_data_size > 0) {
	          	memset(cache->session_data, 0, cache->session_data_size);
	          	cache->session_data_size = 0;
	          	cache->session_id_size = 0;
		}
          	free(cache);
          	
          	cache = htable_next(&db->ht, &iter);
        }
        htable_clear(&db->ht);
	db->entries = 0;

        return;
}

static void tls_log_func(int level, const char *str)
{
	syslog(LOG_DEBUG, "TLS[<%d>]: %s", level, str);
}

static void tls_audit_log_func(gnutls_session_t session, const char *str)
{
worker_st * ws;

	if (session == NULL)
		syslog(LOG_AUTH, "Warning: %s", str);
	else {
		ws = gnutls_session_get_ptr(session);
		
		oclog(ws, LOG_ERR, "Warning: %s", str);
	}
}

static int verify_certificate_cb(gnutls_session_t session)
{
	unsigned int status;
	int ret;
	worker_st * ws;

	ws = gnutls_session_get_ptr(session);
	if (ws == NULL) {
		syslog(LOG_ERR, "%s:%d: Could not obtain worker state.", __func__, __LINE__);
		return -1;
	}
	
	if (session == ws->dtls_session) /* no certificate is verified in DTLS */
		return 0;

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	ret = gnutls_certificate_verify_peers2(session, &status);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "Error verifying client certificate");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (status != 0) {
#if GNUTLS_VERSION_NUMBER > 0x030106
		gnutls_datum_t out;
		int type = gnutls_certificate_type_get(session);

		ret =
		    gnutls_certificate_verification_status_print(status, type,
							 &out, 0);
		if (ret < 0)
			return GNUTLS_E_CERTIFICATE_ERROR;

		oclog(ws, LOG_INFO, "Client certificate verification failed: %s", out.data);

		gnutls_free(out.data);
#else
		oclog(ws, LOG_INFO, "Client certificate verification failed.");
#endif

		return GNUTLS_E_CERTIFICATE_ERROR;
	} else {
		oclog(ws, LOG_INFO, "Client certificate verification succeeded");
	}

	/* notify gnutls to continue handshake normally */
	return 0;
}

void tls_global_init(main_server_st* s)
{
int ret;
const char* perr;

	gnutls_global_set_audit_log_function(tls_audit_log_func);
	if (s->config->tls_debug) {
		gnutls_global_set_log_function(tls_log_func);
		gnutls_global_set_log_level(9);
	}

	ret = gnutls_global_init();
	GNUTLS_FATAL_ERR(ret);
	
	ret = gnutls_certificate_allocate_credentials(&s->creds.xcred);
	GNUTLS_FATAL_ERR(ret);
	
	if (s->config->key != NULL && strncmp(s->config->key, "pkcs11:", 7) != 0) {
		ret =
		    gnutls_certificate_set_x509_key_file(s->creds.xcred, s->config->cert,
						 s->config->key,
						 GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			fprintf(stderr, "Error setting the certificate (%s) or key (%s) files: %s\n",
				s->config->cert, s->config->key, gnutls_strerror(ret));
			exit(1);
		}
	} else {
#ifdef HAVE_PKCS11
		fprintf(stderr, "Cannot load key, GnuTLS is compiled without pkcs11 support\n");
		exit(1);
#endif	
	}

	if (s->config->cert_req != GNUTLS_CERT_IGNORE) {
		if (s->config->ca != NULL) {
			ret =
			    gnutls_certificate_set_x509_trust_file(s->creds.xcred,
								   s->config->ca,
								   GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				fprintf(stderr, "Error setting the CA (%s) file.\n",
					s->config->ca);
				exit(1);
			}

			fprintf(stderr, "Processed %d CA certificate(s).\n", ret);
		}

		if (s->config->crl != NULL) {
			ret =
			    gnutls_certificate_set_x509_crl_file(s->creds.xcred,
								 s->config->crl,
								 GNUTLS_X509_FMT_PEM);
			GNUTLS_FATAL_ERR(ret);
		}

		gnutls_certificate_set_verify_function(s->creds.xcred,
						       verify_certificate_cb);
	}

	ret = gnutls_priority_init(&s->creds.cprio, s->config->priorities, &perr);
	if (ret == GNUTLS_E_PARSING_ERROR)
		fprintf(stderr, "Error in TLS priority string: %s\n", perr);
	GNUTLS_FATAL_ERR(ret);
	
	
	return;
}

int tls_global_init_client(worker_st* ws)
{
int ret;

#ifdef HAVE_PKCS11
	/* when we have PKCS #11 keys we cannot open them and then fork(), we need
	 * to open them at the process they are going to be used. */
	if (ws->config->key != NULL && strncmp(ws->config->key, "pkcs11:", 7) == 0) {
		ret = gnutls_pkcs11_reinit();
		if (ret < 0) {
			oclog(ws, LOG_ERR, "Could not reinitialize PKCS #11 subsystem: %s\n",
				gnutls_strerror(ret));
			return -1;

		}

		ret =
		    gnutls_certificate_set_x509_key_file(ws->creds->xcred, ws->config->cert,
						 ws->config->key,
						 GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			oclog(ws, LOG_ERR, "Error setting the certificate (%s) or key (%s) files: %s\n",
				ws->config->cert, ws->config->key, gnutls_strerror(ret));
			return -1;
		}
	}
#endif

	return 0;
}

void tls_cork(gnutls_session_t session)
{
#if GNUTLS_VERSION_NUMBER > 0x030107
	gnutls_record_cork(session);
#endif
}

int tls_uncork(gnutls_session_t session)
{
#if GNUTLS_VERSION_NUMBER > 0x030107
int ret;

	do {
		ret = gnutls_record_cork(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	
	return ret;
#else
	return 0;
#endif
}
