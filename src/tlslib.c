/*
 * Copyright (C) 2013, 2014 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>
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
#include <common.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <c-ctype.h>

void cstp_cork(worker_st *ws)
{
	if (ws->session) {
		gnutls_record_cork(ws->session);
	} else {
		int state = 1;
#ifdef __linux__
		setsockopt(ws->conn_fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
#elif defined(TCP_NOPUSH)
		setsockopt(ws->conn_fd, IPPROTO_TCP, TCP_NOPUSH, &state, sizeof(state));
#endif
	}
}

int cstp_uncork(worker_st *ws)
{
	if (ws->session) {
		return gnutls_record_uncork(ws->session, GNUTLS_RECORD_WAIT);
	} else {
		int state = 0;
#if defined(__linux__)
		setsockopt(ws->conn_fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
#elif defined(TCP_NOPUSH)
		setsockopt(ws->conn_fd, IPPROTO_TCP, TCP_NOPUSH, &state, sizeof(state));
#endif
		return 0;
	}
}


ssize_t cstp_send(worker_st *ws, const void *data,
			size_t data_size)
{
	int ret;
	int left = data_size;
	const uint8_t* p = data;

	if (ws->session != NULL) {
		while(left > 0) {
			ret = gnutls_record_send(ws->session, p, data_size);
			if (ret < 0) {
				if (ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED) {
					return ret;
				} else {
					/* do not cause mayhem */
					ms_sleep(20);
				}
			}

			if (ret > 0) {
				left -= ret;
				p += ret;
			}
		}
		return data_size;
	} else {
		return force_write(ws->conn_fd, data, data_size);
	}
}

ssize_t cstp_send_file(worker_st *ws, const char *file)
{
FILE* fp;
char buf[512];
ssize_t len, total = 0;
int ret;

	fp = fopen(file, "r");
	if (fp == NULL)
		return GNUTLS_E_FILE_ERROR;

	while (	(len = fread( buf, 1, sizeof(buf), fp)) > 0) {
		ret = cstp_send(ws, buf, len);
		FATAL_ERR(ws, ret);

		total += ret;
	}

	fclose(fp);

	return total;
}

/* Restores gnutls_record_recv() on EAGAIN */
ssize_t cstp_recv(worker_st *ws, void *data, size_t data_size)
{
	int ret;
	int counter = 5;

	if (ws->session != NULL) {
		do {
			ret = gnutls_record_recv(ws->session, data, data_size);
			if (ret == GNUTLS_E_AGAIN) {
				counter--;
				ms_sleep(20);
			}
		} while (ret == GNUTLS_E_AGAIN && counter > 0);
	} else {
		do {
			ret = recv(ws->conn_fd, data, data_size, 0);
			if (ret == -1 && errno == EAGAIN) {
				counter--;
				ms_sleep(20);
			}
		} while(ret == -1 && errno == EAGAIN && counter > 0);
	}

	return ret;
}

ssize_t cstp_recv_nb(worker_st *ws, void *data, size_t data_size)
{
	int ret;

	if (ws->session != NULL) {
		ret = gnutls_record_recv(ws->session, data, data_size);
	} else {
		ret = recv(ws->conn_fd, data, data_size, 0);
	}

	return ret;
}

/* Typically used in a resumed session. It will return
 * true if a certificate has been used.
 */
unsigned tls_has_session_cert(struct worker_st * ws)
{
	unsigned int list_size = 0;
	const gnutls_datum_t * certs;

	if (ws->session == NULL)
		return 0;

	if (ws->cert_auth_ok)
		return 1;

	if (ws->config->cisco_client_compat == 0) {
		return 0;
	}

	certs = gnutls_certificate_get_peers(ws->session, &list_size);
	if (certs != NULL)
		return 1;

	return 0;
}

int __attribute__ ((format(printf, 2, 3)))
    cstp_printf(worker_st *ws, const char *fmt, ...)
{
	char buf[1024];
	va_list args;
	size_t s;

	buf[1023] = 0;

	va_start(args, fmt);
	s = vsnprintf(buf, 1023, fmt, args);
	va_end(args);
	return cstp_send(ws, buf, s);

}

void cstp_close(worker_st *ws)
{
	if (ws->session) {
		gnutls_bye(ws->session, GNUTLS_SHUT_WR);
		gnutls_deinit(ws->session);
	} else {
		close(ws->conn_fd);
	}
}

void cstp_fatal_close(worker_st *ws,
			    gnutls_alert_description_t a)
{
	if (ws->session) {
		gnutls_alert_send(ws->session, GNUTLS_AL_FATAL, a);
		gnutls_deinit(ws->session);
	} else {
		close(ws->conn_fd);
	}
}

ssize_t dtls_send(worker_st *ws, const void *data,
			size_t data_size)
{
	int ret;
	int left = data_size;
	const uint8_t* p = data;

	while(left > 0) {
		ret = gnutls_record_send(ws->dtls_session, p, data_size);
		if (ret < 0) {
			if (ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED) {
				return ret;
			} else {
				/* do not cause mayhem */
				ms_sleep(20);
			}
		}

		if (ret > 0) {
			left -= ret;
			p += ret;
		}
	}

	return data_size;
}

void dtls_close(worker_st *ws)
{
	gnutls_bye(ws->dtls_session, GNUTLS_SHUT_WR);
	gnutls_deinit(ws->dtls_session);
}

static size_t rehash(const void *_e, void *unused)
{
const tls_cache_st *e = _e;

	return hash_any(e->session_id, e->session_id_size, 0);
}

void tls_cache_init(void *pool, tls_sess_db_st* db)
{
	db->ht = talloc(pool, struct htable);
	if (db->ht == NULL)
		exit(1);

	htable_init(db->ht, rehash, NULL);
	db->entries = 0;
}

void tls_cache_deinit(tls_sess_db_st* db)
{
tls_cache_st* cache;
struct htable_iter iter;

	cache = htable_first(db->ht, &iter);
	while(cache != NULL) {
		if (cache->session_data_size > 0) {
	          	safe_memset(cache->session_data, 0, cache->session_data_size);
	          	cache->session_data_size = 0;
	          	cache->session_id_size = 0;
		}
          	talloc_free(cache);

          	cache = htable_next(db->ht, &iter);
        }
        htable_clear(db->ht);
	db->entries = 0;
	talloc_free(db->ht);

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
		syslog(LOG_AUTH, "warning: %s", str);
	else {
		ws = gnutls_session_get_ptr(session);

		oclog(ws, LOG_ERR, "warning: %s", str);
	}
}

static int verify_certificate_cb(gnutls_session_t session)
{
	unsigned int status;
	int ret;
	worker_st * ws;

	ws = gnutls_session_get_ptr(session);
	if (ws == NULL) {
		syslog(LOG_ERR, "%s:%d: could not obtain worker state", __func__, __LINE__);
		return -1;
	}

	if (session == ws->dtls_session) {
		oclog(ws, LOG_ERR, "unexpected issue; client shouldn't have offered a certificate in DTLS");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	ws->cert_auth_ok = 0;

	/* now verify whether the username in the certificate matches the username of the session */
	if (ws->cert_username[0] != 0) {
		char prev_username[MAX_USERNAME_SIZE];
		const gnutls_datum_t *cert;
		unsigned cert_size;

		cert = gnutls_certificate_get_peers(session, &cert_size);
		if (cert != NULL) { /* it's ok for the user not to send any certificate on renegotiation */
			memcpy(prev_username, ws->cert_username, MAX_USERNAME_SIZE);
			ret = get_cert_names(ws, &cert[0]);
			if (ret < 0) {
				oclog(ws, LOG_ERR, "cannot parse certificate");
				return GNUTLS_E_CERTIFICATE_ERROR;
			}

			if (strcmp(prev_username, ws->cert_username) != 0) {
				oclog(ws, LOG_ERR, "user switched during renegotiation!");
				return GNUTLS_E_CERTIFICATE_ERROR;
			}
		}
	}

	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	ret = gnutls_certificate_verify_peers2(session, &status);
	if (ret < 0) {
		oclog(ws, LOG_ERR, "error verifying client certificate: %s", gnutls_strerror(ret));
		goto fail;
	}

	if (status != 0) {
		gnutls_datum_t out;
		int type = gnutls_certificate_type_get(session);

		ret =
		    gnutls_certificate_verification_status_print(status, type,
							 &out, 0);
		if (ret < 0)
			goto fail;

		oclog(ws, LOG_INFO, "client certificate verification failed: %s", out.data);

		gnutls_free(out.data);

		goto fail;
	} else {
		ws->cert_auth_ok = 1;
		oclog(ws, LOG_INFO, "client certificate verification succeeded");
	}

	/* notify gnutls to continue handshake normally */
	return 0;
fail:
	/* In cisco client compatibility we don't hangup immediately, we
	 * simply use the flag (ws->cert_auth_ok). */
	if (ws->config->cisco_client_compat == 0)
		return GNUTLS_E_CERTIFICATE_ERROR;
	else
		return 0;

}

void tls_global_init(tls_st *creds)
{
int ret;

	gnutls_global_set_audit_log_function(tls_audit_log_func);

	ret = gnutls_global_init();
	GNUTLS_FATAL_ERR(ret);

	return;
}

void tls_global_deinit(tls_st *creds)
{
	if (creds->xcred != NULL)
		gnutls_certificate_free_credentials(creds->xcred);
	if (creds->cprio != NULL)
		gnutls_priority_deinit(creds->cprio);

	gnutls_global_deinit();

	return;
}

/* Checks, if there is a single certificate specified, whether it
 * is compatible with all ciphersuites */
static void certificate_check(main_server_st *s)
{
gnutls_datum_t data = {NULL, 0};
gnutls_x509_crt_t crt = NULL;
int ret;
unsigned usage;

	if (s->config->cert_size > 1)
		return;

	if (gnutls_url_is_supported(s->config->cert[0]) == 0) {
		/* no URL */
		ret = gnutls_load_file(s->config->cert[0], &data);
		if (ret < 0)
			return;

		ret = gnutls_x509_crt_init(&crt);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_x509_crt_get_pk_algorithm(crt, NULL);
		if (ret != GNUTLS_PK_RSA)
			goto cleanup;

		ret = gnutls_x509_crt_get_key_usage(crt, &usage, NULL);
		if (ret >= 0) {
			if (!(usage & GNUTLS_KEY_KEY_ENCIPHERMENT)) {
				mslog(s, NULL, LOG_WARNING, "server certificate key usage prevents key encipherment; unable to support the RSA ciphersuites; "
					"if that is not intentional, regenerate the server certificate with the key usage flag 'key encipherment' set.");
				if (s->config->dh_params_file != NULL)
					mslog(s, NULL, LOG_WARNING, "no DH-params file specified; server will be limited to ECDHE ciphersuites\n");
			}
		}
	}

cleanup:
	if (crt != NULL)
        	gnutls_x509_crt_deinit(crt);
	gnutls_free(data.data);
	return;
}

static void set_dh_params(main_server_st* s, tls_st *creds)
{
gnutls_datum_t data;
int ret;

	if (s->config->dh_params_file != NULL) {
		ret = gnutls_dh_params_init (&creds->dh_params);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_load_file(s->config->dh_params_file, &data);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_dh_params_import_pkcs3(creds->dh_params, &data, GNUTLS_X509_FMT_PEM);
		GNUTLS_FATAL_ERR(ret);

		gnutls_free(data.data);

		gnutls_certificate_set_dh_params(creds->xcred, creds->dh_params);
	}
}

struct key_cb_data {
	unsigned idx; /* the index of the key */
	struct sockaddr_un sa;
	unsigned sa_len;
};

static
int key_cb_common_func (gnutls_privkey_t key, void* userdata, const gnutls_datum_t * raw_data,
	gnutls_datum_t * output, unsigned type)
{
	struct key_cb_data* cdata = userdata;
	int sd = -1, ret, e;
	SecOpMsg msg = SEC_OP_MSG__INIT;
	SecOpMsg *reply = NULL;
	PROTOBUF_ALLOCATOR(pa, userdata);

	output->data = NULL;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		syslog(LOG_ERR, "error opening socket: %s", strerror(e));
		return GNUTLS_E_INTERNAL_ERROR;
	}

	ret = connect(sd, (struct sockaddr *)&cdata->sa, cdata->sa_len);
	if (ret == -1) {
		e = errno;
		syslog(LOG_ERR, "error connecting to sec-mod socket '%s': %s", 
			cdata->sa.sun_path, strerror(e));
		goto error;
	}

	msg.has_key_idx = 1;
	msg.key_idx = cdata->idx;
	msg.data.data = raw_data->data;
	msg.data.len = raw_data->size;

	ret = send_msg(userdata, sd, type, &msg,
			(pack_size_func)sec_op_msg__get_packed_size,
			(pack_func)sec_op_msg__pack);
	if (ret < 0) {
		goto error;
	}

	ret = recv_msg(userdata, sd, type, (void*)&reply, (unpack_func)sec_op_msg__unpack);
	if (ret < 0) {
		e = errno;
		syslog(LOG_ERR, "error receiving sec-mod reply: %s", 
				strerror(e));
		goto error;
	}
	close(sd);
	sd = -1;

	output->size = reply->data.len;
	output->data = gnutls_malloc(reply->data.len);
	if (output->data == NULL) {
		syslog(LOG_ERR, "error allocating memory");
		goto error;
	}

	memcpy(output->data, reply->data.data, reply->data.len);

	if (reply != NULL)
		sec_op_msg__free_unpacked(reply, &pa);
	return 0;

error:
	if (sd != -1)
		close(sd);
	gnutls_free(output->data);
	if (reply != NULL)
		sec_op_msg__free_unpacked(reply, &pa);
	return GNUTLS_E_INTERNAL_ERROR;

}

static
int key_cb_sign_func (gnutls_privkey_t key, void* userdata, const gnutls_datum_t * raw_data,
	gnutls_datum_t * signature)
{
	return key_cb_common_func(key, userdata, raw_data, signature, SM_CMD_SIGN);
}

static int key_cb_decrypt_func(gnutls_privkey_t key, void* userdata, const gnutls_datum_t * ciphertext,
	gnutls_datum_t * plaintext)
{
	return key_cb_common_func(key, userdata, ciphertext, plaintext, SM_CMD_DECRYPT);
}

static void key_cb_deinit_func(gnutls_privkey_t key, void* userdata)
{
	talloc_free(userdata);
}

static
int load_cert_files(main_server_st *s, tls_st *creds)
{
int ret;
gnutls_pcert_st *pcert_list;
unsigned pcert_list_size, i;
gnutls_privkey_t key;
gnutls_datum_t data;
struct key_cb_data * cdata;

	for (i=0;i<s->config->key_size;i++) {
		/* load the certificate */
		if (gnutls_url_is_supported(s->config->cert[i]) != 0) {
			mslog(s, NULL, LOG_ERR, "Loading a certificate from '%s' is unsupported", s->config->cert[i]);
			return -1;
		} else {
			ret = gnutls_load_file(s->config->cert[i], &data);
			if (ret < 0) {
				mslog(s, NULL, LOG_ERR, "error loading file '%s'", s->config->cert[i]);
				return -1;
			}

			pcert_list_size = 8;
			pcert_list = gnutls_malloc(sizeof(pcert_list[0])*pcert_list_size);
			if (pcert_list == NULL) {
				mslog(s, NULL, LOG_ERR, "error allocating memory");
				return -1;
			}

			ret = gnutls_pcert_list_import_x509_raw(pcert_list, &pcert_list_size,
				&data, GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED|GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
			GNUTLS_FATAL_ERR(ret);

			gnutls_free(data.data);
		}

		ret = gnutls_privkey_init(&key);
		GNUTLS_FATAL_ERR(ret);

		/* use use the main pool rather than main, to allow usage of the credentials
		 * after freeing s.
		 */
		cdata = talloc(s->main_pool, struct key_cb_data);
		if (cdata == NULL) {
			mslog(s, NULL, LOG_ERR, "error allocating memory");
			return -1;
		}

		cdata->idx = i;

		memset(&cdata->sa, 0, sizeof(cdata->sa));
		cdata->sa.sun_family = AF_UNIX;
		strlcpy(cdata->sa.sun_path, s->socket_file, sizeof(cdata->sa.sun_path));
		cdata->sa_len = SUN_LEN(&cdata->sa);

		/* load the private key */
		ret = gnutls_privkey_import_ext2(key, gnutls_pubkey_get_pk_algorithm(pcert_list[0].pubkey, NULL),
			cdata, key_cb_sign_func, key_cb_decrypt_func,
			key_cb_deinit_func, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_certificate_set_key(creds->xcred, NULL, 0, pcert_list,
				pcert_list_size, key);
		GNUTLS_FATAL_ERR(ret);
	}

	return 0;
}

/* reload key files etc. */
void tls_load_certs(main_server_st *s, tls_st *creds)
{
int ret;
const char* perr;

	if (s->config->debug >= DEBUG_TLS) {
		gnutls_global_set_log_function(tls_log_func);
		gnutls_global_set_log_level(9);
	}

	if (creds->xcred != NULL)
		gnutls_certificate_free_credentials(creds->xcred);

	ret = gnutls_certificate_allocate_credentials(&creds->xcred);
	GNUTLS_FATAL_ERR(ret);

	set_dh_params(s, creds);

	if (s->config->key_size == 0 || s->config->cert_size == 0) {
		mslog(s, NULL, LOG_ERR, "no certificate or key files were specified"); 
		exit(1);
	}

	certificate_check(s);

	ret = load_cert_files(s, creds);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "error loading the certificate or key file");
		exit(1);
	}

	if (s->config->cert_req != GNUTLS_CERT_IGNORE) {
		if (s->config->ca != NULL) {
			ret =
			    gnutls_certificate_set_x509_trust_file(creds->xcred,
								   s->config->ca,
								   GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				mslog(s, NULL, LOG_ERR, "error setting the CA (%s) file",
					s->config->ca);
				exit(1);
			}

			mslog(s, NULL, LOG_INFO, "processed %d CA certificate(s)", ret);
		}

		tls_reload_crl(s, creds);

		gnutls_certificate_set_verify_function(creds->xcred,
						       verify_certificate_cb);
	}

	ret = gnutls_priority_init(&creds->cprio, s->config->priorities, &perr);
	if (ret == GNUTLS_E_PARSING_ERROR)
		mslog(s, NULL, LOG_ERR, "error in TLS priority string: %s", perr);
	GNUTLS_FATAL_ERR(ret);

	if (s->config->ocsp_response != NULL) {
		ret = gnutls_certificate_set_ocsp_status_request_file(creds->xcred,
			s->config->ocsp_response, 0);
		GNUTLS_FATAL_ERR(ret);
	}

	return;
}

void tls_reload_crl(main_server_st* s, tls_st *creds)
{
int ret;

	if (s->config->cert_req != GNUTLS_CERT_IGNORE && s->config->crl != NULL) {
		ret =
		    gnutls_certificate_set_x509_crl_file(creds->xcred,
							 s->config->crl,
							 GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			/* ignore the CRL file when empty */
			if (ret == GNUTLS_E_BASE64_DECODING_ERROR) {
				mslog(s, NULL, LOG_ERR, "empty or unreadable CRL file (%s); check documentation to generate an empty CRL",
					s->config->crl);
			} else {
				mslog(s, NULL, LOG_ERR, "error reading the CRL (%s) file: %s",
					s->config->crl, gnutls_strerror(ret));
			}
			exit(1);
		}
	}
}

void tls_cork(gnutls_session_t session)
{
	gnutls_record_cork(session);
}

int tls_uncork(gnutls_session_t session)
{
	return gnutls_record_uncork(session, GNUTLS_RECORD_WAIT);
}

void *calc_sha1_hash(void *pool, char* file, unsigned cert)
{
int ret;
gnutls_datum_t data;
uint8_t digest[20];
char * retval;
gnutls_x509_crt_t crt;
unsigned i;

	ret = gnutls_load_file(file, &data);
	if (ret < 0) {
		return NULL;
	}

	if (cert != 0) {
		ret = gnutls_x509_crt_init(&crt);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM);
		if (ret == GNUTLS_E_BASE64_DECODING_ERROR)
	  		ret = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_DER);
		GNUTLS_FATAL_ERR(ret);

		gnutls_free(data.data);

		ret = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &data);
		GNUTLS_FATAL_ERR(ret);
		gnutls_x509_crt_deinit(crt);
	}

	ret = gnutls_hash_fast(GNUTLS_DIG_SHA1, data.data, data.size, digest);
	gnutls_free(data.data);

	if (ret < 0) {
		fprintf(stderr, "error calculating hash of '%s': %s", file, gnutls_strerror(ret));
		exit(1);
	}

	size_t ret_size = sizeof(digest)*2+1;
	retval = talloc_size(pool, ret_size);
	if (retval == NULL) {
		fprintf(stderr, "memory error");
		exit(1);
	}

	data.data = digest;
	data.size = sizeof(digest);
	ret = gnutls_hex_encode(&data, retval, &ret_size);
	if (ret < 0) {
		fprintf(stderr, "error in hex encode: %s", gnutls_strerror(ret));
		exit(1);
	}
	if (retval[ret_size-1] == 0) ret_size--; /* remove the null terminator */

	/* convert to all caps */
	for (i=0;i<ret_size;i++)
	        retval[i] = c_toupper(retval[i]);

	return retval;
}

size_t tls_get_overhead(gnutls_protocol_t version, gnutls_cipher_algorithm_t cipher, gnutls_mac_algorithm_t mac)
{
#if GNUTLS_VERSION_NUMBER >= 0x030207
	return gnutls_est_record_overhead_size(version, cipher, mac, GNUTLS_COMP_NULL, 0);
#else
unsigned overhead = 0, t;
unsigned block_size;
	block_size = gnutls_cipher_get_block_size(cipher);

	switch(version) {
		case GNUTLS_DTLS0_9:
		case GNUTLS_DTLS1_0:
#if GNUTLS_VERSION_NUMBER >= 0x030200
		case GNUTLS_DTLS1_2:
#endif
			overhead += 13;
			break;
		default:
			overhead += 5;
			break;
	}

	switch(cipher) {
		case GNUTLS_CIPHER_3DES_CBC:
		case GNUTLS_CIPHER_AES_128_CBC:
		case GNUTLS_CIPHER_AES_256_CBC:
		case GNUTLS_CIPHER_CAMELLIA_128_CBC:
		case GNUTLS_CIPHER_CAMELLIA_256_CBC:
		case GNUTLS_CIPHER_AES_192_CBC:
		case GNUTLS_CIPHER_CAMELLIA_192_CBC:
			overhead += block_size; /* max pad */
			overhead += block_size; /* IV */
			break;
		case GNUTLS_CIPHER_AES_128_GCM:
		case GNUTLS_CIPHER_AES_256_GCM:
			overhead += 8; /* explicit nonce */
			overhead += block_size; /* tag size */
			break;
		default:
			break;
	}

	t = gnutls_hmac_get_len(mac);
	if (t > 0)
		overhead += t;

	return overhead;
#endif
}
