/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2016 Red Hat, Inc.
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
#ifndef _GNU_SOURCE
# define _GNU_SOURCE /* for vasprintf() */
#endif
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

static void tls_reload_ocsp(main_server_st* s, struct vhost_cfg_st *vhost);

void cstp_cork(worker_st *ws)
{
	if (ws->session) {
		gnutls_record_cork(ws->session);
	} else {
		int state = 1, ret = 0;
#if defined(__linux__)
		ret = setsockopt(ws->conn_fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
#elif defined(TCP_NOPUSH)
		ret = setsockopt(ws->conn_fd, IPPROTO_TCP, TCP_NOPUSH, &state, sizeof(state));
#endif
		if (ret == -1) {
			oclog(ws, LOG_ERR, "setsockopt(IPPROTO_TCP(TCP_CORK) failed");
		}
	}
}

int cstp_uncork(worker_st *ws)
{
	if (ws->session) {
		return gnutls_record_uncork(ws->session, GNUTLS_RECORD_WAIT);
	} else {
		int state = 0, ret = 0;
#if defined(__linux__)
		ret = setsockopt(ws->conn_fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
#elif defined(TCP_NOPUSH)
		ret = setsockopt(ws->conn_fd, IPPROTO_TCP, TCP_NOPUSH, &state, sizeof(state));
#endif
		if (ret == -1) {
			oclog(ws, LOG_ERR, "setsockopt(IPPROTO_TCP(TCP_UNCORK) failed");
		}
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
	int fd;
	char buf[1024];
	int counter = 100; /* allow 10 seconds for a full packet */
	ssize_t len, total = 0;
	int ret;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return GNUTLS_E_FILE_ERROR;

	while (	(len = read( fd, buf, sizeof(buf))) > 0 ||
		(len == -1 && counter > 0 && (errno == EINTR || errno == EAGAIN))) {

		if (len == -1) {
			counter--;
			ms_sleep(100);
			continue;
		}

		ret = cstp_send(ws, buf, len);
		CSTP_FATAL_ERR(ws, ret);

		total += ret;
	}

	close(fd);

	return total;
}

static
int recv_remaining(int fd, uint8_t *p, int left)
{
	int counter = 100; /* allow 10 seconds for a full packet */
	unsigned total = 0;
	int ret;

	while(left > 0) {
		ret = recv(fd, p, left, 0);
		if (ret == -1 && counter > 0 && (errno == EINTR || errno == EAGAIN)) {
			counter--;
			ms_sleep(100);
			continue;
		}
		if (ret == 0)
			ret = GNUTLS_E_PREMATURE_TERMINATION;
		if (ret < 0)
			break;

		left -= ret;
		p += ret;
		total += ret;
	}

	return total;
}

/* Receives CSTP packet, after the channel is established.
 * It makes sure that CSTP packet boundaries are respected in
 * case we do not read over TLS - e.g., when TLS is done by
 * a proxy. */
static ssize_t _cstp_recv_packet(worker_st *ws, void *data, size_t data_size)
{
	int ret;

	/* socket is in non-blocking mode already */

	if (ws->session != NULL) {
		return gnutls_record_recv(ws->session, data, data_size);
	} else {
		/* It can happen in UNIX sockets case that we receive an
		 * incomplete CSTP packet. In that case we attempt to read
		 * a full CSTP packet.
		 */
		unsigned pktlen;
		uint8_t *p = data;

		/* read the header */
		ret = recv_remaining(ws->conn_fd, p, 8);
		if (ret <= 0)
			return ret;

		/* get the actual length from headers */
		pktlen = (p[4] << 8) + p[5];
		if (pktlen+8 > data_size) {
			oclog(ws, LOG_ERR, "error in CSTP packet length");
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

		if (pktlen > 0) {
			ret = recv_remaining(ws->conn_fd, p+8, pktlen);
			if (ret <= 0)
				return ret;
		}

		return 8+pktlen;
	}
}

ssize_t cstp_recv_packet(worker_st *ws, gnutls_datum_t *data, void **p)
{
	int ret;
#ifdef ZERO_COPY
	gnutls_packet_t packet = NULL;

	if (ws->session != NULL) {
		ret = gnutls_record_recv_packet(ws->session, &packet);
		if (ret > 0) {
			*p = packet;
			gnutls_packet_get(packet, data, NULL);
		}
	} else {
		ret = _cstp_recv_packet(ws, ws->buffer, ws->buffer_size);
		data->data = ws->buffer;
		data->size = ret;
	}

#else
	ret = _cstp_recv_packet(ws, ws->buffer, ws->buffer_size);
	data->data = ws->buffer;
	data->size = ret;
#endif
	return ret;
}

/* Restores gnutls_record_recv() on EAGAIN */
ssize_t cstp_recv(worker_st *ws, void *data, size_t data_size)
{
	int ret;
	int counter = 5;

	if (ws->session != NULL) {
		do {
			ret = gnutls_record_recv(ws->session, data, data_size);
			if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
				counter--;
				ms_sleep(20);
			}
		} while ((ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) && counter > 0);
	} else {
		do {
			ret = recv(ws->conn_fd, data, data_size, 0);
			if (ret == -1 && (errno == EAGAIN || errno == EINTR)) {
				counter--;
				ms_sleep(20);
			}
		} while(ret == -1 && (errno == EINTR || errno == EAGAIN) && counter > 0);
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

	if (WSCONFIG(ws)->cisco_client_compat == 0) {
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
	char *buf;
	va_list args;
	int ret, s;

	va_start(args, fmt);
	s = vasprintf(&buf, fmt, args);
	va_end(args);

	if (s == -1)
		return -1;

	ret = cstp_send(ws, buf, s);
	free(buf);
	return ret;
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

ssize_t dtls_recv_packet(worker_st *ws, gnutls_datum_t *data, void **p)
{
	int ret;
#ifdef ZERO_COPY
	gnutls_packet_t packet = NULL;

	ret = gnutls_record_recv_packet(ws->dtls_session, &packet);
	if (ret > 0) {
		gnutls_packet_get(packet, data, NULL);
		*p = packet;
	} else {
		data->size = 0;
	}
#else
	ret =
	    gnutls_record_recv(ws->dtls_session, ws->buffer, ws->buffer_size);
	data->data = ws->buffer;
	data->size = ret;
#endif

	return ret;
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

	(void)(ws);

	if (session == NULL)
		syslog(LOG_NOTICE, "warning: %s", str);
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
	if (ret == GNUTLS_E_NO_CERTIFICATE_FOUND) {
		oclog(ws, LOG_ERR, "no certificate was found");
		goto no_cert;
	}
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
no_cert:
	if (WSCONFIG(ws)->cisco_client_compat != 0 || WSCONFIG(ws)->cert_req != GNUTLS_CERT_REQUIRE)
		return 0;
fail:
	return GNUTLS_E_CERTIFICATE_ERROR;
}

void tls_global_init(void)
{
	gnutls_global_set_audit_log_function(tls_audit_log_func);
}

void tls_vhost_init(struct vhost_cfg_st *vhost)
{
	int ret;

	ret = gnutls_psk_allocate_server_credentials(&vhost->creds.pskcred);
	GNUTLS_FATAL_ERR(ret);
}

void tls_vhost_deinit(struct vhost_cfg_st *vhost)
{
#ifndef GNUTLS_BROKEN_CERTIFICATE_SET_KEY
	if (vhost->creds.xcred != NULL)
		gnutls_certificate_free_credentials(vhost->creds.xcred);
#endif

	if (vhost->creds.pskcred != NULL)
		gnutls_psk_free_server_credentials(vhost->creds.pskcred);
	if (vhost->creds.cprio != NULL)
		gnutls_priority_deinit(vhost->creds.cprio);

	gnutls_free(vhost->creds.ocsp_response.data);
	vhost->creds.ocsp_response.data = NULL;
	vhost->creds.xcred = NULL;
	vhost->creds.pskcred = NULL;
	vhost->creds.cprio = NULL;

	return;
}

/* Checks, if there is a single certificate specified, whether it
 * is compatible with all ciphersuites */
static void certificate_check(main_server_st *s, const char *vhostname, gnutls_pcert_st *pcert)
{
	gnutls_datum_t data = {NULL, 0};
	gnutls_x509_crt_t crt = NULL;
	int ret;
	unsigned usage;
	gnutls_datum_t dn = {NULL, 0};
	const char *cert_name = "unnamed";
	time_t t;

	(void)cert_name;

	ret = gnutls_x509_crt_init(&crt);
	GNUTLS_FATAL_ERR(ret);

	ret = gnutls_x509_crt_import(crt, &pcert->cert, GNUTLS_X509_FMT_DER);
	GNUTLS_FATAL_ERR(ret);

	ret = gnutls_x509_crt_get_pk_algorithm(crt, NULL);
	if (ret != GNUTLS_PK_RSA)
		goto cleanup;

#if GNUTLS_VERSION_NUMBER >= 0x030507
	ret = gnutls_x509_crt_get_dn3(crt, &dn, 0);
#else
	ret = gnutls_x509_crt_get_dn2(crt, &dn);
#endif
	if (ret >= 0) {
		cert_name = (char*)dn.data;
	}

	ret = gnutls_x509_crt_get_key_usage(crt, &usage, NULL);
	if (ret >= 0) {
		if (!(usage & GNUTLS_KEY_KEY_ENCIPHERMENT)) {
			mslog(s, NULL, LOG_WARNING, "%s certificate key usage prevents key encipherment; unable to support the RSA ciphersuites; "
				"if that is not intentional, regenerate the server certificate with the key usage flag 'key encipherment' set.",
				cert_name);
		}
	}

	if (vhostname) {
		/* check whether the hostname matches our vhost */
		if (!gnutls_x509_crt_check_hostname(crt, vhostname)) {
			mslog(s, NULL, LOG_WARNING, "The %s certificate's name doesn't match for vhost %s",
			      cert_name, vhostname);
		}
	}

	t = gnutls_x509_crt_get_expiration_time(crt);
	if (t < time(0)) {
		mslog(s, NULL, LOG_WARNING, "The %s certificate set is expired!", cert_name);
	}

	t = gnutls_x509_crt_get_activation_time(crt);
	if (t > time(0)) {
		mslog(s, NULL, LOG_WARNING, "The %s certificate set is not yet active!", cert_name);
	}

cleanup:
	if (crt != NULL)
		gnutls_x509_crt_deinit(crt);
	gnutls_free(data.data);
	gnutls_free(dn.data);
	return;
}

static void set_dh_params(main_server_st* s, struct vhost_cfg_st *vhost)
{
	gnutls_datum_t data;
	int ret;

	if (vhost->perm_config.dh_params_file != NULL) {
		ret = gnutls_dh_params_init (&vhost->creds.dh_params);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_load_file(vhost->perm_config.dh_params_file, &data);
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_dh_params_import_pkcs3(vhost->creds.dh_params, &data, GNUTLS_X509_FMT_PEM);
		GNUTLS_FATAL_ERR(ret);

		gnutls_free(data.data);

		gnutls_certificate_set_dh_params(vhost->creds.xcred, vhost->creds.dh_params);
	} else {
#if GNUTLS_VERSION_NUMBER >= 0x030506
		/* use pre-generated parameters */
		gnutls_certificate_set_known_dh_params(vhost->creds.xcred, GNUTLS_SEC_PARAM_MEDIUM);
#endif
	}
}

#ifndef UNDER_TEST
struct key_cb_data {
	unsigned pk;
	unsigned bits;
	unsigned idx; /* the index of the key */
	struct sockaddr_un sa;
	unsigned sa_len;
	const char *vhost;
};

static
int key_cb_common_func (gnutls_privkey_t key, void* userdata, const gnutls_datum_t * raw_data,
	gnutls_datum_t * output, unsigned sigalgo, unsigned type)
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
	msg.sig = sigalgo;
	msg.data.data = raw_data->data;
	msg.data.len = raw_data->size;
	msg.vhost = (char*)cdata->vhost;

	ret = send_msg(userdata, sd, type, &msg,
			(pack_size_func)sec_op_msg__get_packed_size,
			(pack_func)sec_op_msg__pack);
	if (ret < 0) {
		goto error;
	}

	ret = recv_msg(userdata, sd, type, (void*)&reply,
		       (unpack_func)sec_op_msg__unpack,
		       DEFAULT_SOCKET_TIMEOUT);
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

#if GNUTLS_VERSION_NUMBER >= 0x030600
static int key_cb_info_func(gnutls_privkey_t key, unsigned int flags, void *userdata)
{
	struct key_cb_data *p = userdata;

	if (flags & GNUTLS_PRIVKEY_INFO_PK_ALGO) {
		return p->pk;
#if GNUTLS_VERSION_NUMBER >= 0x030603
	} else if (flags & GNUTLS_PRIVKEY_INFO_PK_ALGO_BITS) {
		return p->bits;
#endif
	} else if (flags & GNUTLS_PRIVKEY_INFO_HAVE_SIGN_ALGO) {
		unsigned sig = GNUTLS_FLAGS_TO_SIGN_ALGO(flags);

		if (gnutls_sign_supports_pk_algorithm(sig, p->pk))
			return 1;

		return 0;
	}

	return -1;
}

static
int key_cb_sign_data_func (gnutls_privkey_t key, gnutls_sign_algorithm_t sig,
			   void* userdata, unsigned int flags, const gnutls_datum_t *data,
			   gnutls_datum_t *signature)
{
	return key_cb_common_func(key, userdata, data, signature, sig, CMD_SEC_SIGN_DATA);
}

static
int key_cb_sign_hash_func (gnutls_privkey_t key, gnutls_sign_algorithm_t sig,
			   void* userdata, unsigned int flags, const gnutls_datum_t *data,
			   gnutls_datum_t *signature)
{
	if (sig == GNUTLS_SIGN_RSA_RAW)
		return key_cb_common_func(key, userdata, data, signature, 0, CMD_SEC_SIGN);

	return key_cb_common_func(key, userdata, data, signature, sig, CMD_SEC_SIGN_HASH);
}

#else
static
int key_cb_sign_func (gnutls_privkey_t key, void* userdata, const gnutls_datum_t * raw_data,
	gnutls_datum_t * signature)
{
	return key_cb_common_func(key, userdata, raw_data, signature, 0, CMD_SEC_SIGN);
}
#endif

static int key_cb_decrypt_func(gnutls_privkey_t key, void* userdata, const gnutls_datum_t * ciphertext,
	gnutls_datum_t * plaintext)
{
	return key_cb_common_func(key, userdata, ciphertext, plaintext, 0, CMD_SEC_DECRYPT);
}

static void key_cb_deinit_func(gnutls_privkey_t key, void* userdata)
{
	talloc_free(userdata);
}

static
int load_cert_files(main_server_st *s, struct vhost_cfg_st *vhost)
{
	int ret;
	gnutls_pcert_st *pcert_list;
	unsigned pcert_list_size, i;
	gnutls_privkey_t key;
	gnutls_datum_t data;
	struct key_cb_data *cdata;
	unsigned flags;

	for (i=0;i<vhost->perm_config.key_size;i++) {
		/* load the certificate */

		if (gnutls_url_is_supported(vhost->perm_config.cert[i]) != 0) {
			mslog(s, NULL, LOG_ERR, "Loading a certificate from '%s' is unsupported", vhost->perm_config.cert[i]);
			return -1;
		} else {
			ret = gnutls_load_file(vhost->perm_config.cert[i], &data);
			if (ret < 0) {
				mslog(s, NULL, LOG_ERR, "error loading file[%d] '%s'", i, vhost->perm_config.cert[i]);
				return -1;
			}

			pcert_list_size = 8;
			pcert_list = talloc_size(vhost->pool, sizeof(pcert_list[0])*pcert_list_size);
			if (pcert_list == NULL) {
				mslog(s, NULL, LOG_ERR, "error allocating memory");
				return -1;
			}

			flags = GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED|GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED;
#if GNUTLS_VERSION_NUMBER > 0x030409
			flags |= GNUTLS_X509_CRT_LIST_SORT;
#endif

			ret = gnutls_pcert_list_import_x509_raw(pcert_list, &pcert_list_size,
								&data, GNUTLS_X509_FMT_PEM, flags);
			GNUTLS_FATAL_ERR(ret);

			gnutls_free(data.data);
		}

		/* sanity checks on the loaded certificate and key */
		certificate_check(s, vhost->name, &pcert_list[0]);

		ret = gnutls_privkey_init(&key);
		GNUTLS_FATAL_ERR(ret);

		/* use use the vhost/config pool rather than main, to allow usage of the credentials
		 * after freeing s.
		 */
		cdata = talloc_zero(vhost->pool, struct key_cb_data);
		if (cdata == NULL) {
			mslog(s, NULL, LOG_ERR, "error allocating memory");
			return -1;
		}

		cdata->idx = i;
		cdata->vhost = vhost->name;

		/* when called here configuration may not be populated, so avoid using it */
		cdata->sa.sun_family = AF_UNIX;
		strlcpy(cdata->sa.sun_path, secmod_socket_file_name(&vhost->perm_config), sizeof(cdata->sa.sun_path));
		cdata->sa_len = SUN_LEN(&cdata->sa);


		/* load the private key */

#if GNUTLS_VERSION_NUMBER >= 0x030600
		cdata->pk = gnutls_pubkey_get_pk_algorithm(pcert_list[0].pubkey, &cdata->bits);
		ret = gnutls_privkey_import_ext4(key, cdata, key_cb_sign_data_func,
			key_cb_sign_hash_func,key_cb_decrypt_func,
			key_cb_deinit_func, key_cb_info_func,
			GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
#else
		ret = gnutls_privkey_import_ext2(key, gnutls_pubkey_get_pk_algorithm(pcert_list[0].pubkey, NULL),
			cdata, key_cb_sign_func, key_cb_decrypt_func,
			key_cb_deinit_func, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
#endif
		GNUTLS_FATAL_ERR(ret);

		ret = gnutls_certificate_set_key(vhost->creds.xcred, NULL, 0, pcert_list,
				pcert_list_size, key);
		GNUTLS_FATAL_ERR(ret);
	}

	return 0;
}

unsigned need_file_reload(const char *file, time_t last_access)
{
	struct stat st;
	int ret, e;

	if (file == NULL || file[0] == 0)
		return 0;

	if (last_access == 0)
		return 1;

	ret = stat(file, &st);
	if (ret == -1) {
		e = errno;
		syslog(LOG_INFO, "file %s (to be reloaded) was not found: %s",
		      file, strerror(e));
		return 0;
	}

	/* reload only if it is a newer file */
	if (st.st_mtime > last_access)
		return 1;
	return 0;
}

/* reload key files etc.
 * @s may be %NULL, and should be used for mslog() purposes only.
 */
void tls_load_files(main_server_st *s, struct vhost_cfg_st *vhost)
{
	int ret;
	unsigned i;
	unsigned need_reload = 0;

	if (vhost->params_last_access != 0) {
		for (i=0;i<vhost->perm_config.key_size;i++) {
			if (need_file_reload(vhost->perm_config.cert[i], vhost->params_last_access) != 0) {
				need_reload = 1;
				break;
			}
		}

		if (need_file_reload(vhost->perm_config.ca, vhost->params_last_access) ||
		    need_file_reload(vhost->perm_config.config->ocsp_response, vhost->params_last_access) ||
		    need_file_reload(vhost->perm_config.dh_params_file, vhost->params_last_access)) {
			need_reload = 1;
		}

		if (need_reload == 0)
			return;

		mslog(s, NULL, LOG_INFO, "reloading server certificates");
	}

	if (vhost->perm_config.debug >= DEBUG_TLS) {
		gnutls_global_set_log_function(tls_log_func);
		gnutls_global_set_log_level(9);
	}

	vhost->params_last_access = time(0);

#ifndef GNUTLS_BROKEN_CERTIFICATE_SET_KEY
	if (vhost->creds.xcred != NULL)
		gnutls_certificate_free_credentials(vhost->creds.xcred);
#endif

	ret = gnutls_certificate_allocate_credentials(&vhost->creds.xcred);
	GNUTLS_FATAL_ERR(ret);

	set_dh_params(s, vhost);

	if (vhost->perm_config.key_size == 0 || vhost->perm_config.cert_size == 0) {
		mslog(s, NULL, LOG_ERR, "no certificate or key files were specified");
		exit(1);
	}

	/* on reload reduce any checks done */
	if (need_reload) {
#if GNUTLS_VERSION_NUMBER >= 0x030407
		gnutls_certificate_set_flags(vhost->creds.xcred, GNUTLS_CERTIFICATE_SKIP_KEY_CERT_MATCH);
#endif
	}

	ret = load_cert_files(s, vhost);
	if (ret < 0) {
		mslog(s, NULL, LOG_ERR, "error loading the certificate or key file");
		exit(1);
	}

	if (vhost->perm_config.config->cert_req != GNUTLS_CERT_IGNORE) {
		if (vhost->perm_config.ca != NULL) {
			ret =
			    gnutls_certificate_set_x509_trust_file(vhost->creds.xcred,
								   vhost->perm_config.ca,
								   GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				mslog(s, NULL, LOG_ERR, "error setting the CA (%s) file",
					vhost->perm_config.ca);
				exit(1);
			}

			mslog(s, NULL, LOG_INFO, "processed %d CA certificate(s)", ret);
		}

		tls_reload_crl(s, vhost, 1);

		gnutls_certificate_set_verify_function(vhost->creds.xcred,
						       verify_certificate_cb);
	}

	tls_reload_ocsp(s, vhost);

	return;
}

static int ocsp_get_func(gnutls_session_t session, void *ptr, gnutls_datum_t *response)
{
	struct vhost_cfg_st *vhost = ptr;

	if (ptr == NULL || vhost->creds.ocsp_response.size == 0)
		return GNUTLS_E_NO_CERTIFICATE_STATUS;

	response->data = gnutls_malloc(vhost->creds.ocsp_response.size);
	if (response->data == NULL)
		return GNUTLS_E_NO_CERTIFICATE_STATUS;

	memcpy(response->data, vhost->creds.ocsp_response.data, vhost->creds.ocsp_response.size);
	response->size = vhost->creds.ocsp_response.size;

	return 0;
}

static void tls_reload_ocsp(main_server_st* s, struct vhost_cfg_st *vhost)
{
	int ret;

	gnutls_free(vhost->creds.ocsp_response.data);
	vhost->creds.ocsp_response.data = NULL;

	if (vhost->perm_config.config->ocsp_response != NULL) {
		ret = gnutls_load_file(vhost->perm_config.config->ocsp_response, &vhost->creds.ocsp_response);
		if (ret < 0)
			return;

		gnutls_certificate_set_ocsp_status_request_function(vhost->creds.xcred,
								    ocsp_get_func, vhost);
	} else {
		gnutls_certificate_set_ocsp_status_request_function(vhost->creds.xcred, NULL, 0);
	}
}

/*
 * @s may be %NULL, and should be used for mslog() purposes only.
 */
void tls_load_prio(main_server_st *s, struct vhost_cfg_st *vhost)
{
	int ret;
	const char* perr;

	if (vhost->creds.cprio != NULL)
		gnutls_priority_deinit(vhost->creds.cprio);

	ret = gnutls_priority_init(&vhost->creds.cprio, vhost->perm_config.config->priorities, &perr);
	if (ret == GNUTLS_E_PARSING_ERROR)
		mslog(s, NULL, LOG_ERR, "error in TLS priority string: %s", perr);
	GNUTLS_FATAL_ERR(ret);

	return;
}

/*
 * @s may be %NULL, and should be used for mslog() purposes only.
 */
void tls_reload_crl(main_server_st* s, struct vhost_cfg_st *vhost, unsigned force)
{
	int ret, saved_ret;
	static unsigned crl_type = GNUTLS_X509_FMT_PEM;

	if (force)
		vhost->crl_last_access = 0;

	if (vhost->perm_config.config->cert_req != GNUTLS_CERT_IGNORE && vhost->perm_config.config->crl != NULL) {
		if (need_file_reload(vhost->perm_config.config->crl, vhost->crl_last_access) == 0) {
			mslog(s, NULL, LOG_DEBUG, "skipping already loaded CRL: %s", vhost->perm_config.config->crl);
			return;
		}

		vhost->crl_last_access = time(0);

		ret =
		    gnutls_certificate_set_x509_crl_file(vhost->creds.xcred,
							 vhost->perm_config.config->crl,
							 crl_type);
		if (ret == GNUTLS_E_BASE64_DECODING_ERROR && crl_type == GNUTLS_X509_FMT_PEM) {
			crl_type = GNUTLS_X509_FMT_DER;
			saved_ret = ret;
			ret =
			    gnutls_certificate_set_x509_crl_file(vhost->creds.xcred,
								 vhost->perm_config.config->crl,
								 crl_type);
			if (ret < 0)
				ret = saved_ret;
		}
		if (ret < 0) {
			/* ignore the CRL file when empty */
			mslog(s, NULL, LOG_ERR, "error reading the CRL (%s) file: %s",
				vhost->perm_config.config->crl, gnutls_strerror(ret));
			exit(1);
		}
		mslog(s, NULL, LOG_INFO, "loaded CRL: %s", vhost->perm_config.config->crl);
	}
}
#endif

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
	return gnutls_est_record_overhead_size(version, cipher, mac, GNUTLS_COMP_NULL, 0);
}
