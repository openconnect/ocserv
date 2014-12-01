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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <system.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <common.h>
#include <syslog.h>
#include <vpn.h>
#include <sec-mod.h>
#include <tlslib.h>
#include <ipc.pb-c.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#define MAX_WAIT_SECS 3
#define MAX_PIN_SIZE GNUTLS_PKCS11_MAX_PIN_LEN
#define MAINTAINANCE_TIME 300

static int need_maintainance = 0;
static int need_reload = 0;
static int need_exit = 0;

struct pin_st {
	char pin[MAX_PIN_SIZE];
	char srk_pin[MAX_PIN_SIZE];
};

static
int pin_callback(void *user, int attempt, const char *token_url,
		 const char *token_label, unsigned int flags, char *pin,
		 size_t pin_max)
{
	struct pin_st *ps = user;
	int srk = 0;
	const char *p;
	unsigned len;

	if (flags & GNUTLS_PIN_FINAL_TRY) {
		syslog(LOG_ERR,
		       "PIN callback: final try before locking; not attempting to unlock");
		return -1;
	}

	if (flags & GNUTLS_PIN_WRONG) {
		syslog(LOG_ERR,
		       "PIN callback: wrong PIN was entered for '%s' (%s)",
		       token_label, token_url);
		return -1;
	}

	if (ps->pin[0] == 0) {
		syslog(LOG_ERR,
		       "PIN required for '%s' but pin-file was not set",
		       token_label);
		return -1;
	}

	if (strcmp(token_url, "SRK") == 0 || strcmp(token_label, "SRK") == 0) {
		srk = 1;
		p = ps->srk_pin;
	} else {
		p = ps->pin;
	}

	if (srk != 0 && ps->srk_pin[0] == 0) {
		syslog(LOG_ERR,
		       "PIN required for '%s' but srk-pin-file was not set",
		       token_label);
		return -1;
	}

	len = strlen(p);
	if (len > pin_max - 1) {
		syslog(LOG_ERR, "Too long PIN (%u chars)", len);
		return -1;
	}

	memcpy(pin, p, len);
	pin[len] = 0;

	return 0;
}

static
int load_pins(struct cfg_st *config, struct pin_st *s)
{
	int fd, ret;

	s->srk_pin[0] = 0;
	s->pin[0] = 0;

	if (config->srk_pin_file != NULL) {
		fd = open(config->srk_pin_file, O_RDONLY);
		if (fd < 0) {
			syslog(LOG_ERR, "could not open SRK PIN file '%s'",
			       config->srk_pin_file);
			return -1;
		}

		ret = read(fd, s->srk_pin, sizeof(s->srk_pin) - 1);
		close(fd);
		if (ret <= 1) {
			syslog(LOG_ERR, "could not read from PIN file '%s'",
			       config->srk_pin_file);
			return -1;
		}

		if (s->srk_pin[ret - 1] == '\n' || s->srk_pin[ret - 1] == '\r')
			s->srk_pin[ret - 1] = 0;
		s->srk_pin[ret] = 0;
	}

	if (config->pin_file != NULL) {
		fd = open(config->pin_file, O_RDONLY);
		if (fd < 0) {
			syslog(LOG_ERR, "could not open PIN file '%s'",
			       config->pin_file);
			return -1;
		}

		ret = read(fd, s->pin, sizeof(s->pin) - 1);
		close(fd);
		if (ret <= 1) {
			syslog(LOG_ERR, "could not read from PIN file '%s'",
			       config->pin_file);
			return -1;
		}

		if (s->pin[ret - 1] == '\n' || s->pin[ret - 1] == '\r')
			s->pin[ret - 1] = 0;
		s->pin[ret] = 0;
	}

	return 0;
}

static int handle_op(void *pool, sec_mod_st * sec, uint8_t type, uint8_t * rep,
		     size_t rep_size)
{
	SecOpMsg msg = SEC_OP_MSG__INIT;
	int ret;

	msg.data.data = rep;
	msg.data.len = rep_size;

	ret = send_msg(pool, sec->fd, type, &msg,
		       (pack_size_func) sec_op_msg__get_packed_size,
		       (pack_func) sec_op_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_WARNING, "sec-mod error in sending reply");
	}

	return 0;
}

static
int process_packet(void *pool, sec_mod_st * sec, cmd_request_t cmd,
		   uid_t uid, uint8_t * buffer, size_t buffer_size)
{
	unsigned i;
	gnutls_datum_t data, out;
	int ret;
	SecOpMsg *op;
	PROTOBUF_ALLOCATOR(pa, pool);

	seclog(sec, LOG_DEBUG, "cmd [size=%d] %s\n", (int)buffer_size,
	       cmd_request_to_str(cmd));
	data.data = buffer;
	data.size = buffer_size;

	switch (cmd) {
	case SM_CMD_SIGN:
	case SM_CMD_DECRYPT:
		op = sec_op_msg__unpack(&pa, data.size, data.data);
		if (op == NULL) {
			seclog(sec, LOG_INFO, "error unpacking sec op\n");
			return -1;
		}

		i = op->key_idx;
		if (op->has_key_idx == 0 || i >= sec->key_size) {
			seclog(sec, LOG_INFO,
			       "received out-of-bounds key index (%d)", i);
			return -1;
		}

		data.data = op->data.data;
		data.size = op->data.len;

		if (cmd == SM_CMD_DECRYPT) {
			ret =
			    gnutls_privkey_decrypt_data(sec->key[i], 0, &data,
							&out);
		} else {
#if GNUTLS_VERSION_NUMBER >= 0x030200
			ret =
			    gnutls_privkey_sign_hash(sec->key[i], 0,
						     GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA,
						     &data, &out);
#else
			ret =
			    gnutls_privkey_sign_raw_data(sec->key[i], 0, &data,
							 &out);
#endif
		}
		sec_op_msg__free_unpacked(op, &pa);

		if (ret < 0) {
			seclog(sec, LOG_INFO, "error in crypto operation: %s",
			       gnutls_strerror(ret));
			return -1;
		}

		ret = handle_op(pool, sec, cmd, out.data, out.size);
		gnutls_free(out.data);

		return ret;

	case SM_CMD_AUTH_INIT:{
			SecAuthInitMsg *auth_init;

			auth_init =
			    sec_auth_init_msg__unpack(&pa, data.size,
						      data.data);
			if (auth_init == NULL) {
				seclog(sec, LOG_INFO, "error unpacking auth init\n");
				return -1;
			}

			ret = handle_sec_auth_init(sec, auth_init);
			sec_auth_init_msg__free_unpacked(auth_init, &pa);
			return ret;
		}
	case SM_CMD_AUTH_CONT:{
			SecAuthContMsg *auth_cont;

			auth_cont =
			    sec_auth_cont_msg__unpack(&pa, data.size,
						      data.data);
			if (auth_cont == NULL) {
				seclog(sec, LOG_INFO, "error unpacking auth cont\n");
				return -1;
			}

			ret = handle_sec_auth_cont(sec, auth_cont);
			sec_auth_cont_msg__free_unpacked(auth_cont, &pa);
			return ret;
		}
	case SM_CMD_AUTH_SESSION_OPEN:
	case SM_CMD_AUTH_SESSION_CLOSE:{
			SecAuthSessionMsg *msg;
			SecAuthSessionReplyMsg rep = SEC_AUTH_SESSION_REPLY_MSG__INIT;

			if (uid != 0) {
				seclog(sec, LOG_INFO, "received session open/close from unauthorized uid (%u)\n", (unsigned)uid);
				return -1;
			}

			msg =
			    sec_auth_session_msg__unpack(&pa, data.size,
						      data.data);
			if (msg == NULL) {
				seclog(sec, LOG_INFO, "error unpacking session close\n");
				return -1;
			}

			ret = handle_sec_auth_session_cmd(sec, msg, cmd);
			sec_auth_session_msg__free_unpacked(msg, &pa);

			if (cmd == SM_CMD_AUTH_SESSION_OPEN) {
				if (ret < 0)
					rep.reply = AUTH__REP__FAILED;
				else
					rep.reply = AUTH__REP__OK;

				ret = send_msg(pool, sec->fd, SM_CMD_AUTH_SESSION_REPLY, &rep,
					(pack_size_func) sec_auth_session_reply_msg__get_packed_size,
					(pack_func) sec_auth_session_reply_msg__pack);
				if (ret < 0) {
					seclog(sec, LOG_WARNING, "sec-mod error in sending session reply");
				}
			}

			return ret;
		}
	default:
		seclog(sec, LOG_WARNING, "unknown type 0x%.2x", cmd);
		return -1;
	}

	return 0;
}

static void handle_alarm(int signo)
{
	need_maintainance = 1;
}

static void handle_sighup(int signo)
{
	need_reload = 1;
}

static void handle_sigterm(int signo)
{
	need_exit = 1;
}

static void check_other_work(sec_mod_st *sec)
{
	if (need_exit) {
		unsigned i;

		for (i = 0; i < sec->key_size; i++) {
			gnutls_privkey_deinit(sec->key[i]);
		}

		sec_mod_client_db_deinit(sec);
		sec_mod_ban_db_deinit(sec);
		talloc_free(sec);
		exit(0);
	}

	if (need_reload) {
		seclog(sec, LOG_DEBUG, "reloading configuration");
		reload_cfg_file(sec, sec->config);
		need_reload = 0;
	}

	if (need_maintainance) {
		seclog(sec, LOG_DEBUG, "performing maintenance");
		cleanup_client_entries(sec);
		cleanup_banned_entries(sec);
		seclog(sec, LOG_DEBUG, "active sessions %d, banned entries %d", 
			sec_mod_client_db_elems(sec),
			sec_mod_ban_db_elems(sec));
		alarm(MAINTAINANCE_TIME);
		need_maintainance = 0;
	}
}

/* sec_mod_server:
 * @config: server configuration
 * @socket_file: the name of the socket
 *
 * This is the main part of the security module.
 * It creates the unix domain socket identified by @socket_file
 * and then accepts connections from the workers to it. Then 
 * it serves commands requested on the server's private key.
 *
 * When the operation is decrypt the provided data are
 * decrypted and sent back to worker. The sign operation
 * signs the provided data.
 *
 * The security module's reply to the worker has the
 * following format:
 * byte[0-1]: length (uint16_t)
 * byte[2-total]: data (signature or decrypted data)
 *
 * The reason for having this as a separate process
 * is to avoid any bug on the workers to leak the key.
 * It is not part of main because workers are spawned
 * from main, and thus should be prevented from accessing
 * parts the key in stack or heap that was not zeroized.
 * Other than that it allows the main server to spawn
 * clients fast without becoming a bottleneck due to private 
 * key operations.
 */
void sec_mod_server(void *main_pool, struct cfg_st *config, const char *socket_file,
		    uint8_t cookie_key[COOKIE_KEY_SIZE])
{
	struct sockaddr_un sa;
	socklen_t sa_len;
	int cfd, ret, e;
	unsigned cmd, length;
	unsigned i, buffer_size;
	uid_t uid;
	uint8_t *buffer, *tpool;
	uint16_t l16;
	struct pin_st pins;
	int sd;
	sec_mod_st *sec;
	void *sec_mod_pool;

#ifdef DEBUG_LEAKS
	talloc_enable_leak_report_full();
#endif

	sec_mod_pool = talloc_init("sec-mod");
	if (sec_mod_pool == NULL) {
		seclog(sec, LOG_ERR, "error in memory allocation");
		exit(1);
	}

	sec = talloc_zero(sec_mod_pool, sec_mod_st);
	if (sec == NULL) {
		seclog(sec, LOG_ERR, "error in memory allocation");
		exit(1);
	}

	memcpy(sec->cookie_key, cookie_key, COOKIE_KEY_SIZE);
	sec->dcookie_key.data = sec->cookie_key;
	sec->dcookie_key.size = COOKIE_KEY_SIZE;
	sec->config = talloc_steal(sec, config);

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", socket_file);
	remove(socket_file);

#define SOCKET_FILE sa.sun_path

	/* we no longer need the main pool after this point. */
	talloc_free(main_pool);

	ocsignal(SIGHUP, handle_sighup);
	ocsignal(SIGINT, handle_sigterm);
	ocsignal(SIGTERM, handle_sigterm);
	ocsignal(SIGALRM, handle_alarm);

	alarm(MAINTAINANCE_TIME);

	sec_auth_init(config);

#ifdef HAVE_PKCS11
	ret = gnutls_pkcs11_reinit();
	if (ret < 0) {
		seclog(sec, LOG_WARNING, "error in PKCS #11 reinitialization: %s",
		       gnutls_strerror(ret));
	}
#endif

	if (sec_mod_client_db_init(sec) == NULL) {
		seclog(sec, LOG_ERR, "error in client db initialization");
		exit(1);
	}

	if (config->min_reauth_time > 0)
		sec_mod_ban_db_init(sec);

	buffer_size = 8 * 1024;
	buffer = talloc_size(sec, buffer_size);
	if (buffer == NULL) {
		seclog(sec, LOG_ERR, "error in memory allocation");
		exit(1);
	}


	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		seclog(sec, LOG_ERR, "could not create socket '%s': %s", SOCKET_FILE,
		       strerror(e));
		exit(1);
	}

	umask(066);
	ret = bind(sd, (struct sockaddr *)&sa, SUN_LEN(&sa));
	if (ret == -1) {
		e = errno;
		seclog(sec, LOG_ERR, "could not bind socket '%s': %s", SOCKET_FILE,
		       strerror(e));
		exit(1);
	}

	ret = chown(SOCKET_FILE, config->uid, config->gid);
	if (ret == -1) {
		e = errno;
		seclog(sec, LOG_INFO, "could not chown socket '%s': %s", SOCKET_FILE,
		       strerror(e));
	}

	ret = listen(sd, 1024);
	if (ret == -1) {
		e = errno;
		seclog(sec, LOG_ERR, "could not listen to socket '%s': %s",
		       SOCKET_FILE, strerror(e));
		exit(1);
	}

	ret = load_pins(config, &pins);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "error loading PIN files");
		exit(1);
	}

	/* FIXME: the private key isn't reloaded on reload */
	sec->key_size = config->key_size;
	sec->key = talloc_size(sec, sizeof(*sec->key) * config->key_size);
	if (sec->key == NULL) {
		seclog(sec, LOG_ERR, "error in memory allocation");
		exit(1);
	}

	/* read private keys */
	for (i = 0; i < sec->key_size; i++) {
		ret = gnutls_privkey_init(&sec->key[i]);
		GNUTLS_FATAL_ERR(ret);

		/* load the private key */
		if (gnutls_url_is_supported(config->key[i]) != 0) {
			gnutls_privkey_set_pin_function(sec->key[i],
							pin_callback, &pins);
			ret =
			    gnutls_privkey_import_url(sec->key[i],
						      config->key[i], 0);
			GNUTLS_FATAL_ERR(ret);
		} else {
			gnutls_datum_t data;
			ret = gnutls_load_file(config->key[i], &data);
			if (ret < 0) {
				seclog(sec, LOG_ERR, "error loading file '%s'",
				       config->key[i]);
				GNUTLS_FATAL_ERR(ret);
			}

			ret =
			    gnutls_privkey_import_x509_raw(sec->key[i], &data,
							   GNUTLS_X509_FMT_PEM,
							   NULL, 0);
			GNUTLS_FATAL_ERR(ret);

			gnutls_free(data.data);
		}
	}

	seclog(sec, LOG_INFO, "sec-mod initialized (socket: %s)", SOCKET_FILE);

	for (;;) {
		check_other_work(sec);

		sa_len = sizeof(sa);
		cfd = accept(sd, (struct sockaddr *)&sa, &sa_len);
		if (cfd == -1) {
			e = errno;
			if (e != EINTR) {
				seclog(sec, LOG_DEBUG,
				       "sec-mod error accepting connection: %s",
				       strerror(e));
			}
			continue;
		}

		/* do not allow unauthorized processes to issue commands
		 */
		ret = check_upeer_id("sec-mod", cfd, config->uid, config->gid, &uid);
		if (ret < 0) {
			seclog(sec, LOG_INFO, "rejected unauthorized connection");
			goto cont;
		}

		/* read request */
		ret = force_read_timeout(cfd, buffer, 3, MAX_WAIT_SECS);
		if (ret == 0)
			goto cont;
		else if (ret < 3) {
			e = errno;
			seclog(sec, LOG_INFO, "error receiving msg head: %s",
			       strerror(e));
			goto cont;
		}

		cmd = buffer[0];
		memcpy(&l16, &buffer[1], 2);
		length = l16;

		if (length > buffer_size - 4) {
			seclog(sec, LOG_INFO, "too big message (%d)", length);
			goto cont;
		}

		/* read the body */
		ret = force_read_timeout(cfd, buffer, length, MAX_WAIT_SECS);
		if (ret < 0) {
			e = errno;
			seclog(sec, LOG_INFO, "error receiving msg body: %s",
			       strerror(e));
			goto cont;
		}

		tpool = talloc_new(sec);
		sec->fd = cfd;
		ret = process_packet(tpool, sec, cmd, uid, buffer, ret);
		if (ret < 0) {
			seclog(sec, LOG_INFO, "error processing data for '%s' command (%d)", cmd_request_to_str(cmd), ret);
		}
		talloc_free(tpool);

#ifdef DEBUG_LEAKS
		talloc_report_full(sec, stderr);
#endif
 cont:
		close(cfd);
	}
}
