/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
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
#include <main.h>
#include <sec-mod.h>
#include <tlslib.h>
#include <ipc.pb-c.h>
#include <sec-mod-sup-config.h>
#include <sec-mod-resume.h>
#include <cloexec.h>
#include <assert.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#define MAINTAINANCE_TIME 310

static int need_maintainance = 0;
static int need_reload = 0;
static int need_exit = 0;

static void reload_server(sec_mod_st *sec);

static int load_keys(sec_mod_st *sec, unsigned force);

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
int load_pins(struct perm_cfg_st *config, struct pin_st *s)
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

	if (config->key_pin != NULL) {
		strlcpy(s->pin, config->key_pin, sizeof(s->pin));
	}

	if (config->srk_pin != NULL) {
		strlcpy(s->srk_pin, config->srk_pin, sizeof(s->srk_pin));
	}

	return 0;
}

static int handle_op(void *pool, int cfd, sec_mod_st * sec, uint8_t type, uint8_t * rep,
		     size_t rep_size)
{
	SecOpMsg msg = SEC_OP_MSG__INIT;
	int ret;

	msg.data.data = rep;
	msg.data.len = rep_size;

	ret = send_msg(pool, cfd, type, &msg,
		       (pack_size_func) sec_op_msg__get_packed_size,
		       (pack_func) sec_op_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_WARNING, "sec-mod error in sending reply");
	}

	return 0;
}

static
int process_worker_packet(void *pool, int cfd, pid_t pid, sec_mod_st *sec, cmd_request_t cmd,
		   uint8_t * buffer, size_t buffer_size)
{
	unsigned i;
	gnutls_datum_t data, out;
	int ret;
	SecOpMsg *op;
	vhost_cfg_st *vhost;
#if GNUTLS_VERSION_NUMBER >= 0x030600
	unsigned bits;
	SecGetPkMsg *pkm;
#endif
	PROTOBUF_ALLOCATOR(pa, pool);

	seclog(sec, LOG_DEBUG, "cmd [size=%d] %s\n", (int)buffer_size,
	       cmd_request_to_str(cmd));
	data.data = buffer;
	data.size = buffer_size;

	switch (cmd) {
#if GNUTLS_VERSION_NUMBER >= 0x030600
	case CMD_SEC_GET_PK:
		pkm = sec_get_pk_msg__unpack(&pa, data.size, data.data);
		if (pkm == NULL) {
			seclog(sec, LOG_INFO, "error unpacking sec get pk\n");
			return -1;
		}

		vhost = find_vhost(sec->vconfig, pkm->vhost);
		/* check for static analyzer - find_vhost is always non-NULL */
		assert(vhost != NULL);

		i = pkm->key_idx;
		if (i >= vhost->key_size) {
			seclog(sec, LOG_INFO,
			       "%sreceived out-of-bounds key index (%d); have %d keys", PREFIX_VHOST(vhost), i, vhost->key_size);
			return -1;
		}

		pkm->pk = gnutls_privkey_get_pk_algorithm(vhost->key[i], &bits);
		pkm->bits = bits;

		ret = send_msg(pool, cfd, CMD_SEC_GET_PK, pkm,
			       (pack_size_func) sec_get_pk_msg__get_packed_size,
			       (pack_func) sec_get_pk_msg__pack);

		sec_get_pk_msg__free_unpacked(pkm, &pa);

		if (ret < 0) {
			seclog(sec, LOG_INFO, "error sending reply: %s",
			       gnutls_strerror(ret));
			return -1;
		}

		return ret;

	case CMD_SEC_SIGN_DATA:
	case CMD_SEC_SIGN_HASH:
		op = sec_op_msg__unpack(&pa, data.size, data.data);
		if (op == NULL) {
			seclog(sec, LOG_INFO, "error unpacking sec op\n");
			return -1;
		}

		vhost = find_vhost(sec->vconfig, op->vhost);
		assert(vhost != NULL);

		i = op->key_idx;
		if (op->has_key_idx == 0 || i >= vhost->key_size) {
			seclog(sec, LOG_INFO,
			       "%sreceived out-of-bounds key index (%d); have %d keys", PREFIX_VHOST(vhost), i, vhost->key_size);
			return -1;
		}

		data.data = op->data.data;
		data.size = op->data.len;

		if (cmd == CMD_SEC_SIGN_DATA) {
			ret = gnutls_privkey_sign_data2(vhost->key[i], op->sig, 0, &data, &out);
		} else {
			ret = gnutls_privkey_sign_hash2(vhost->key[i], op->sig, 0, &data, &out);
		}
		sec_op_msg__free_unpacked(op, &pa);

		if (ret < 0) {
			seclog(sec, LOG_INFO, "error in crypto operation: %s",
			       gnutls_strerror(ret));
			return -1;
		}

		ret = handle_op(pool, cfd, sec, cmd, out.data, out.size);
		gnutls_free(out.data);

		return ret;
#endif
	case CMD_SEC_SIGN:
	case CMD_SEC_DECRYPT:
		op = sec_op_msg__unpack(&pa, data.size, data.data);
		if (op == NULL) {
			seclog(sec, LOG_INFO, "error unpacking sec op\n");
			return -1;
		}

		vhost = find_vhost(sec->vconfig, op->vhost);
		assert(vhost != NULL);

		i = op->key_idx;
		if (op->has_key_idx == 0 || i >= vhost->key_size) {
			seclog(sec, LOG_INFO,
			       "%sreceived out-of-bounds key index (%d); have %d keys", PREFIX_VHOST(vhost), i, vhost->key_size);
			return -1;
		}

		data.data = op->data.data;
		data.size = op->data.len;

		if (cmd == CMD_SEC_DECRYPT) {
			ret =
			    gnutls_privkey_decrypt_data(vhost->key[i], 0, &data,
							&out);
		} else {
			ret =
			    gnutls_privkey_sign_hash(vhost->key[i], 0,
						     GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA,
						     &data, &out);
		}
		sec_op_msg__free_unpacked(op, &pa);

		if (ret < 0) {
			seclog(sec, LOG_INFO, "error in crypto operation: %s",
			       gnutls_strerror(ret));
			return -1;
		}

		ret = handle_op(pool, cfd, sec, cmd, out.data, out.size);
		gnutls_free(out.data);

		return ret;

	case CMD_SEC_CLI_STATS:{
			CliStatsMsg *tmsg;

			tmsg = cli_stats_msg__unpack(&pa, data.size, data.data);
			if (tmsg == NULL) {
				seclog(sec, LOG_ERR, "error unpacking data");
				return -1;
			}

			ret = handle_sec_auth_stats_cmd(sec, tmsg, pid);
			cli_stats_msg__free_unpacked(tmsg, &pa);
			return ret;
		}
		break;

	case CMD_SEC_AUTH_INIT:{
			SecAuthInitMsg *auth_init;

			auth_init =
			    sec_auth_init_msg__unpack(&pa, data.size,
						      data.data);
			if (auth_init == NULL) {
				seclog(sec, LOG_INFO, "error unpacking auth init\n");
				return -1;
			}

			ret = handle_sec_auth_init(cfd, sec, auth_init, pid);
			sec_auth_init_msg__free_unpacked(auth_init, &pa);
			return ret;
		}
	case CMD_SEC_AUTH_CONT:{
			SecAuthContMsg *auth_cont;

			auth_cont =
			    sec_auth_cont_msg__unpack(&pa, data.size,
						      data.data);
			if (auth_cont == NULL) {
				seclog(sec, LOG_INFO, "error unpacking auth cont\n");
				return -1;
			}

			ret = handle_sec_auth_cont(cfd, sec, auth_cont);
			sec_auth_cont_msg__free_unpacked(auth_cont, &pa);
			return ret;
		}
	case RESUME_STORE_REQ:{
			SessionResumeStoreReqMsg *smsg;

			smsg =
			    session_resume_store_req_msg__unpack(&pa, buffer_size,
								 buffer);
			if (smsg == NULL) {
				seclog(sec, LOG_ERR, "error unpacking data");
				return ERR_BAD_COMMAND;
			}

			ret = handle_resume_store_req(sec, smsg);

			/* zeroize the data */
			safe_memset(buffer, 0, buffer_size);
			safe_memset(smsg->session_data.data, 0, smsg->session_data.len);

			session_resume_store_req_msg__free_unpacked(smsg, &pa);

			if (ret < 0) {
				seclog(sec, LOG_DEBUG,
				      "could not store resumption data");
			}
		}

		break;

	case RESUME_DELETE_REQ:{
			SessionResumeFetchMsg *fmsg;

			fmsg =
			    session_resume_fetch_msg__unpack(&pa, buffer_size,
							     buffer);
			if (fmsg == NULL) {
				seclog(sec, LOG_ERR, "error unpacking data");
				return ERR_BAD_COMMAND;
			}

			ret = handle_resume_delete_req(sec, fmsg);

			session_resume_fetch_msg__free_unpacked(fmsg, &pa);

			if (ret < 0) {
				seclog(sec, LOG_DEBUG,
				      "could not delete resumption data.");
			}
		}

		break;
	case RESUME_FETCH_REQ:{
			SessionResumeReplyMsg msg =
			    SESSION_RESUME_REPLY_MSG__INIT;
			SessionResumeFetchMsg *fmsg;

			/* FIXME: rate limit that */

			fmsg =
			    session_resume_fetch_msg__unpack(&pa, buffer_size,
							     buffer);
			if (fmsg == NULL) {
				seclog(sec, LOG_ERR, "error unpacking data");
				return ERR_BAD_COMMAND;
			}

			ret = handle_resume_fetch_req(sec, fmsg, &msg);

			session_resume_fetch_msg__free_unpacked(fmsg, &pa);

			if (ret < 0) {
				msg.reply =
				    SESSION_RESUME_REPLY_MSG__RESUME__REP__FAILED;
				seclog(sec, LOG_DEBUG,
				      "could not fetch resumption data.");
			} else {
				msg.reply =
				    SESSION_RESUME_REPLY_MSG__RESUME__REP__OK;
			}

			ret =
			    send_msg(pool, cfd, RESUME_FETCH_REP, &msg,
					       (pack_size_func)
					       session_resume_reply_msg__get_packed_size,
					       (pack_func)
					       session_resume_reply_msg__pack);

			if (ret < 0) {
				seclog(sec, LOG_ERR,
				      "could not send reply cmd %d.",
				      (unsigned)cmd);
				return ERR_BAD_COMMAND;
			}

		}

		break;

	default:
		seclog(sec, LOG_WARNING, "unknown type 0x%.2x", cmd);
		return -1;
	}

	return 0;
}

static
int process_packet_from_main(void *pool, int fd, sec_mod_st * sec, cmd_request_t cmd,
		   uint8_t * buffer, size_t buffer_size)
{
	gnutls_datum_t data;
	int ret;
	PROTOBUF_ALLOCATOR(pa, pool);

	seclog(sec, LOG_DEBUG, "cmd [size=%d] %s\n", (int)buffer_size,
	       cmd_request_to_str(cmd));
	data.data = buffer;
	data.size = buffer_size;

	switch (cmd) {
	case CMD_SECM_RELOAD:
		reload_server(sec);

		ret = send_msg(pool, fd, CMD_SECM_RELOAD_REPLY, NULL,
			       NULL, NULL);
		if (ret < 0) {
			seclog(sec, LOG_ERR, "could not send reload reply to main!\n");
			return ERR_BAD_COMMAND;
		}
		break;
	case CMD_SECM_LIST_COOKIES:
		handle_secm_list_cookies_reply(pool, fd, sec);

		return 0;
	case CMD_SECM_BAN_IP_REPLY:{
		BanIpReplyMsg *msg = NULL;

		msg =
		    ban_ip_reply_msg__unpack(&pa, data.size,
					     data.data);
		if (msg == NULL) {
			seclog(sec, LOG_INFO, "error unpacking auth ban ip reply\n");
			return ERR_BAD_COMMAND;
		}

		handle_sec_auth_ban_ip_reply(sec, msg);
		ban_ip_reply_msg__free_unpacked(msg, &pa);

		return 0;
	}
	case CMD_SECM_SESSION_OPEN:{
			SecmSessionOpenMsg *msg;

			msg =
			    secm_session_open_msg__unpack(&pa, data.size,
						      data.data);
			if (msg == NULL) {
				seclog(sec, LOG_INFO, "error unpacking session open\n");
				return ERR_BAD_COMMAND;
			}

			ret = handle_secm_session_open_cmd(sec, fd, msg);
			secm_session_open_msg__free_unpacked(msg, &pa);

			return ret;
		}
	case CMD_SECM_SESSION_CLOSE:{
			SecmSessionCloseMsg *msg;

			msg =
			    secm_session_close_msg__unpack(&pa, data.size,
						      data.data);
			if (msg == NULL) {
				seclog(sec, LOG_INFO, "error unpacking session close\n");
				return ERR_BAD_COMMAND;
			}

			ret = handle_secm_session_close_cmd(sec, fd, msg);
			secm_session_close_msg__free_unpacked(msg, &pa);

			return ret;
		}
	default:
		seclog(sec, LOG_WARNING, "unknown type 0x%.2x", cmd);
		return ERR_BAD_COMMAND;
	}

	return 0;
}

static void handle_alarm(int signo)
{
	need_maintainance = 1;
}

static void handle_sigterm(int signo)
{
	need_exit = 1;
}

static void send_stats_to_main(sec_mod_st *sec)
{
	int ret;
	time_t now = time(0);
	SecmStatsMsg msg = SECM_STATS_MSG__INIT;

	if (GETPCONFIG(sec)->stats_reset_time != 0 &&
	    now - sec->last_stats_reset > GETPCONFIG(sec)->stats_reset_time) {
		sec->auth_failures = 0;
		sec->avg_auth_time = 0;
		sec->max_auth_time = 0;
		sec->last_stats_reset = now;
	}

	msg.secmod_client_entries = sec_mod_client_db_elems(sec);
	msg.secmod_tlsdb_entries = sec->tls_db.entries;
	msg.secmod_auth_failures = sec->auth_failures;
	msg.secmod_avg_auth_time = sec->avg_auth_time;
	msg.secmod_max_auth_time = sec->max_auth_time;
	/* we only report the number of failures since last call */
	sec->auth_failures = 0;

	/* the following two are not resettable */
	msg.secmod_client_entries = sec_mod_client_db_elems(sec);
	msg.secmod_tlsdb_entries = sec->tls_db.entries;

	ret = send_msg(sec, sec->cmd_fd, CMD_SECM_STATS, &msg,
			(pack_size_func) secm_stats_msg__get_packed_size,
			(pack_func) secm_stats_msg__pack);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "error in sending statistics to main");
		return;
	}

	return;
}

static void reload_server(sec_mod_st *sec)
{
	vhost_cfg_st *vhost = NULL;

	seclog(sec, LOG_DEBUG, "reloading configuration");
	reload_cfg_file(sec, sec->vconfig, 1);
	load_keys(sec, 0);

	list_for_each(sec->vconfig, vhost, list) {
		sec_auth_init(vhost);
	}
	sup_config_init(sec);

	need_reload = 0;
}

static void check_other_work(sec_mod_st *sec)
{
	vhost_cfg_st *vhost = NULL;

	if (need_exit) {
		unsigned i;

		list_for_each(sec->vconfig, vhost, list) {
			for (i = 0; i < vhost->key_size; i++) {
				gnutls_privkey_deinit(vhost->key[i]);
				vhost->key[i] = NULL;
			}
			vhost->key_size = 0;
		}

		sec_mod_client_db_deinit(sec);
		tls_cache_deinit(&sec->tls_db);
		talloc_free(sec->config_pool);
		talloc_free(sec->sec_mod_pool);
		exit(0);
	}

	if (need_reload) {
		reload_server(sec);
	}

	if (need_maintainance) {
		seclog(sec, LOG_DEBUG, "performing maintenance");
		cleanup_client_entries(sec);
		expire_tls_sessions(sec);
		send_stats_to_main(sec);
		seclog(sec, LOG_DEBUG, "active sessions %d", 
			sec_mod_client_db_elems(sec));
		alarm(MAINTAINANCE_TIME);
		need_maintainance = 0;
	}
}

static
int serve_request_main(sec_mod_st *sec, int fd, uint8_t *buffer, unsigned buffer_size)
{
	int ret, e;
	uint8_t cmd;
	size_t length;
	void *pool = buffer;

	/* read request */
	ret = recv_msg_headers(fd, &cmd, MAIN_SEC_MOD_TIMEOUT);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "error receiving msg head from main");
		ret = ERR_BAD_COMMAND;
		goto leave;
	}

	length = ret;

	seclog(sec, LOG_DEBUG, "received request %s", cmd_request_to_str(cmd));
	if (cmd <= MIN_SECM_CMD || cmd >= MAX_SECM_CMD) {
		seclog(sec, LOG_ERR, "received invalid message from main of %u bytes (cmd: %u)\n",
		      (unsigned)length, (unsigned)cmd);
		return ERR_BAD_COMMAND;
	}

	if (length > buffer_size) {
		seclog(sec, LOG_ERR, "received too big message (%d)", (int)length);
		ret = ERR_BAD_COMMAND;
		goto leave;
	}

	/* read the body */
	ret = force_read_timeout(fd, buffer, length, MAIN_SEC_MOD_TIMEOUT);
	if (ret < 0) {
		e = errno;
		seclog(sec, LOG_ERR, "error receiving msg body of cmd %u with length %u: %s",
		       cmd, (unsigned)length, strerror(e));
		ret = ERR_BAD_COMMAND;
		goto leave;
	}

	ret = process_packet_from_main(pool, fd, sec, cmd, buffer, ret);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "error processing data for '%s' command (%d)", cmd_request_to_str(cmd), ret);
	}
	
 leave:
	return ret;
}

static
int serve_request_worker(sec_mod_st *sec, int cfd, pid_t pid, uint8_t *buffer, unsigned buffer_size)
{
	int ret, e;
	uint8_t cmd;
	size_t length;
	void *pool = buffer;

	/* read request */
	ret = recv_msg_headers(cfd, &cmd, MAX_WAIT_SECS);
	if (ret < 0) {
		seclog(sec, LOG_DEBUG, "error receiving msg head from worker");
		goto leave;
	}

	length = ret;

	if (length > buffer_size) {
		seclog(sec, LOG_INFO, "too big message (%d)", (int)length);
		ret = -1;
		goto leave;
	}

	/* read the body */
	ret = force_read_timeout(cfd, buffer, length, MAX_WAIT_SECS);
	if (ret < 0) {
		e = errno;
		seclog(sec, LOG_INFO, "error receiving msg body: %s",
		       strerror(e));
		ret = -1;
		goto leave;
	}

	ret = process_worker_packet(pool, cfd, pid, sec, cmd, buffer, ret);
	if (ret < 0) {
		seclog(sec, LOG_DEBUG, "error processing '%s' command (%d)", cmd_request_to_str(cmd), ret);
	}
	
 leave:
	return ret;
}

#define CHECK_LOOP_ERR(x) \
	if (force != 0) { GNUTLS_FATAL_ERR(x); } \
	else { if (ret < 0) { \
		seclog(sec, LOG_ERR, "could not reload key %s", vhost->perm_config.key[i]); \
		continue; } \
	}

static int load_keys(sec_mod_st *sec, unsigned force)
{
	unsigned i, need_reload;
	int ret;
	vhost_cfg_st *vhost = NULL;

	list_for_each_rev(sec->vconfig, vhost, list) {
		if (force == 0) {
			need_reload = 0;

			for (i = 0; i < vhost->perm_config.key_size; i++) {
				if (need_file_reload(vhost->perm_config.key[i], vhost->cert_last_access) != 0) {
					need_reload = 1;
					break;
				}
			}

			if (need_reload == 0)
				continue;
		}

		vhost->cert_last_access = time(0);

		ret = load_pins(GETPCONFIG(sec), &vhost->pins);
		if (ret < 0) {
			seclog(sec, LOG_ERR, "error loading PIN files");
			exit(1);
		}

		/* Reminder: the number of private keys or their filenames cannot be changed on reload
		 */
		if (vhost->key == NULL) {
			vhost->key_size = vhost->perm_config.key_size;
			vhost->key = talloc_zero_size(sec, sizeof(*vhost->key) * vhost->perm_config.key_size);
			if (vhost->key == NULL) {
				seclog(sec, LOG_ERR, "error in memory allocation");
				exit(1);
			}
		}

		/* read private keys */
		for (i = 0; i < vhost->key_size; i++) {
			gnutls_privkey_t p;

			ret = gnutls_privkey_init(&p);
			CHECK_LOOP_ERR(ret);

			/* load the private key */
			if (gnutls_url_is_supported(vhost->perm_config.key[i]) != 0) {
				gnutls_privkey_set_pin_function(p,
								pin_callback, &vhost->pins);
				ret =
				    gnutls_privkey_import_url(p,
							      vhost->perm_config.key[i], 0);
				CHECK_LOOP_ERR(ret);
			} else {
				gnutls_datum_t data;
				ret = gnutls_load_file(vhost->perm_config.key[i], &data);
				if (ret < 0) {
					seclog(sec, LOG_ERR, "error loading file '%s'",
					       vhost->perm_config.key[i]);
					CHECK_LOOP_ERR(ret);
				}

				ret =
				    gnutls_privkey_import_x509_raw(p, &data,
								   GNUTLS_X509_FMT_PEM,
								   NULL, 0);
				if (ret == GNUTLS_E_DECRYPTION_FAILED && vhost->pins.pin[0]) {
					ret =
					    gnutls_privkey_import_x509_raw(p, &data,
									   GNUTLS_X509_FMT_PEM,
									   vhost->pins.pin, 0);
				}
				CHECK_LOOP_ERR(ret);

				gnutls_free(data.data);
			}

			if (vhost->key[i] != NULL) {
				gnutls_privkey_deinit(vhost->key[i]);
			}
			vhost->key[i] = p;
		}
		seclog(sec, LOG_DEBUG, "%sloaded %d keys\n", PREFIX_VHOST(vhost), vhost->key_size);
	}
	return 0;
}

/* sec_mod_server:
 * @config: server configuration
 * @socket_file: the name of the socket
 * @cmd_fd: socket to exchange commands with main
 * @cmd_fd_sync: socket to received sync commands from main
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
 * byte[0-5]: length (uint32_t)
 * byte[5-total]: data (signature or decrypted data)
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
void sec_mod_server(void *main_pool, void *config_pool, struct list_head *vconfig,
		    const char *socket_file, int cmd_fd, int cmd_fd_sync)
{
	struct sockaddr_un sa;
	socklen_t sa_len;
	int cfd, ret, e, n;
	unsigned buffer_size;
	uid_t uid;
	uint8_t *buffer;
	int sd;
	sec_mod_st *sec;
	void *sec_mod_pool;
	vhost_cfg_st *vhost = NULL;
	fd_set rd_set;
	pid_t pid;
#ifdef HAVE_PSELECT
	struct timespec ts;
#else
	struct timeval ts;
#endif
	sigset_t emptyset, blockset;

#ifdef DEBUG_LEAKS
	talloc_enable_leak_report_full();
#endif
	sigemptyset(&blockset);
	sigemptyset(&emptyset);
	sigaddset(&blockset, SIGALRM);
	sigaddset(&blockset, SIGTERM);
	sigaddset(&blockset, SIGINT);
	sigaddset(&blockset, SIGHUP);

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

	sec->vconfig = vconfig;
	sec->config_pool = config_pool;
	sec->sec_mod_pool = sec_mod_pool;

	tls_cache_init(sec, &sec->tls_db);
	sup_config_init(sec);

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strlcpy(sa.sun_path, socket_file, sizeof(sa.sun_path));
	remove(socket_file);

#define SOCKET_FILE sa.sun_path

	/* we no longer need the main pool after this point. */
	talloc_free(main_pool);

	ocsignal(SIGHUP, SIG_IGN);
	ocsignal(SIGINT, handle_sigterm);
	ocsignal(SIGTERM, handle_sigterm);
	ocsignal(SIGALRM, handle_alarm);

	list_for_each(sec->vconfig, vhost, list) {
		sec_auth_init(vhost);
	}

	sec->cmd_fd = cmd_fd;
	sec->cmd_fd_sync = cmd_fd_sync;

	if (sec_mod_client_db_init(sec) == NULL) {
		seclog(sec, LOG_ERR, "error in client db initialization");
		exit(1);
	}

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		seclog(sec, LOG_ERR, "could not create socket '%s': %s", SOCKET_FILE,
		       strerror(e));
		exit(1);
	}
	set_cloexec_flag(sd, 1);

	umask(066);
	ret = bind(sd, (struct sockaddr *)&sa, SUN_LEN(&sa));
	if (ret == -1) {
		e = errno;
		seclog(sec, LOG_ERR, "could not bind socket '%s': %s", SOCKET_FILE,
		       strerror(e));
		exit(1);
	}

	ret = chown(SOCKET_FILE, GETPCONFIG(sec)->uid, GETPCONFIG(sec)->gid);
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

	ret = load_keys(sec, 1);
	if (ret < 0) {
		seclog(sec, LOG_ERR, "error loading private key files");
		exit(1);
	}

	sigprocmask(SIG_BLOCK, &blockset, &sig_default_set);
	alarm(MAINTAINANCE_TIME);
	seclog(sec, LOG_INFO, "sec-mod initialized (socket: %s)", SOCKET_FILE);


	for (;;) {
		check_other_work(sec);

		FD_ZERO(&rd_set);
		n = 0;

		FD_SET(cmd_fd, &rd_set);
		n = MAX(n, cmd_fd);

		FD_SET(cmd_fd_sync, &rd_set);
		n = MAX(n, cmd_fd_sync);

		FD_SET(sd, &rd_set);
		n = MAX(n, sd);

#ifdef HAVE_PSELECT
		ts.tv_nsec = 0;
		ts.tv_sec = 120;
		ret = pselect(n + 1, &rd_set, NULL, NULL, &ts, &emptyset);
#else
		ts.tv_usec = 0;
		ts.tv_sec = 120;
		sigprocmask(SIG_UNBLOCK, &blockset, NULL);
		ret = select(n + 1, &rd_set, NULL, NULL, &ts);
		sigprocmask(SIG_BLOCK, &blockset, NULL);
#endif
		if (ret == 0 || (ret == -1 && errno == EINTR))
			continue;

		if (ret < 0) {
			e = errno;
			seclog(sec, LOG_ERR, "Error in pselect(): %s",
			       strerror(e));
			exit(1);
		}

		/* we do a new allocation, to also use it as pool for the
		 * parsers to use */
		buffer_size = MAX_MSG_SIZE;
		buffer = talloc_size(sec, buffer_size);
		if (buffer == NULL) {
			seclog(sec, LOG_ERR, "error in memory allocation");
			exit(1);
		}

		/* we use two fds for communication with main. The synchronous is for
		 * ping-pong communication which each request is answered immediated. The
		 * async is for messages sent back and forth in no particular order */
		if (FD_ISSET(cmd_fd_sync, &rd_set)) {
			ret = serve_request_main(sec, cmd_fd_sync, buffer, buffer_size);
			if (ret < 0 && ret == ERR_BAD_COMMAND) {
				seclog(sec, LOG_ERR, "error processing sync command from main");
				exit(1);
			}
		}

		if (FD_ISSET(cmd_fd, &rd_set)) {
			ret = serve_request_main(sec, cmd_fd, buffer, buffer_size);
			if (ret < 0 && ret == ERR_BAD_COMMAND) {
				seclog(sec, LOG_ERR, "error processing async command from main");
				exit(1);
			}
		}
		
		if (FD_ISSET(sd, &rd_set)) {
			sa_len = sizeof(sa);
			cfd = accept(sd, (struct sockaddr *)&sa, &sa_len);
			if (cfd == -1) {
				e = errno;
				if (e != EINTR) {
					seclog(sec, LOG_DEBUG,
					       "sec-mod error accepting connection: %s",
					       strerror(e));
					goto cont;
				}
			}
			set_cloexec_flag (cfd, 1);

			/* do not allow unauthorized processes to issue commands
			 */
			ret = check_upeer_id("sec-mod", GETPCONFIG(sec)->debug, cfd,
					     GETPCONFIG(sec)->uid, GETPCONFIG(sec)->gid,
					     &uid, &pid);
			if (ret < 0) {
				seclog(sec, LOG_INFO, "rejected unauthorized connection");
			} else {
				memset(buffer, 0, buffer_size);
				serve_request_worker(sec, cfd, pid, buffer, buffer_size);
			}
			close(cfd);
		}
 cont:
		talloc_free(buffer);
#ifdef DEBUG_LEAKS
		talloc_report_full(sec, stderr);
#endif
	}
}
