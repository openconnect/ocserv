/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2016 Red Hat, Inc.
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <sys/resource.h>

#include <system.h>
#include "setproctitle.h"
#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#endif

#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif
#include <main.h>
#include <worker.h>
#include <base64-helper.h>
#include <snapshot.h>
#include <isolate.h>

#ifdef HAVE_GSSAPI
#include <libtasn1.h>

extern const ASN1_ARRAY_TYPE kkdcp_asn1_tab[];
ASN1_TYPE _kkdcp_pkix1_asn = ASN1_TYPE_EMPTY;
#endif

extern struct snapshot_t *config_snapshot;

int syslog_open = 0;
sigset_t sig_default_set;
static unsigned allow_broken_clients = 0;

static int set_ws_from_env(worker_st * ws);

extern char secmod_socket_file_name_socket_file[_POSIX_PATH_MAX];

int main(int argc, char **argv)
{
	int ret, flags;
	void *worker_pool;
	void *main_pool, *config_pool;
	main_server_st *s;
	worker_st *ws;
	char *str;

#ifdef DEBUG_LEAKS
	talloc_enable_leak_report_full();
#endif

	if (!getenv(OCSERV_ENV_WORKER_STARTUP_MSG)) {
		fprintf(stderr,
			"This application is part of ocserv and should not be run in isolation\n");
		exit(1);
	}

	/* main pool */
	main_pool = talloc_init("main");
	if (main_pool == NULL) {
		fprintf(stderr, "talloc init error\n");
		exit(1);
	}

	config_pool = talloc_init("config");
	if (config_pool == NULL) {
		fprintf(stderr, "talloc init error\n");
		exit(1);
	}

	if (snapshot_init(config_pool, &config_snapshot, "/tmp/ocserv_") < 0) {
		fprintf(stderr, "failed to init snapshot");
		exit(-1);
	}

	s = talloc_zero(main_pool, main_server_st);
	if (s == NULL) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}
	s->main_pool = main_pool;
	s->config_pool = config_pool;
	s->stats.start_time = s->stats.last_reset = time(0);
	s->top_fd = -1;
	s->ctl_fd = -1;

	worker_pool = talloc_init("worker");
	if (worker_pool == NULL) {
		fprintf(stderr, "talloc init error\n");
		exit(1);
	}

	s->ws = talloc_zero(worker_pool, worker_st);
	ws = s->ws;

	if (ws == NULL) {
		fprintf(stderr, "talloc init error\n");
		exit(1);
	}

	if (!set_ws_from_env(ws)) {
		return 1;
	}

	restore_secmod_socket_file_name(ws->secmod_addr.sun_path);

	str = getenv("OCSERV_ALLOW_BROKEN_CLIENTS");
	if (str && str[0] == '1' && str[1] == 0)
		allow_broken_clients = 1;

	sigemptyset(&sig_default_set);

	ocsignal(SIGPIPE, SIG_IGN);

	/* Initialize GnuTLS */
	tls_global_init();

	/* load configuration */
	s->vconfig = talloc_zero(config_pool, struct list_head);
	if (s->vconfig == NULL) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}
	list_head_init(s->vconfig);

	ret = cmd_parser(config_pool, argc, argv, s->vconfig, true);
	if (ret < 0) {
		fprintf(stderr, "Error in arguments\n");
		exit(1);
	}

	snapshot_terminate(config_snapshot);
	config_snapshot = NULL;

	flags = LOG_PID | LOG_NDELAY;
#ifdef LOG_PERROR
	if (GETPCONFIG(s)->debug != 0)
		flags |= LOG_PERROR;
#endif
	openlog("ocserv", flags, LOG_DAEMON);
	syslog_open = 1;
#ifdef HAVE_LIBWRAP
	allow_severity = LOG_DAEMON | LOG_INFO;
	deny_severity = LOG_DAEMON | LOG_WARNING;
#endif

#ifdef HAVE_GSSAPI
	/* Initialize kkdcp structures */
	ret = asn1_array2tree(kkdcp_asn1_tab, &_kkdcp_pkix1_asn, NULL);
	if (ret != ASN1_SUCCESS) {
		mslog(s, NULL, LOG_ERR, "KKDCP ASN.1 initialization error");
		exit(1);
	}
#endif

	init_fd_limits_default(s);

	sigprocmask(SIG_SETMASK, &sig_default_set, NULL);

	setproctitle(PACKAGE_NAME "-worker");
	kill_on_parent_kill(SIGTERM);

	ws->main_pool = s->main_pool;
	ws->vconfig = s->vconfig;

	ws->tun_fd = -1;
	DTLS_ACTIVE(ws)->dtls_tptr.fd = -1;
	DTLS_INACTIVE(ws)->dtls_tptr.fd = -1;

	/* Drop privileges after this point */
	drop_privileges(s);

	vpn_server(ws);

	return 0;
}

extern char **pam_auth_group_list;
extern char **gssapi_auth_group_list;
extern char **plain_auth_group_list;
extern unsigned pam_auth_group_list_size;
extern unsigned gssapi_auth_group_list_size;
extern unsigned plain_auth_group_list_size;

static int clone_array(void *pool, char **input_array, size_t input_array_size,
		       char ***output_array)
{
	int ret = 0;
	int index;
	char **array = talloc_zero_array(pool, char *, input_array_size);
	if (array == NULL) {
		goto cleanup;
	}

	for (index = 0; index < input_array_size; index++) {
		array[index] = talloc_strdup(pool, input_array[index]);
		if (array[index] == NULL) {
			goto cleanup;
		}
	}

	*output_array = array;
	array = NULL;
	ret = 1;
 cleanup:
	if (array != NULL) {
		for (index = 0; index < input_array_size; index++) {
			if (array[index] != NULL) {
				talloc_free(array[index]);
			}
		}
		talloc_free(array);
	}
	return ret;
}

static int set_ws_from_env(worker_st * ws)
{
	PROTOBUF_ALLOCATOR(pa, ws);
	WorkerStartupMsg *msg = NULL;
	const char *string_buffer = getenv(OCSERV_ENV_WORKER_STARTUP_MSG);
	size_t string_size;
	size_t msg_size;
	uint8_t *msg_buffer = NULL;
	int ret = 0;
	size_t index;

	if (string_buffer == NULL) {
		fprintf(stderr, "This application must be called from ocserv (no env variable set)\n");
		goto cleanup;
	}

	string_size = strlen(string_buffer);

	if (!oc_base64_decode_alloc
	    (ws, string_buffer, string_size, (char **)&msg_buffer, &msg_size)) {
		fprintf(stderr, "oc_base64_decode_alloc failed\n");
		goto cleanup;
	}

	msg = worker_startup_msg__unpack(&pa, msg_size, msg_buffer);
	if (!msg) {
		fprintf(stderr, "worker_startup_msg__unpack failed\n");
		goto cleanup;
	}

	if (msg->secmod_addr.len > sizeof(ws->secmod_addr)) {
		fprintf(stderr, "msg->secmod_addr.len too large\n");
		goto cleanup;
	}
	if (msg->remote_addr.len > sizeof(ws->remote_addr)) {
		fprintf(stderr, "msg->remote_addr.len too large\n");
		goto cleanup;
	}
	if (msg->our_addr.len > sizeof(ws->our_addr)) {
		fprintf(stderr, "msg->our_addr.len too large\n");
		goto cleanup;
	}
	if (msg->sec_auth_init_hmac.len > sizeof(ws->sec_auth_init_hmac)) {
		fprintf(stderr, "msg->sec_auth_init_hmac.len too large\n");
		goto cleanup;
	}

	ws->secmod_addr_len = msg->secmod_addr.len;
	memcpy(&ws->secmod_addr, msg->secmod_addr.data, msg->secmod_addr.len);

	ws->cmd_fd = msg->cmd_fd;
	ws->conn_fd = msg->conn_fd;
	ws->conn_type = (sock_type_t) msg->conn_type;
	ws->session_start_time = msg->session_start_time;
	ws->remote_addr_len = msg->remote_addr.len;
	memcpy(&ws->remote_addr, msg->remote_addr.data, msg->remote_addr.len);
	if (msg->our_addr.data != NULL)
		memcpy(&ws->our_addr, msg->our_addr.data, msg->our_addr.len);

	memcpy((void *)ws->sec_auth_init_hmac, msg->sec_auth_init_hmac.data,
	       msg->sec_auth_init_hmac.len);

	strlcpy(ws->remote_ip_str, msg->remote_ip_str,
		sizeof(ws->remote_ip_str));
	strlcpy(ws->our_ip_str, msg->our_ip_str, sizeof(ws->our_ip_str));

	for (index = 0; index < msg->n_snapshot_entries; index++) {
		int fd = msg->snapshot_entries[index]->file_descriptor;
		const char *file_name = msg->snapshot_entries[index]->file_name;
		if (snapshot_restore_entry(config_snapshot, fd, file_name) != 0)
			goto cleanup;
	}

	if (!clone_array
	    (ws, msg->pam_auth_group_list, msg->n_pam_auth_group_list,
	     &pam_auth_group_list))
		goto cleanup;
	pam_auth_group_list_size = (unsigned)msg->n_pam_auth_group_list;

	if (!clone_array
	    (ws, msg->plain_auth_group_list, msg->n_plain_auth_group_list,
	     &plain_auth_group_list))
		goto cleanup;
	plain_auth_group_list_size = (unsigned)msg->n_plain_auth_group_list;

	if (!clone_array
	    (ws, msg->gssapi_auth_group_list, msg->n_gssapi_auth_group_list,
	     &gssapi_auth_group_list))
		goto cleanup;
	gssapi_auth_group_list_size = (unsigned)msg->n_gssapi_auth_group_list;

	ret = 1;

 cleanup:
	if (msg_buffer)
		talloc_free(msg_buffer);

	if (msg)
		worker_startup_msg__free_unpacked(msg, &pa);

	return ret;
}
