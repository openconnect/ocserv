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
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <common.h>
#include <syslog.h>
#include <vpn.h>
#include <tlslib.h>
#include <sys/uio.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#define MAX_PIN_SIZE GNUTLS_PKCS11_MAX_PIN_LEN

struct pin_st {
	char pin[MAX_PIN_SIZE];
	char srk_pin[MAX_PIN_SIZE];
};

static
int pin_callback (void *user, int attempt, const char *token_url,
	const char *token_label, unsigned int flags, char *pin,
	size_t pin_max)
{
struct pin_st * ps = user;
int srk = 0;
const char* p;
unsigned len;

	if (flags & GNUTLS_PIN_FINAL_TRY) {
		syslog(LOG_ERR, "PIN callback: final try before locking; not attempting to unlock");
		return -1;
	}

	if (flags & GNUTLS_PIN_WRONG) {
		syslog(LOG_ERR, "PIN callback: wrong PIN was entered for '%s' (%s)", token_label, token_url);
		return -1;
	}

	if (ps->pin[0] == 0) {
		syslog(LOG_ERR, "PIN required for '%s' but pin-file was not set", token_label);
		return -1;
	}

	if (strcmp(token_url, "SRK") == 0 || strcmp(token_label, "SRK") == 0) {
		srk = 1;
		p = ps->srk_pin;
	} else {
		p = ps->pin;
	}

	if (srk != 0 && ps->srk_pin[0] == 0) {
		syslog(LOG_ERR, "PIN required for '%s' but srk-pin-file was not set", token_label);
		return -1;
	}
	
	len = strlen(p);
	if (len > pin_max-1) {
		syslog(LOG_ERR, "Too long PIN (%u chars)", len);
		return -1;
	}
	
	memcpy(pin, p, len);
	pin[len] = 0;
	
	return 0;
}

static
int load_pins(struct cfg_st* config, struct pin_st* s)
{
int fd, ret;

	s->srk_pin[0] = 0;
	s->pin[0] = 0;

	if (config->srk_pin_file != NULL) {
		fd = open(config->srk_pin_file, O_RDONLY);
		if (fd < 0) {
			syslog(LOG_ERR, "could not open SRK PIN file '%s'", config->srk_pin_file);
			return -1;
		}
	
		ret = read(fd, s->srk_pin, sizeof(s->srk_pin));
		close(fd);
		if (ret <= 1) {
			syslog(LOG_ERR, "could not read from PIN file '%s'", config->srk_pin_file);
			return -1;
		}
	
		if (s->srk_pin[ret-1] == '\n' || s->srk_pin[ret-1] == '\r')
			s->srk_pin[ret-1] = 0;
		s->srk_pin[ret] = 0;
	}

	if (config->pin_file != NULL) {
		fd = open(config->pin_file, O_RDONLY);
		if (fd < 0) {
			syslog(LOG_ERR, "could not open PIN file '%s'", config->pin_file);
			return -1;
		}
	
		ret = read(fd, s->pin, sizeof(s->pin));
		close(fd);
		if (ret <= 1) {
			syslog(LOG_ERR, "could not read from PIN file '%s'", config->pin_file);
			return -1;
		}
	
		if (s->pin[ret-1] == '\n' || s->pin[ret-1] == '\r')
			s->pin[ret-1] = 0;
		s->pin[ret] = 0;
	}
	
	return 0;
}

void
sec_mod_server(struct cfg_st* config, const char* socket_file)
{
struct sockaddr_un sa;
socklen_t sa_len;
int cfd, ret, e;
unsigned i, buffer_size, type;
gnutls_privkey_t *key;
uint8_t *buffer;
unsigned key_size = config->key_size;
struct pin_st pins;
gnutls_datum_t data, out;
uint16_t length;
struct iovec iov[2];
int sd;
int mask;

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

#ifdef HAVE_PKCS11
	ret = gnutls_pkcs11_reinit();
	if (ret < 0) {
	 	syslog(LOG_WARNING, "error in PKCS #11 reinitialization: %s", gnutls_strerror(ret));
	}
#endif

	buffer_size = 8*1024;
	buffer = malloc(buffer_size);
	if (buffer == NULL) {
	 	syslog(LOG_ERR, "error in memory allocation");
	 	exit(1);
	}	

	memset(&sa, 0, sizeof(sa));	
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", socket_file);
	remove(socket_file);

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		syslog(LOG_ERR, "could not create socket '%s': %s", socket_file, strerror(e));
		exit(1);
	}
	
	mask = umask(066);
	ret = bind(sd, (struct sockaddr *)&sa, SUN_LEN(&sa));
	if (ret == -1) {
		e = errno;
		syslog(LOG_ERR, "could not bind socket '%s': %s", socket_file, strerror(e));
		exit(1);
	}
	umask(mask);

	ret = chown(socket_file, config->uid, config->gid);
	if (ret == -1) {
		e = errno;
		syslog(LOG_ERR, "could not chown socket '%s': %s", socket_file, strerror(e));
	}

	ret = listen(sd, 1024);
	if (ret == -1) {
		e = errno;
		syslog(LOG_ERR, "could not listen to socket '%s': %s", socket_file, strerror(e));
		exit(1);
	}

	ret = load_pins(config, &pins);
	if (ret < 0) {
	 	syslog(LOG_ERR, "error loading PIN files");
	 	exit(1);
	}	
	
	key = malloc(sizeof(*key)*config->key_size);
	if (key == NULL) {
	 	syslog(LOG_ERR, "error in memory allocation");
	 	exit(1);
	}	

	/* read private keys */
	for (i=0;i<key_size;i++) {
		ret = gnutls_privkey_init(&key[i]);
		GNUTLS_FATAL_ERR(ret);

		/* load the private key */
		if (gnutls_url_is_supported(config->key[i]) != 0) {
			gnutls_privkey_set_pin_function (key[i], pin_callback, &pins);
			ret = gnutls_privkey_import_url(key[i], config->key[i], 0);
			GNUTLS_FATAL_ERR(ret);
		} else {
			ret = gnutls_load_file(config->key[i], &data);
			if (ret < 0) {
				syslog(LOG_ERR, "error loading file '%s'", config->key[i]);
				GNUTLS_FATAL_ERR(ret);
			}

			ret = gnutls_privkey_import_x509_raw(key[i], &data, GNUTLS_X509_FMT_PEM, NULL, 0);
			GNUTLS_FATAL_ERR(ret);

			gnutls_free(data.data);
		}
	}

	syslog(LOG_INFO, "sec-mod initialized (socket: %s)", socket_file);
	for (;;) {
		sa_len = sizeof(sa);
		cfd = accept(sd, (struct sockaddr *)&sa, &sa_len);
		if (cfd == -1) {
		 	e = errno;
		 	syslog(LOG_ERR, "error accepting sec-mod connection: %s", strerror(e));
		 	continue;
		}
		 
		 /* read request */
		ret = recv(cfd, buffer, buffer_size, 0);
		if (ret == 0)
			goto cont;
		else if (ret <= 2) {
		 	e = errno;
		 	syslog(LOG_ERR, "error receiving sec-mod data: %s", strerror(e));
		 	goto cont;
		}
		 
		/* calculate */
		i = buffer[0];
		type = buffer[1];

		if (i >= key_size) {
		 	syslog(LOG_ERR, "sec-mod received out-of-bounds key index");
			goto cont;
		}
		 
		data.data = &buffer[2];
		data.size = ret - 2;
		 
#if GNUTLS_VERSION_NUMBER >= 0x03010a
		if (type == 'S') {
		 	ret = gnutls_privkey_sign_raw_data(key[i], 0, &data, &out);
		} else 
#endif
		if (type == 'D') {
		 	ret = gnutls_privkey_decrypt_data(key[i], 0, &data, &out);
		} else {
		 	syslog(LOG_ERR, "unknown type 0x%.2x", type);
			goto cont;
		}
		
		if (ret < 0) {
		 	syslog(LOG_ERR, "sec-mod error in crypto operation: %s", gnutls_strerror(ret));
			goto cont;
		}
		 
		/* write reply */
		length = out.size;
		
		iov[0].iov_base = &length;
		iov[0].iov_len = 2;
		
		iov[1].iov_base = out.data;
		iov[1].iov_len = out.size;
		writev(cfd, iov, 2);

		gnutls_free(out.data);
cont:
		close(cfd);
	}
}

