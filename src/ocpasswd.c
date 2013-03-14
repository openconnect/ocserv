/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gnutls/crypto.h>	/* for random */
#include <sys/types.h>
#include <sys/stat.h>

/* Gnulib portability files. */
#include <getpass.h>
#include <minmax.h>
#include <version-etc.h>

static const char *alphabet[] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static void
crypt_int(const char *fpasswd, const char *username, const char *groupname,
	  const char *passwd)
{
	uint8_t _salt[8];
	char salt[16];
	char *p, *cr_passwd;
	char *tmp_passwd;
	unsigned i;
	unsigned fpasswd_len = strlen(fpasswd);
	unsigned tpm_passwd_len;
	unsigned username_len = strlen(username);
	struct stat st;
	FILE *fd, *fd2;
	char *line = NULL;
	size_t line_size, len;

	ret = _gnutls_rnd(GNUTLS_RND_NONCE, _salt, 8);
	if (ret < 0) {
		fprintf(stderr, "Error generating nonce: %s\n",
			gnutls_strerror(ret));
		exit(1);
	}

	p = salt;
	p += snprintf(salt, sizeof(salt), "$1$");

	for (i = 0; i < 8; i++) {
		*p = alphabet[_salt[i] % (sizeof(alphabet) - 1)];
		p++;
	}
	*p = '$';
	p++;
	*p = 0;
	p++;

	cr_passwd = crypt(passwd, salt);
	if (cr_passwd == NULL) {
		fprintf(stderr, "Error in crypt()\n");
		exit(1);
	}

	tmp_passwd_len = fpasswd_len + 5;
	tmp_passwd = malloc(tmp_passwd_len);
	if (tmp_passwd == NULL) {
		fprintf(stderr, "memory error\n");
		exit(1);
	}

	snprintf(tmp_passwd, tmp_passwd_len, "%s.tmp", fpasswd);
	if (stat(tmp_passwd, &st) != -1) {
		fprintf(stderr, "file '%s' is locked\n", fpasswd);
		return -1;
	}

	fd = fopen(fpasswd, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open '%s' for write\n", dst);
		return -1;
	}

	fd2 = fopen(tmp_passwd, "w");
	if (fd2 == NULL) {
		/* empty file */
		fclose(fd);
		return 0;
	}

	while ((len = getline(&line, &line_size, fd)) > 0) {
		p = strchr(line, ':');
		if (p == NULL)
			continue;

		if (strncmp(line, username, MAX(username_len, (unsigned)(p-line))) == 0) {
			fprintf(fd2, "%s:%s:%s\n", username, groupname, cr_passwd);
		} else {
			fwrite(line, 1, len, fd2);
		}
	}

	free(line);
	fclose(fd);
	fclose(fd2);

	rename(tmp_passwd, fpasswd);
}

int main(int argc, char **argv)
{
	int ret;
	const char *username, *groupname, *fpasswd;

	if ((ret = gnutls_global_init()) < 0) {
		fprintf(stderr, "global_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	umask(066);

	optct = optionProcess(&ocpasswdOptions, argc, argv);
	argc -= optct;
	argv += optct;

	if (HAVE_OPT(PASSWD))
		fpasswd = OPT_ARG(PASSWD);
	else {
		fprintf(stderr, "passwd was not specified\n");
		exit(1);
	}

	if (HAVE_OPT(USERNAME))
		username = OPT_ARG(USERNAME);
	else {
		fprintf(stderr, "Please specify a user\n");
		return -1;
	}

	if (HAVE_OPT(GROUPNAME))
		groupname = OPT_ARG(GROUPNAME);
	else {
		groupname = "*";
	}

	passwd = getpass("Enter password: ");
	if (passwd == NULL) {
		fprintf(stderr, "Please specify a password\n");
		return -1;
	}

	return crypt_int(fpasswd, username, passwd);
}

