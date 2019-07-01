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
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#ifndef _XOPEN_SOURCE
# define _XOPEN_SOURCE
#endif
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>	/* for random */
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#ifdef HAVE_CRYPT_H
  /* libcrypt in Fedora28 does not provide prototype
   * in unistd.h */
# include <crypt.h>
#endif

/* Gnulib portability files. */
#include <getpass.h>
#include <minmax.h>

#define DEFAULT_OCPASSWD "/etc/ocserv/ocpasswd"

static const char alphabet[] =
	"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./";

#define SALT_SIZE 16
static void
crypt_int(const char *fpasswd, const char *username, const char *groupname,
	  const char *passwd)
{
	uint8_t _salt[SALT_SIZE];
	char salt[SALT_SIZE+16];
	char *p, *cr_passwd;
	char *tmp_passwd;
	unsigned i;
	unsigned fpasswd_len = strlen(fpasswd);
	unsigned tmp_passwd_len;
	unsigned username_len = strlen(username);
	struct stat st;
	FILE *fd, *fd2;
	char *line = NULL;
	size_t line_size;
	ssize_t len, l;
	int ret;

	ret = gnutls_rnd(GNUTLS_RND_NONCE, _salt, sizeof(_salt));
	if (ret < 0) {
		fprintf(stderr, "Error generating nonce: %s\n",
			gnutls_strerror(ret));
		exit(1);
	}

#ifdef TRY_SHA2_CRYPT
	strcpy(salt, "$5$");
#else
	strcpy(salt, "$1$");
#endif
	p = salt + 3;

	for (i = 0; i < sizeof(_salt); i++) {
		*p = alphabet[_salt[i] % (sizeof(alphabet) - 1)];
		p++;
	}
	*p = '$';
	p++;
	*p = 0;
	p++;

	cr_passwd = crypt(passwd, salt);
	if (cr_passwd == NULL) { /* try MD5 */
		salt[1] = '1';
		cr_passwd = crypt(passwd, salt);
	}
	if (cr_passwd == NULL) {
		fprintf(stderr, "Error in crypt().\n");
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
		fprintf(stderr, "file '%s' is locked.\n", fpasswd);
		exit(1);
	}

	fd2 = fopen(tmp_passwd, "w");
	if (fd2 == NULL) {
		fprintf(stderr, "Cannot open '%s' for writing.\n", tmp_passwd);
		exit(1);
	}

	fd = fopen(fpasswd, "r");
	if (fd == NULL) {
		fprintf(fd2, "%s:%s:%s\n", username, groupname, cr_passwd);
	} else {
		int found = 0;
		while ((len = getline(&line, &line_size, fd)) > 0) {
			p = strchr(line, ':');
			if (p == NULL)
				continue;

			l = p-line;
			if (l == username_len && strncmp(line, username, l) == 0) {
				fprintf(fd2, "%s:%s:%s\n", username, groupname, cr_passwd);
				found = 1;
			} else {
				fwrite(line, 1, len, fd2);
			}
		}
		free(line);
		fclose(fd);

		if (found == 0)
			fprintf(fd2, "%s:%s:%s\n", username, groupname, cr_passwd);
	}

	fclose(fd2);

	ret = rename(tmp_passwd, fpasswd);
	if (ret < 0) {
		fprintf(stderr, "Cannot write to '%s'.\n", fpasswd);
		exit(1);
	}
	free(tmp_passwd);
}

static void
delete_user(const char *fpasswd, const char *username)
{
	FILE * fd, *fd2;
	char *tmp_passwd;
	char *line, *p;
	unsigned fpasswd_len = strlen(fpasswd);
	unsigned tmp_passwd_len;
	unsigned username_len = strlen(username);
	int ret;
	ssize_t len, l;
	size_t line_size;
	struct stat st;

	tmp_passwd_len = fpasswd_len + 5;
	tmp_passwd = malloc(tmp_passwd_len);

	snprintf(tmp_passwd, tmp_passwd_len, "%s.tmp", fpasswd);
	if (stat(tmp_passwd, &st) != -1) {
		fprintf(stderr, "file '%s' is locked.\n", fpasswd);
		exit(1);
	}

	fd = fopen(fpasswd, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open '%s' for reading.\n", fpasswd);
		exit(1);
	}

	fd2 = fopen(tmp_passwd, "w");
	if (fd2 == NULL) {
		fprintf(stderr, "Cannot open '%s' for writing.\n", tmp_passwd);
		exit(1);
	}

	line = NULL;
	while ((len = getline(&line, &line_size, fd)) > 0) {
		p = strchr(line, ':');
		if (p == NULL)
			continue;

		l = p-line;
		if (l == username_len && strncmp(line, username, l) == 0) {
			continue;
		} else {
			fwrite(line, 1, len, fd2);
		}
	}

	free(line);
	fclose(fd);
	fclose(fd2);

	ret = rename(tmp_passwd, fpasswd);
	if (ret == -1) {
		fprintf(stderr, "Cannot write to '%s'.\n", fpasswd);
		exit(1);
	}
	free(tmp_passwd);
}

static void
lock_user(const char *fpasswd, const char *username)
{
	FILE * fd, *fd2;
	char *tmp_passwd;
	char *line, *p;
	unsigned fpasswd_len = strlen(fpasswd);
	unsigned tmp_passwd_len;
	unsigned username_len = strlen(username);
	int ret;
	ssize_t len, l;
	size_t line_size;
	struct stat st;

	tmp_passwd_len = fpasswd_len + 5;
	tmp_passwd = malloc(tmp_passwd_len);

	snprintf(tmp_passwd, tmp_passwd_len, "%s.tmp", fpasswd);
	if (stat(tmp_passwd, &st) != -1) {
		fprintf(stderr, "file '%s' is locked.\n", fpasswd);
		exit(1);
	}

	fd = fopen(fpasswd, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open '%s' for reading.\n", fpasswd);
		exit(1);
	}

	fd2 = fopen(tmp_passwd, "w");
	if (fd2 == NULL) {
		fprintf(stderr, "Cannot open '%s' for writing.\n", tmp_passwd);
		exit(1);
	}

	line = NULL;
	while ((len = getline(&line, &line_size, fd)) > 0) {
		p = strchr(line, ':');
		if (p == NULL)
			continue;

		l = p-line;
		if (l == username_len && strncmp(line, username, l) == 0) {
			p = strchr(p+1, ':');
			if (p == NULL)
				continue;
			p++;

			if(*p != '!') {
				l = p-line;
				fwrite(line, 1, l, fd2);
				fputc('!', fd2);
				fwrite(p, 1, len-l, fd2);
			} else {
				fwrite(line, 1, len, fd2);
			}
		} else {
			fwrite(line, 1, len, fd2);
		}
	}

	free(line);
	fclose(fd);
	fclose(fd2);

	ret = rename(tmp_passwd, fpasswd);
	if (ret == -1) {
		fprintf(stderr, "Cannot write to '%s'.\n", fpasswd);
		exit(1);
	}
	free(tmp_passwd);
}

static void
unlock_user(const char *fpasswd, const char *username)
{
	FILE * fd, *fd2;
	char *tmp_passwd;
	char *line, *p;
	unsigned fpasswd_len = strlen(fpasswd);
	unsigned tmp_passwd_len;
	unsigned username_len = strlen(username);
	int ret;
	ssize_t len, l;
	size_t line_size;
	struct stat st;

	tmp_passwd_len = fpasswd_len + 5;
	tmp_passwd = malloc(tmp_passwd_len);

	snprintf(tmp_passwd, tmp_passwd_len, "%s.tmp", fpasswd);
	if (stat(tmp_passwd, &st) != -1) {
		fprintf(stderr, "file '%s' is locked.\n", fpasswd);
		exit(1);
	}

	fd = fopen(fpasswd, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open '%s' for reading.\n", fpasswd);
		exit(1);
	}

	fd2 = fopen(tmp_passwd, "w");
	if (fd2 == NULL) {
		fprintf(stderr, "Cannot open '%s' for writing.\n", tmp_passwd);
		exit(1);
	}

	line = NULL;
	while ((len = getline(&line, &line_size, fd)) > 0) {
		p = strchr(line, ':');
		if (p == NULL)
			continue;

		l = p-line;
		if (l == username_len && strncmp(line, username, l) == 0) {
			p = strchr(p+1, ':');
			if (p == NULL)
				continue;
			p++;

			l = p-line;
			fwrite(line, 1, l, fd2);

			if (*p=='!') p++;
			l = p-line;
			fwrite(p, 1, len-l, fd2);
		} else {
			fwrite(line, 1, len, fd2);
		}
	}

	free(line);
	fclose(fd);
	fclose(fd2);

	ret = rename(tmp_passwd, fpasswd);
	if (ret == -1) {
		fprintf(stderr, "Cannot write to '%s'.\n", fpasswd);
		exit(1);
	}
	free(tmp_passwd);
}

static const struct option long_options[] = {
	{"passwd", 1, 0, 'c'},
	{"groupname", 1, 0, 'g'},
	{"delete", 0, 0, 'd'},
	{"lock", 0, 0, 'l'},
	{"unlock", 0, 0, 'u'},
	{"help", 0, 0, 'h'},
	{"version", 0, 0, 'v'},
	{NULL, 0, 0, 0}
};

static
void usage(void)
{
	fprintf(stderr, "ocpasswd - OpenConnect server password utility\n");
	fprintf(stderr, "Usage:  ocpasswd [ -<flag> [<val>] | --<name>[{=| }<val>] ]... [username]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "   -c, --passwd=file          Password file\n");
	fprintf(stderr, "   -g, --groupname=str        User's group name\n");
	fprintf(stderr, "   -d, --delete               Delete user\n");
	fprintf(stderr, "   -l, --lock                 Lock user\n");
	fprintf(stderr, "   -u, --unlock               Unlock user\n");
	fprintf(stderr, "   -v, --version              output version information and exit\n");
	fprintf(stderr, "   -h, --help                 display extended usage information and exit\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options are specified by doubled hyphens and their name or by a single\n");
	fprintf(stderr, "hyphen and the flag character.\n\n");
	fprintf(stderr, "This program is openconnect password (ocpasswd) utility.  It allows the\n");
	fprintf(stderr, "generation and handling of a 'plain' password file used by ocserv.\n\n");
	fprintf(stderr, "Please send bug reports to:  "PACKAGE_BUGREPORT"\n");
}

static
void version(void)
{
	fprintf(stderr, "ocpasswd - "VERSION"\n");
	fprintf(stderr, "Copyright (C) 2013-2017 Nikos Mavrogiannopoulos, all rights reserved.\n");
	fprintf(stderr, "This is free software. It is licensed for use, modification and\n");
	fprintf(stderr, "redistribution under the terms of the GNU General Public License,\n");
	fprintf(stderr, "version 2 <http://gnu.org/licenses/gpl.html>\n\n");
	fprintf(stderr, "Please send bug reports to:  "PACKAGE_BUGREPORT"\n");
}

#define FLAG_DELETE 1
#define FLAG_LOCK (1<<1)
#define FLAG_UNLOCK (1<<2)

int main(int argc, char **argv)
{
	int ret, c;
	const char *username = NULL;
	char *groupname = NULL, *fpasswd = NULL;
	char* passwd = NULL;
	unsigned free_passwd = 0;
	size_t l, i;
	unsigned flags = 0;

	if ((ret = gnutls_global_init()) < 0) {
		fprintf(stderr, "global_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	umask(066);

	while (1) {
		c = getopt_long(argc, argv, "c:g:dluvh", long_options, NULL);
		if (c == -1)
			break;

		switch(c) {
			case 'c':
				if (fpasswd) {
					fprintf(stderr, "-c option cannot be specified multiple time\n");
					exit(1);
				}
				fpasswd = strdup(optarg);
				break;
			case 'g':
				if (groupname) {
					fprintf(stderr, "-g option cannot be specified multiple time\n");
					exit(1);
				}
				groupname = strdup(optarg);
				break;
			case 'd':
				if (flags) {
					usage();
					exit(1);
				}
				flags |= FLAG_DELETE;
				break;
			case 'u':
				if (flags) {
					usage();
					exit(1);
				}
				flags |= FLAG_UNLOCK;
				break;
			case 'l':
				if (flags) {
					usage();
					exit(1);
				}
				flags |= FLAG_LOCK;
				break;
			case 'h':
				usage();
				exit(0);
			case 'v':
				version();
				exit(0);
		}
	}

	if (optind < argc && argc-optind == 1) {
		username = argv[optind++];
	} else {
		usage();
		exit(1);
	}

	if (!groupname)
		groupname = strdup("*");
	if (!fpasswd)
		fpasswd = strdup(DEFAULT_OCPASSWD);

	if (flags & FLAG_LOCK) {
		lock_user(fpasswd, username);
	} else if (flags & FLAG_UNLOCK) {
		unlock_user(fpasswd, username);
	} else if (flags & FLAG_DELETE) {
		delete_user(fpasswd, username);
	} else { /* set password */

		if (isatty(STDIN_FILENO)) {
			char* p2;

			passwd = getpass("Enter password: ");
			if (passwd == NULL) {
				fprintf(stderr, "Please specify a password\n");
				exit(1);
			}


			p2 = strdup(passwd);
			passwd = getpass("Re-enter password: ");
			if (passwd == NULL) {
				fprintf(stderr, "Please specify a password\n");
				exit(1);
			}

			if (p2 == NULL || strcmp(passwd, p2) != 0) {
				fprintf(stderr, "Passwords do not match\n");
				exit(1);
			}
			free(p2);
		} else {
			passwd = NULL;
			l = getline(&passwd, &i, stdin);
			if (l <= 1) {
				fprintf(stderr, "Please specify a password\n");
				exit(1);
			}

			free_passwd = 1;
			if (passwd[l-1] == '\n')
				passwd[l-1] = 0;
		}

		crypt_int(fpasswd, username, groupname, passwd);
		if (free_passwd)
			free(passwd);
	}

	free(fpasswd);
	free(groupname);
	gnutls_global_deinit();
	return 0;
}

