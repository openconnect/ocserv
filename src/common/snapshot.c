/*
 * Copyright (C) 2020 Microsoft Corporation
 *
 * Author: Alan Jowett
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <talloc.h>
#include <sys/stat.h>
#include <common/common.h>

#include <ccan/htable/htable.h>
#include <ccan/hash/hash.h>

#include <snapshot.h>

#define ERRSTR "error: "
#define WARNSTR "warning: "
#define NOTESTR "note: "

typedef struct snapshot_t {
	struct htable ht;
	void *pool;
	const char *tmp_filename_template;
} snapshot_t;

typedef struct snapshot_entry_t {
	uint32_t fd;
	const char name[];
} snapshot_entry_t;

typedef struct htable_iter snapshot_iter_t;

static size_t snapshot_hash_filename(const char *file_name)
{
	return hash64(file_name, strlen(file_name), 0);
}

static size_t snapshot_rehash(const void *elem, void *priv)
{
	snapshot_entry_t *entry = (snapshot_entry_t *) elem;
	return snapshot_hash_filename(entry->name);
}

static snapshot_entry_t *snapshot_find(struct snapshot_t *snapshot,
				       const char *filename)
{
	struct htable_iter iter;
	size_t hash = snapshot_hash_filename(filename);
	snapshot_entry_t *entry = htable_firstval(&snapshot->ht, &iter, hash);
	while (entry != NULL) {
		if (strcmp(entry->name, filename) == 0) {
			break;
		}
		entry = htable_nextval(&snapshot->ht, &iter, hash);
	}
	return entry;
}

static int snapshot_file_name_from_fd(int fd, char *file_name,
				      size_t file_name_length)
{
	int ret = snprintf(file_name, file_name_length, "/proc/self/fd/%d", fd);
	if (ret >= file_name_length) {
		return -1;
	} else {
		return 0;
	}
}

static int snapshot_add_entry(snapshot_t * snapshot, const char *filename,
			      int fd)
{
	int retval = -1;
	snapshot_entry_t *entry = NULL;
	size_t file_name_length = strlen(filename) + 1;
	entry =
	    (snapshot_entry_t *) talloc_zero_array(snapshot->pool, char,
						   sizeof(uint32_t) +
						   file_name_length);
	if (entry == NULL) 
		goto cleanup;

	entry->fd = fd;
	strlcpy((char *)entry->name, filename, file_name_length);

	if (!htable_add
	    (&snapshot->ht, snapshot_hash_filename(entry->name), entry)) 
		goto cleanup;

	entry = NULL;
	retval = 0;
 cleanup:
	if (entry) 
		talloc_free(entry);

	return retval;
}

static int talloc_clear_htable(snapshot_t *s)
{
	htable_clear(&s->ht);
	return 0;
}

int snapshot_init(void *pool, struct snapshot_t **snapshot, const char *prefix)
{
	snapshot_t *new_snapshot = NULL;
	size_t tmp_filename_template_length = strlen(prefix) + 7;

	new_snapshot = talloc_zero(pool, snapshot_t);
	if (new_snapshot == NULL) 
		goto cleanup;

	new_snapshot->pool = pool;

	new_snapshot->tmp_filename_template =
	    talloc_array(pool, char, tmp_filename_template_length);

	if (snprintf
	    ((char *)new_snapshot->tmp_filename_template,
	     tmp_filename_template_length, "%sXXXXXX",
	     prefix) >= tmp_filename_template_length) 
		goto cleanup;

	htable_init(&new_snapshot->ht, snapshot_rehash, new_snapshot);
	talloc_set_destructor(new_snapshot, talloc_clear_htable);

	*snapshot = new_snapshot;
	new_snapshot = NULL;
 cleanup:
	if (new_snapshot != NULL) {
		if (new_snapshot->tmp_filename_template != NULL) 
			talloc_free((char *)new_snapshot->
				    tmp_filename_template);
		talloc_free(new_snapshot);
	}

	if ((*snapshot) != NULL) {
		return 0;
	} else {
		return -1;
	}
}

void snapshot_terminate(struct snapshot_t *snapshot)
{
	struct htable_iter iter;
	snapshot_entry_t *entry = htable_first(&snapshot->ht, &iter);
	while (entry != NULL) {
		htable_delval(&snapshot->ht, &iter);
		close(entry->fd);
		talloc_free(entry);
		entry = htable_next(&snapshot->ht, &iter);
	}
}

int snapshot_create(struct snapshot_t *snapshot, const char *filename)
{
	int ret = -1;
	char buffer[4096];
	char tmp_file_name[_POSIX_PATH_MAX];
	int fd_in = -1;
	int fd_out = -1;
	snapshot_entry_t *entry = NULL;

	if (filename == NULL) 
		return 0;

	strlcpy(tmp_file_name, snapshot->tmp_filename_template,
		_POSIX_PATH_MAX);

	fd_in = open(filename, O_RDONLY);
	if (fd_in == -1) {
		fprintf(stderr, ERRSTR "cannot open file %s\n", filename);
		goto cleanup;
	}

	umask(006);
	fd_out = mkstemp(tmp_file_name);
	if (fd_out == -1) {
		int err = errno;
		fprintf(stderr, ERRSTR "cannot create temp file '%s' : %s\n",
			tmp_file_name, strerror(err));
		goto cleanup;
	}
	// After opening the output file, unlink it to make it anonymous
	unlink(tmp_file_name);

	for (;;) {
		int byteRead = read(fd_in, buffer, sizeof(buffer));
		int bytesWritten;
		if (byteRead == 0) {
			break;
		} else if (byteRead == -1) {
			int err = errno;
			fprintf(stderr, ERRSTR " reading %s failed %s\n",
				filename, strerror(err));
			goto cleanup;
		} else {
			bytesWritten = write(fd_out, buffer, byteRead);
			if (bytesWritten != byteRead) {
				int err = errno;
				fprintf(stderr,
					ERRSTR " writing %s failed %s\n",
					tmp_file_name, strerror(err));
				goto cleanup;
			}
		}
	}

	lseek(fd_out, 0, SEEK_SET);

	close(fd_in);
	fd_in = -1;

	entry = snapshot_find(snapshot, filename);
	if (entry != NULL) {
		close(entry->fd);
		entry->fd = fd_out;
	} else {
		if (snapshot_add_entry(snapshot, filename, fd_out) != 0) 
			goto cleanup;
	}

	fd_out = -1;
	ret = 0;
	entry = NULL;

 cleanup:
	if (fd_in != -1)
		close(fd_in);

	if (fd_out != -1)
		close(fd_out);

	return ret;
}

int snapshot_first(struct snapshot_t *snapshot, struct htable_iter *iter,
		   int *fd, const char **file_name)
{
	snapshot_entry_t *entry = htable_first(&snapshot->ht, iter);
	if (entry == NULL) {
		return -1;
	} else {
		*fd = entry->fd;
		*file_name = entry->name;
		return 0;
	}
}

int snapshot_next(struct snapshot_t *snapshot, struct htable_iter *iter,
		  int *fd, const char **file_name)
{
	snapshot_entry_t *entry = htable_next(&snapshot->ht, iter);
	if (entry == NULL) {
		return -1;
	} else {
		*fd = entry->fd;
		*file_name = entry->name;
		return 0;
	}
}

int snapshot_restore_entry(struct snapshot_t *snapshot, int fd,
			   const char *file_name)
{
	int ret = snapshot_add_entry(snapshot, file_name, fd);
	if (ret < 0) 
		return ret;

	return 0;
}

size_t snapshot_entry_count(struct snapshot_t * snapshot)
{
	struct htable_iter iter;
	size_t count = 0;
	snapshot_entry_t *entry = htable_first(&snapshot->ht, &iter);

	while (entry != NULL) {
		entry = htable_next(&snapshot->ht, &iter);
		count++;
	}

	return count;
}

int snapshot_lookup_filename(struct snapshot_t *snapshot, const char *file_name,
			     char **snapshot_file_name)
{
	int ret = -1;
	char fd_path[128];
	char *new_file_name = NULL;
	snapshot_entry_t *entry = snapshot_find(snapshot, file_name);
	if (entry == NULL) 
		goto cleanup;

	if (snapshot_file_name_from_fd(entry->fd, fd_path, sizeof(fd_path)) < 0)
		goto cleanup;

	new_file_name = talloc_strdup(snapshot->pool, fd_path);
	if (new_file_name == NULL) 
		goto cleanup;

	*snapshot_file_name = new_file_name;
	new_file_name = NULL;

	ret = 0;

 cleanup:
	if (new_file_name != NULL) 
		talloc_free(new_file_name);

	return ret;
}
