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

#ifndef SNAPSHOT_H
#define SNAPSHOT_H

struct snapshot_t;
struct snapshot_iter_t;

/**
 * snapshot_init - initialize the file snapshot collection
 * @pool: talloc context
 * @snapshot: file snapshot created
 * @path: path in the filesystem
 */
int snapshot_init(void *pool, struct snapshot_t **snapshot, const char *path);

/**
 * snapshot_terminate - release the file snapshot collection
 * @snapshot: file snapshot collection
 */
void snapshot_terminate(struct snapshot_t *snapshot);

/**
 * snapshot_create - create a snapshot of a file and add it to the collection
 * @snapshot: file snapshot collection
 * @filename: file to snapshot
 * Note: Replaces any files in the collection with the same name.
 */
int snapshot_create(struct snapshot_t *snapshot, const char *filename);

/**
 * snapshot_entry_count - get a count of the entries
 * @snapshot: file snapshot collection
 */
size_t snapshot_entry_count(struct snapshot_t *snapshot);

/**
 * snapshot_first - start iterating over the snapshot entries
 * @snapshot: file snapshot collection
 * @iter: opaque iterator
 * @fd: fd found
 * @file_name: filename found
 * @return: 0 on success, non-zero on failure
 */
int snapshot_first(struct snapshot_t *snapshot, struct htable_iter *iter,
		   int *fd, const char **file_name);

/**
 * snapshot_first - continue iterating over the snapshot entries
 * @snapshot: file snapshot collection
 * @iter: opaque iterator
 * @fd: fd found
 * @file_name: filename found
 * @return: 0 on success, non-zero on failure
 */
int snapshot_next(struct snapshot_t *snapshot, struct htable_iter *iter,
		  int *fd, const char **file_name);

/**
 * snapshot_restore - put an entry back into the snapshot collection
 * @snapshot: file snapshot collection
 * @fd: fd to add
 * @file_name: filename to add
 */
int snapshot_restore_entry(struct snapshot_t *snapshot, int fd,
			   const char *file_name);

int snapshot_lookup_filename(struct snapshot_t *snapshot, const char *file_name,
			     char **snapshot_file_name);

#endif
