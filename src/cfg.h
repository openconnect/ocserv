/*
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
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

#ifndef CFG_H
#define CFG_H
#define MAX_SUBOPTIONS 5

typedef struct subcfg_val_st {
	char *name;
	char *value;
} subcfg_val_st;

typedef struct gssapi_cfg_st {
	char *keytab;
	unsigned no_local_map;
} gssapi_cfg_st;

typedef struct radius_cfg_st {
	char *config;
	char *nas_identifier;
} radius_cfg_st;

typedef struct plain_cfg_st {
	char *passwd;
} plain_cfg_st;

typedef struct pam_cfg_st {
	int gid_min;
} pam_cfg_st;

#define CHECK_TRUE(str) (str != NULL && (c_strcasecmp(str, "true") == 0 || c_strcasecmp(str, "yes") == 0))?1:0

void *get_brackets_string1(void *pool, const char *str);
void *gssapi_get_brackets_string(struct perm_cfg_st *config, const char *str);
void *radius_get_brackets_string(struct perm_cfg_st *config, const char *str);
void *pam_get_brackets_string(struct perm_cfg_st *config, const char *str);
void *plain_get_brackets_string(struct perm_cfg_st *config, const char *str);

#endif
