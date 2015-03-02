/*
 * Copyright (C) 2014 Red Hat
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
#ifndef SUP_CONFIG_H
# define SUP_CONFIG_H

#include <sec-mod.h>

#define SUP_CONFIG_FILE 1
#define SUP_CONFIG_RADIUS 2

/* The get_sup_config() should read any additional configuration for
 * proc->username/proc->groupname and save it in proc->config.
 */
struct config_mod_st {
	int (*get_sup_config)(struct cfg_st *perm_config, client_entry_st *entry,
	                      SecAuthSessionReplyMsg *msg, void *pool);
};

void sup_config_init(sec_mod_st *sec);

#endif
