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

#include <main.h>

/* The get_sup_config() should read any additional configuration for
 * proc->username/proc->groupname and save it in proc->config.
 */
struct config_mod_st {
	int (*get_sup_config)(struct cfg_st *global_config, struct proc_st *proc);
	void (*clear_sup_config)(struct group_cfg_st *out);
};

void sup_config_init(main_server_st *s);

#endif
