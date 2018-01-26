/*
 * Copyright (C) 2013, 2014 Nikos Mavrogiannopoulos
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vpn.h>
#include <tun.h>
#include <main.h>
#include <common.h>
#include <vpn.h>
#include <sec-mod-sup-config.h>
#include <sup-config/file.h>
#include <sup-config/radius.h>

void sup_config_init(sec_mod_st *sec)
{
	vhost_cfg_st *vhost = NULL;

	list_for_each(sec->vconfig, vhost, list) {
		if (vhost->perm_config.sup_config_type == SUP_CONFIG_FILE) {
			seclog(sec, LOG_INFO, "%sreading supplemental config from files", PREFIX_VHOST(vhost));
			vhost->config_module = &file_sup_config;
#ifdef HAVE_RADIUS
		} else if (vhost->perm_config.sup_config_type == SUP_CONFIG_RADIUS) {
			seclog(sec, LOG_INFO, "%sreading supplemental config from radius", PREFIX_VHOST(vhost));
			vhost->config_module = &radius_sup_config;
#endif
		}
	}
}

