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
#ifndef COMMON_CONFIG_H
# define COMMON_CONFIG_H

#include <vpn.h>

int add_multi_line_val(void *pool, const char *name, char ***s_name, size_t *num,
	 	       tOptionValue const *pov,
		       const tOptionValue *val);

#endif
