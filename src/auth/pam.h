/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
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
#ifndef PAM_H
#define PAM_H

#include <config.h>
#include <sec-mod-auth.h>

#ifdef HAVE_PAM

#include <security/pam_appl.h>
#include <str.h>
#include <pcl.h>

extern const struct auth_mod_st pam_auth_funcs;

struct pam_ctx_st {
	char password[MAX_PASSWORD_SIZE];
	char username[MAX_USERNAME_SIZE];
	pam_handle_t * ph;
	struct pam_conv dc;
	coroutine_t cr;
	int cr_ret;
	unsigned changing; /* whether we are entering a new password */
	str_st msg;
	str_st prompt;
	unsigned sent_msg;
	struct pam_response *replies; /* for safety */
	unsigned state; /* PAM_S_ */
	unsigned passwd_counter;
	size_t prev_prompt_hash;
};

#endif

#endif
