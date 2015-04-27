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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <vpn.h>
#include "pam.h"
#include <sec-mod-acct.h>

#ifdef HAVE_PAM

#include <security/pam_appl.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <pcl.h>
#include <str.h>
#include "auth/pam.h"

static int pam_acct_open_session(unsigned auth_method, void *ctx, const struct common_auth_info_st *ai, const void *sid, unsigned sid_size)
{
struct pam_ctx_st * pctx = ctx;
int pret;

	if (auth_method != AUTH_TYPE_PAM) {
		syslog(LOG_AUTH, "PAM-acct: pam_open_session cannot be combined with this authentication method (%x)", auth_method);
		return -1;
	}

	if (pctx->cr != NULL) {
		co_delete(pctx->cr);
		pctx->cr = NULL;
	}

	pret = pam_open_session(pctx->ph, PAM_SILENT);
	if (pret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "PAM-acct: pam_open_session: %s", pam_strerror(pctx->ph, pret));
		return -1;
	}

	return 0;
}

static void pam_acct_close_session(unsigned auth_method, void *ctx, const struct common_auth_info_st *ai, stats_st *stats, unsigned status)
{
struct pam_ctx_st * pctx = ctx;
int pret;

	pret = pam_close_session(pctx->ph, PAM_SILENT);
	if (pret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "PAM-acct: pam_close_session: %s", pam_strerror(pctx->ph, pret));
	}

	return;
}

const struct acct_mod_st pam_acct_funcs = {
  .type = ACCT_TYPE_PAM,
  .auth_types = AUTH_TYPE_PAM & (~VIRTUAL_AUTH_TYPES),
  .open_session = pam_acct_open_session,
  .close_session = pam_acct_close_session,
};

#endif
