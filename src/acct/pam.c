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

static int ocserv_conv(int msg_size, const struct pam_message **msg, 
		struct pam_response **resp, void *uptr)
{
	*resp = NULL;
	return PAM_SUCCESS;
}

static int pam_acct_open_session(unsigned auth_method, const struct common_acct_info_st *ai, const void *sid, unsigned sid_size)
{
int pret;
pam_handle_t *ph;
struct pam_conv dc;

	if (ai->username[0] == 0) {
		syslog(LOG_AUTH,
		       "PAM-acct: no username present");
		return ERR_AUTH_FAIL;
	}

	dc.conv = ocserv_conv;
	dc.appdata_ptr = NULL;
	pret = pam_start(PACKAGE, ai->username, &dc, &ph);
	if (pret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "PAM-acct init: %s", pam_strerror(ph, pret));
		goto fail1;
	}

	pret = pam_acct_mgmt(ph, PAM_DISALLOW_NULL_AUTHTOK);
	if (pret != PAM_SUCCESS) {
		syslog(LOG_INFO, "PAM-acct account error: %s", pam_strerror(ph, pret));
		goto fail2;
	}

	pam_end(ph, pret);
	return 0;

fail2:
	pam_end(ph, pret);
fail1:
	return -1;

}

static void pam_acct_close_session(unsigned auth_method, const struct common_acct_info_st *ai, stats_st *stats, unsigned status)
{
	return;
}

const struct acct_mod_st pam_acct_funcs = {
  .type = ACCT_TYPE_PAM,
  .auth_types = ALL_AUTH_TYPES,
  .open_session = pam_acct_open_session,
  .close_session = pam_acct_close_session,
};

#endif
