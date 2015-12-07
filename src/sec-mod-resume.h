/*
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
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
#ifndef SEC_MOD_RESUME_H
# define SEC_MOD_RESUME_H

#include <sec-mod.h>

int handle_resume_delete_req(sec_mod_st* sec,
  			   const SessionResumeFetchMsg * req);

int handle_resume_fetch_req(sec_mod_st* sec,
  			   const SessionResumeFetchMsg * req, 
  			   SessionResumeReplyMsg* rep);

int handle_resume_store_req(sec_mod_st* sec,
  			   const SessionResumeStoreReqMsg *);

void expire_tls_sessions(sec_mod_st *sec);

#endif
