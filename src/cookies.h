#ifndef COOKIES_H
#define COOKIES_H

#include <main.h>

struct __attribute__ ((__packed__)) stored_cookie_st {
	char username[MAX_USERNAME_SIZE];
	char hostname[MAX_USERNAME_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	time_t expiration;
};

int store_cookie(const struct cfg_st *, const void* cookie, unsigned cookie_size, 
 		 const struct stored_cookie_st* sc);
void expire_cookies(main_server_st* s);

int retrieve_cookie(const struct cfg_st *, const void* cookie, unsigned cookie_size, 
			struct stored_cookie_st* sc);

#endif
