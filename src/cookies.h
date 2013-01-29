#ifndef COOKIES_H
#define COOKIES_H

#include <vpn.h>

struct __attribute__ ((__packed__)) stored_cookie_st {
	char username[MAX_USERNAME_SIZE];
	time_t expiration;
};

int store_cookie(worker_st *server, const void* cookie, unsigned cookie_size, 
		const struct stored_cookie_st* sc);
void expire_cookies(struct cfg_st *cfg);

int retrieve_cookie(worker_st *server, const void* cookie, unsigned cookie_size, 
			struct stored_cookie_st* sc);

#endif
