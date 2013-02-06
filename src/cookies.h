#ifndef COOKIES_H
#define COOKIES_H

#include <vpn.h>
#include <main.h>

struct stored_cookie_st {
	uint8_t cookie[COOKIE_SIZE];
	char username[MAX_USERNAME_SIZE];
	char hostname[MAX_USERNAME_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	time_t expiration;
};

int store_cookie(main_server_st *, struct stored_cookie_st* sc);

int retrieve_cookie(main_server_st *, const void* cookie, unsigned cookie_size, 
			struct stored_cookie_st* sc);

void cookie_db_deinit(hash_db_st* db);
void cookie_db_init(hash_db_st** _db);

#endif
