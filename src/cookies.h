#ifndef COOKIES_H
#define COOKIES_H

#include <vpn.h>

struct __attribute__ ((__packed__)) stored_cookie_st {
	char username[MAX_USERNAME_SIZE];
	char groupname[MAX_GROUPNAME_SIZE];
	char hostname[MAX_HOSTNAME_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	uint32_t expiration;
};

#define COOKIE_IV_SIZE 12 /* AES-GCM */
#define COOKIE_MAC_SIZE 12 /* 96-bits of AES-GCM */
#define COOKIE_SIZE (COOKIE_IV_SIZE + sizeof(struct stored_cookie_st) + COOKIE_MAC_SIZE)

int encrypt_cookie(struct main_server_st * s, const struct stored_cookie_st* sc,
			uint8_t* cookie, unsigned cookie_size);
int decrypt_cookie(struct main_server_st * s, const uint8_t* cookie, unsigned cookie_size, 
			struct stored_cookie_st* sc);

#endif
