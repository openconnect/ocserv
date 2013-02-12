#ifndef COOKIES_H
#define COOKIES_H

#include <vpn.h>
#include <main.h>

struct stored_cookie_st {
	uint8_t cookie[COOKIE_SIZE];
	char username[MAX_USERNAME_SIZE];
	char groupname[MAX_GROUPNAME_SIZE];
	char hostname[MAX_HOSTNAME_SIZE];
	uint8_t session_id[GNUTLS_MAX_SESSION_ID];
	time_t expiration;
};

typedef int (*cookie_store_fn)(main_server_st *, struct stored_cookie_st* sc);

typedef int (*cookie_retrieve_fn)(main_server_st *, const void* cookie, unsigned cookie_size, 
			struct stored_cookie_st* sc);

typedef void (*cookie_db_deinit_fn)(main_server_st*);
typedef void (*cookie_expire_fn)(main_server_st* s);

extern cookie_store_fn store_cookie;
extern cookie_retrieve_fn retrieve_cookie;
extern cookie_db_deinit_fn cookie_db_deinit;
extern cookie_expire_fn expire_cookies;
extern cookie_expire_fn erase_cookies;

int cookie_db_init(main_server_st*);


struct cookie_storage_st {
	cookie_store_fn store;
	cookie_retrieve_fn retrieve;
	cookie_expire_fn expire;
	cookie_expire_fn erase; /* erases cookies if stored in process */
	int (*init)(main_server_st *);
	cookie_db_deinit_fn deinit;
};

extern struct cookie_storage_st gdbm_cookie_funcs;
extern struct cookie_storage_st hash_cookie_funcs;

#endif
