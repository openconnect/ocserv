/*
 * Copyright (C) 2020 Microsoft Corporation
 *
 * Author: Alan Jowett
 *
 * This file is part of ocserv.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif
#include <unistd.h>
#include <vpn.h>
#include <c-ctype.h>
#include "plain.h"
#include "common-config.h"
#include "auth/common.h"

#ifdef SUPPORT_OIDC_AUTH
#include <curl/curl.h>
#include <jansson.h>
#include <cjose/cjose.h>
#include <time.h>

#define MINIMUM_KEY_REFRESH_INTERVAL (900)

typedef struct oidc_vctx_st {
	json_t *config;
	json_t *jwks;
	void * pool;
	int minimum_jwk_refresh_time;
	time_t last_jwks_load_time;
} oidc_vctx_st;

typedef struct oidc_ctx_st {
	oidc_vctx_st *vctx_st;
	char username[MAX_USERNAME_SIZE];
	int token_verified;
} oidc_ctx_st;

static bool oidc_fetch_oidc_keys(oidc_vctx_st * vctx);
static bool oidc_verify_token(oidc_vctx_st * vctx, const char *token,
				size_t token_length,
				char user_name[MAX_USERNAME_SIZE]);

static void oidc_vhost_init(void **vctx, void *pool, void *additional)
{
	const char *config = (const char *)additional;
	json_error_t err;
	struct oidc_vctx_st *vc;

	vc = talloc(pool, struct oidc_vctx_st);
	if (vc == NULL) {
		syslog(LOG_ERR, "ocserv-oidc allocation failure!\n");
		exit(1);
	}
	vc->config = NULL;
	vc->jwks = NULL;
	vc->pool = pool;

	if (config == NULL) {
		syslog(LOG_ERR, "ocserv-oidc: no configuration passed!\n");
		exit(1);
	}

	vc->config = json_load_file(config, 0, &err);
	if (vc->config == NULL) {
		syslog(LOG_ERR, "ocserv-oidc: failed to load config file: %s\n", config);
		exit(1);
	}

	if (!json_object_get(vc->config, "openid_configuration_url")) {
		syslog(LOG_ERR,
		       "ocserv-oidc: config file missing openid_configuration_url\n");
		exit(1);
	}

	if (!json_object_get(vc->config, "required_claims")) {
		syslog(LOG_ERR,
		       "ocserv-oidc: config file missing required_claims\n");
		exit(1);
	}

	if (!json_object_get(vc->config, "user_name_claim")) {
		syslog(LOG_ERR,
		       "ocserv-oidc: config file missing user_name_claim\n");
		exit(1);
	}

	if (json_object_get(vc->config, "minimum_jwk_refresh_time")) {
		vc->minimum_jwk_refresh_time = json_integer_value(json_object_get(vc->config, "minimum_jwk_refresh_time"));
	} else {
		vc->minimum_jwk_refresh_time = MINIMUM_KEY_REFRESH_INTERVAL;
	}

	if (!oidc_fetch_oidc_keys(vc)) {
		syslog(LOG_ERR, "ocserv-oidc: failed to load jwks\n");
		exit(1);
	}

	*vctx = (void *)vc;

	return;
}

static void oidc_vhost_deinit(void *ctx)
{
	oidc_vctx_st *vctx = (oidc_vctx_st *) ctx;

	if (!vctx) {
		return;
	}

	if (vctx->jwks) {
		json_decref(vctx->jwks);
		vctx->jwks = NULL;
	}

	if (vctx->config) {
		json_decref(vctx->config);
		vctx->config = NULL;
	}
}

static int oidc_auth_init(void **ctx, void *pool, void *vctx,
			    const common_auth_init_st * info)
{
	oidc_vctx_st *vt = (oidc_vctx_st *) vctx;
	oidc_ctx_st *ct;
	ct = talloc_zero(pool, struct oidc_ctx_st);
	if (!ct) {
		return ERR_AUTH_FAIL;
	}
	ct->vctx_st = vt;
	*ctx = (void *)ct;

	if (oidc_verify_token(ct->vctx_st, info->username, strlen(info->username), ct->username)) {
		ct->token_verified = 1;
		return 0;
	} else {
		return ERR_AUTH_FAIL;
	}
}

static int oidc_auth_user(void *ctx, char *username, int username_size)
{
	oidc_ctx_st *ct = (oidc_ctx_st *) ctx;

	if (ct->token_verified) {
		strlcpy(username, ct->username, username_size);
		return 0;
	}
	return ERR_AUTH_FAIL;
}

static int oidc_auth_pass(void *ctx, const char *pass, unsigned pass_len)
{
	return ERR_AUTH_FAIL;
}

static int oidc_auth_msg(void *ctx, void *pool, passwd_msg_st * pst)
{
	pst->counter = 0;	/* we support a single password */

	/* use the default prompt */
	return 0;
}

static void oidc_auth_deinit(void *ctx)
{
	talloc_free(ctx);
}

const struct auth_mod_st oidc_auth_funcs = {
	.type = AUTH_TYPE_OIDC,
	.allows_retries = 1,
	.vhost_init = oidc_vhost_init,
	.vhost_deinit = oidc_vhost_deinit,
	.auth_init = oidc_auth_init,
	.auth_deinit = oidc_auth_deinit,
	.auth_msg = oidc_auth_msg,
	.auth_pass = oidc_auth_pass,
	.auth_user = oidc_auth_user,
	.auth_group = NULL,
	.group_list = NULL
};

// Key management
typedef struct oidc_json_parser_context {
	void *pool;
	char *buffer;
	size_t length;
	size_t offset;
} oidc_json_parser_context;

// Callback from CURL for each block as it is downloaded
static size_t oidc_json_parser_context_callback(char *ptr, size_t size,
						  size_t nmemb, void *userdata)
{
	oidc_json_parser_context *context =
	    (oidc_json_parser_context *) userdata;
	size_t new_offset = context->offset + nmemb;

	// Check for buffer overflow
	if (new_offset < nmemb) {
		return 0;
	}

	if (context->offset + nmemb > context->length) {
		size_t new_size = (nmemb + context->length) * 3 / 2;
		void * new_buffer = talloc_realloc_size(context->pool, context->buffer, new_size);
		if (new_buffer) {
			context->buffer = new_buffer;
			context->length = new_size;
		} else {
			return 0;
		}
	}

	memcpy(context->buffer + context->offset, ptr, nmemb);
	context->offset = new_offset;

	return nmemb;
}

// Download a JSON file from the provided URI and return it in a jansson object
static json_t *oidc_fetch_json_from_uri(void * pool, const char *uri)
{
	oidc_json_parser_context context = { pool, NULL, 0, 0 };
	json_t *json = NULL;
	json_error_t err;
	CURL *curl = NULL;
	CURLcode res;

	context.length = 4096;
	context.buffer = talloc_size(context.pool, context.length);

	if (context.buffer == NULL) {
		goto cleanup;
	}

	curl = curl_easy_init();
	if (!curl) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: failed to download JSON document: URI %s\n",
		       uri);
		goto cleanup;
	}

	res = curl_easy_setopt(curl, CURLOPT_URL, uri);
	if (res != CURLE_OK) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: failed to download JSON document: URI %s, CURLcode %d\n",
		       uri, res);
		goto cleanup;
	}

	res =
	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			     oidc_json_parser_context_callback);
	if (res != CURLE_OK) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: failed to download JSON document: URI %s, CURLcode %d\n",
		       uri, res);
		goto cleanup;
	}

	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &context);
	if (res != CURLE_OK) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: failed to download JSON document: URI %s, CURLcode %d\n",
		       uri, res);
		goto cleanup;
	}

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: failed to download JSON document: URI %s, CURLcode %d\n",
		       uri, res);
		goto cleanup;
	}

	json = json_loadb(context.buffer, context.offset, 0, &err);
	if (!json) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: failed to parse JSON document: URI %s\n",
		       uri);
		goto cleanup;
	}

 cleanup:
	if (context.buffer) {
		talloc_free(context.buffer);
	}

	if (curl) {
		curl_easy_cleanup(curl);
	}

	return json;
}

// Download and parse the JWT keys for this virtual server context
static bool oidc_fetch_oidc_keys(oidc_vctx_st * vctx)
{
	bool result = false;
	json_t *jwks = NULL;
	json_t *openid_configuration_url =
	    json_object_get(vctx->config, "openid_configuration_url");

	json_t *array;
	size_t index;
	json_t *value;

	if (!openid_configuration_url) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: openid_configuration_url missing from config\n");
		goto cleanup;
	}
	
	json_t *oidc_config =
	    oidc_fetch_json_from_uri(vctx->pool, 
					   json_string_value
				       (openid_configuration_url));

	if (!oidc_config) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Unable to fetch config doc from %s\n", json_string_value(openid_configuration_url));
		goto cleanup;
	}

	json_t *jwks_uri = json_object_get(oidc_config, "jwks_uri");
	if (!jwks_uri || !json_string_value(jwks_uri)) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: jwks_uri missing from config doc\n");
		goto cleanup;
	}

	jwks = oidc_fetch_json_from_uri(vctx->pool, json_string_value(jwks_uri));
	if (!jwks) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: failed to fetch keys from jwks_uri %s\n",
		       json_string_value(jwks_uri));
		goto cleanup;
	}

	array = json_object_get(jwks, "keys");
	if (array == NULL) {
		syslog(LOG_AUTH, "ocserv-oidc: JWK keys malformed\n");
		goto cleanup;
	}

	// Log the keys obtained
	json_array_foreach(array, index, value) {
		json_t *key_kid = json_object_get(value, "kid");
		syslog(LOG_INFO,
		       "ocserv-oidc: fetched new JWK %s\n",
			   json_string_value(key_kid)
		       );
	}

	if (vctx->jwks) {
		json_decref(vctx->jwks);
	}

	vctx->last_jwks_load_time = time(0);

	vctx->jwks = jwks;
	jwks = NULL;
	result = true;

 cleanup:
	if (oidc_config) {
		json_decref(oidc_config);
	}

	if (jwks) {
		json_decref(oidc_config);
	}
	return result;
}

static bool oidc_verify_lifetime(json_t * token_claims)
{
	bool result = false;

	// Get the time bounds of the token
	json_t *token_nbf = json_object_get(token_claims, "nbf");
	json_t *token_iat = json_object_get(token_claims, "iat");
	json_t *token_exp = json_object_get(token_claims, "exp");
	time_t current_time = time(NULL);

	if (!token_nbf || !json_integer_value(token_nbf)) {
		syslog(LOG_AUTH, "ocserv-oidc: Token missing 'nbf' claim\n");
		goto cleanup;
	}

	if (!token_exp || !json_integer_value(token_exp)) {
		syslog(LOG_AUTH, "ocserv-oidc: Token missing 'exp' claim\n");
		goto cleanup;
	}

	if (!token_iat || !json_integer_value(token_iat)) {
		syslog(LOG_AUTH, "ocserv-oidc: Token missing 'iat' claim\n");
		goto cleanup;
	}

	// Check to ensure the token is within it's validity
	if (json_integer_value(token_nbf) > current_time
	    || json_integer_value(token_exp) < current_time) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Token not within validity period NBF: %lld EXP: %lld Current: %ld\n",
		       json_integer_value(token_nbf),
		       json_integer_value(token_exp), current_time);
		goto cleanup;
	}

	result = true;

 cleanup:
	return result;
}

static bool oidc_verify_required_claims(json_t * required_claims,
					  json_t * token_claims)
{
	bool result = false;

	const char *required_claim_name;
	json_t *required_claim_value;
	json_t *token_claim_value;

	// Ensure all the required claims are present in the token
	json_object_foreach(required_claims, required_claim_name,
			    required_claim_value) {
		token_claim_value =
		    json_object_get(token_claims, required_claim_name);
		if (!json_equal(required_claim_value, token_claim_value)) {
			syslog(LOG_AUTH,
			       "ocserv-oidc: Required claim not met. Claim: %s Expected Value: %s\n",
			       required_claim_name,
			       json_string_value(required_claim_value));
			goto cleanup;
		}
	}

	result = true;

 cleanup:
	return result;
}

static bool oidc_map_user_name(json_t * user_name_claim,
				 json_t * token_claims,
				 char user_name[MAX_USERNAME_SIZE])
{
	bool result = false;

	// Pull the user name from the token
	json_t *token_user_name_claim =
	    json_object_get(token_claims, json_string_value(user_name_claim));
	if (!token_user_name_claim || !json_string_value(token_user_name_claim)) {
		syslog(LOG_AUTH, "ocserv-oidc: Token missing '%s' claim\n",
		       json_string_value(user_name_claim));
		goto cleanup;
	}

	strlcpy(user_name, json_string_value(token_user_name_claim),
		MAX_USERNAME_SIZE);
	result = true;

 cleanup:
	return result;
}

static json_t *oidc_extract_claims(cjose_jws_t * jws)
{
	cjose_err err;
	json_error_t json_err;
	uint8_t *plain_text = NULL;
	size_t plain_text_size = 0;
	json_t *token_claims = NULL;

	// Extract the claim portion from the token
	if (!cjose_jws_get_plaintext(jws, &plain_text, &plain_text_size, &err)) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Failed to get plain text from token\n");
		goto cleanup;
	}

	// Parse the claim JSON
	token_claims =
	    json_loadb((char *)plain_text, plain_text_size, 0, &json_err);
	if (!token_claims) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Failed to get claims from token\n");
		goto cleanup;
	}

 cleanup:
	return token_claims;
}

static bool oidc_verify_singature(oidc_vctx_st * vctx, cjose_jws_t * jws)
{
	bool result = false;

	cjose_err err;
	cjose_jwk_t *jwk = NULL;
	json_t *token_header;
	json_t *token_kid;
	json_t *token_typ;
	json_t *array;
	size_t index;
	json_t *value;

	if (vctx->jwks == NULL) {
		syslog(LOG_AUTH, "ocserv-oidc: JWK keys not available\n");
		goto cleanup;
	}

	array = json_object_get(vctx->jwks, "keys");
	if (array == NULL) {
		syslog(LOG_AUTH, "ocserv-oidc: JWK keys malformed\n");
		goto cleanup;
	}

	// Get the token header
	token_header = cjose_jws_get_protected(jws);
	if (token_header == NULL) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Token malformed - no header\n");
		goto cleanup;
	}

	// Get the kid of the key used to sign this token
	token_kid = json_object_get(token_header, "kid");
	if (token_kid == NULL || !json_string_value(token_kid)) {
		syslog(LOG_AUTH, "ocserv-oidc: Token malformed - no kid\n");
		goto cleanup;
	}

	token_typ = json_object_get(token_header, "typ");
	if (token_typ == NULL || !json_string_value(token_typ) || strcmp(json_string_value(token_typ), "JWT")) {
		syslog(LOG_AUTH, "ocserv-oidc: Token malformed - wrong typ claim\n");
		goto cleanup;
	}

	// Find the signing key in the keys collection
	json_array_foreach(array, index, value) {
		json_t *key_kid = json_object_get(value, "kid");
		if (json_equal(key_kid, token_kid)) {
			jwk = cjose_jwk_import_json(value, &err);
			break;
		}
	}

	if (jwk == NULL) {
		time_t now;
		syslog(LOG_AUTH, "ocserv-oidc: JWK with kid=%s not found\n",
		       json_string_value(token_kid));

		syslog(LOG_AUTH, "ocserv-oidc: attempting to download new JWKs");
		now = time(0);
		if ((now - vctx->last_jwks_load_time) > vctx->minimum_jwk_refresh_time) {
			oidc_fetch_oidc_keys(vctx);
		}
		else {
			syslog(LOG_AUTH, "ocserv-oidc: skipping JWK refresh");
		}

		// Fail the request and let the client try again.
		goto cleanup;
	}

	if (!cjose_jws_verify(jws, jwk, &err)) {
		syslog(LOG_AUTH, "ocserv-oidc: Token failed validation %s\n",
		       err.message);
		goto cleanup;
	}

	result = true;

 cleanup:
	return result;
}

// Verify that the provided token is signed
static bool oidc_verify_token(oidc_vctx_st * vctx, const char *token,
				size_t token_length,
				char user_name[MAX_USERNAME_SIZE])
{
	bool result = false;
	cjose_err err;
	cjose_jws_t *jws = NULL;
	json_t *token_claims = NULL;

	jws = cjose_jws_import(token, token_length, &err);
	if (jws == NULL) {
		syslog(LOG_AUTH, "ocserv-oidc: Token malformed - %s\n",
		       err.message);
		goto cleanup;
	}

	if (!oidc_verify_singature(vctx, jws)) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Token signature validation failed\n");
		goto cleanup;
	}

	token_claims = oidc_extract_claims(jws);
	if (!token_claims) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Unable to access token claims\n");
		goto cleanup;
	}

	if (!oidc_verify_lifetime(token_claims)) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Token lifetime validation failed\n");
		goto cleanup;
	}

	if (!oidc_verify_required_claims
	    (json_object_get(vctx->config, "required_claims"), token_claims)) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Token required claims validation failed\n");
		goto cleanup;
	}

	if (!oidc_map_user_name
	    (json_object_get(vctx->config, "user_name_claim"), token_claims,
	     user_name)) {
		syslog(LOG_AUTH,
		       "ocserv-oidc: Unable to map user name claim\n");
		goto cleanup;
	}

	result = true;

 cleanup:
	if (jws) {
		cjose_jws_release(jws);
	}

	if (token_claims) {
		json_decref(token_claims);
	}

	return result;
}

#endif
