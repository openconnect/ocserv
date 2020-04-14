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
#include <unistd.h>

#include <cjose/cjose.h>
#include <jansson.h>
#include <string.h>

cjose_jwk_t *create_key(const char *kid)
{
	cjose_err err;
	cjose_jwk_t *key = cjose_jwk_create_EC_random(CJOSE_JWK_EC_P_256, &err);
	if (!key) {
		return NULL;
	}

	if (!cjose_jwk_set_kid(key, kid, strlen(kid), &err)) {
		return NULL;
	}
	return key;
}

json_t *create_oidc_config(const char *openid_configuration_url,
			   const char *user_name_claim, const char *audience,
			   const char *issuer)
{
	bool result = false;
	json_t *config = json_object();
	json_t *required_claims = json_object();
	if (json_object_set_new
	    (config, "openid_configuration_url",
	     json_string(openid_configuration_url))) {
		goto cleanup;
	}

	if (json_object_set_new
	    (config, "user_name_claim", json_string(user_name_claim))) {
		goto cleanup;
	}

	if (json_object_set_new(required_claims, "aud", json_string(audience))) {
		goto cleanup;
	}

	if (json_object_set_new(required_claims, "iss", json_string(issuer))) {
		goto cleanup;
	}

	if (json_object_set_new(config, "required_claims", required_claims)) {
		goto cleanup;
	}

	if (json_object_set_new(config, "minimum_jwk_refresh_time", json_integer(0))) {
		goto cleanup;
	}

	required_claims = NULL;

	result = true;

 cleanup:
	if (!result && config) {
		json_decref(config);
		config = NULL;
	}

	return config;
}

json_t *create_openid_configuration(char *key_url)
{
	json_t *config = json_object();
	if (json_object_set_new(config, "jwks_uri", json_string(key_url))) {
		json_decref(config);
		return NULL;
	}
	return config;
}

json_t *create_keys(cjose_jwk_t * key)
{
	cjose_err err;
	json_t *keys_json = json_object();
	json_t *keys_array = json_array();
	json_t *key_json;

	const char *key_str = cjose_jwk_to_json(key, false, &err);
	key_json = json_loads(key_str, 0, NULL);
	json_array_append_new(keys_array, key_json);
	json_object_set_new(keys_json, "keys", keys_array);
	return keys_json;
}

json_t *create_header(const char *typ, const char *alg, const char *kid)
{
	json_t *header_json = json_object();
	if (typ) {
		json_object_set_new(header_json, "typ", json_string(typ));
	}
	if (alg) {
		json_object_set_new(header_json, "alg", json_string(alg));
	}
	if (kid) {
		json_object_set_new(header_json, "kid", json_string(kid));
	}
	return header_json;
}

json_t *create_claims(const char *audience, const char *issuer,
		      json_int_t issued_at, json_int_t not_before,
		      json_int_t expires, const char *preferred_user_name)
{
	json_t *claims_json = json_object();
	if (audience) {
		json_object_set_new(claims_json, "aud", json_string(audience));
	}
	if (issuer) {
		json_object_set_new(claims_json, "iss", json_string(issuer));
	}
	if (issued_at) {
		json_object_set_new(claims_json, "iat",
				    json_integer(issued_at));
	}
	if (not_before) {
		json_object_set_new(claims_json, "nbf",
				    json_integer(not_before));
	}
	if (expires) {
		json_object_set_new(claims_json, "exp", json_integer(expires));
	}
	if (preferred_user_name) {
		json_object_set_new(claims_json, "preferred_username",
				    json_string(preferred_user_name));
	}
	return claims_json;
}

cjose_jws_t *create_jws(cjose_jwk_t * key, json_t * header, json_t * claims)
{
	cjose_err err;
	char *claims_str = json_dumps(claims, 0);
	cjose_jws_t *jws =
	    cjose_jws_sign(key, header, (const uint8_t *)claims_str,
			   strlen(claims_str), &err);
	free(claims_str);
	return jws;
}

bool write_jws_to_file(cjose_jws_t * jws, const char *file)
{
	cjose_err err;
	const char *jws_str;
	FILE *f = fopen(file, "w");
	if (!cjose_jws_export(jws, &jws_str, &err)) {
		fclose(f);
		return false;
	}

	fprintf(f, "%s", jws_str);
	fclose(f);
	return true;
}

void generate_token(const char *output_folder, const char *token_name,
		    cjose_jwk_t * key, const char *typ, const char *alg,
		    const char *kid, const char *audience, const char *issuer,
		    const char *user_name, json_int_t issued_at,
		    json_int_t not_before, json_int_t expires)
{
	char token_file[1024];
	snprintf(token_file, sizeof(token_file), "%s/%s.token", output_folder,
		 token_name);
	json_t *header = create_header(typ, alg, kid);
	json_t *claims =
	    create_claims(audience, issuer, issued_at, not_before, expires,
			  user_name);
	cjose_jws_t *jws = create_jws(key, header, claims);
	write_jws_to_file(jws, token_file);

	cjose_jws_release(jws);
	json_decref(header);
	json_decref(claims);
}

void generate_config_files(const char *output_folder, cjose_jwk_t * key,
			   const char *expected_audience,
			   const char *expected_issuer,
			   const char *user_name_claim)
{
	char oidc_config_file[1024];
	char openid_configuration_file[1024];
	char keys_file[1024];
	char openid_configuration_uri[1024];
	char keys_uri[1024];
	int retval;
	retval =
	    snprintf(oidc_config_file, sizeof(oidc_config_file), "%s/oidc.json",
		     output_folder);

	retval =
	    snprintf(openid_configuration_file,
		     sizeof(openid_configuration_file),
		     "%s/openid-configuration.json", output_folder);
	if (retval < 0 || retval > sizeof(openid_configuration_file)) {
		exit(1);
	}

	retval =
	    snprintf(keys_file, sizeof(keys_file), "%s/keys.json",
		     output_folder);
	if (retval < 0 || retval > sizeof(openid_configuration_file)) {
		exit(1);
	}
	retval =
	    snprintf(openid_configuration_uri, sizeof(openid_configuration_uri),
		     "file://localhost%s", openid_configuration_file);
	if (retval < 0 || retval > sizeof(openid_configuration_file)) {
		exit(1);
	}

	retval =
	    snprintf(keys_uri, sizeof(keys_uri), "file://localhost%s",
		     keys_file);
	if (retval < 0 || retval > sizeof(openid_configuration_file)) {
		exit(1);
	}

	json_t *oidc_config =
	    create_oidc_config(openid_configuration_uri, "preferred_username",
			       "SomeAudience", "SomeIssuer");
	json_t *openid_configuration = create_openid_configuration(keys_uri);
	json_t *keys = create_keys(key);

	json_dump_file(oidc_config, oidc_config_file, 0);
	json_dump_file(openid_configuration, openid_configuration_file, 0);
	json_dump_file(keys, keys_file, 0);

	json_decref(oidc_config);
	json_decref(openid_configuration);
	json_decref(keys);
}

int main(int argc, char **argv)
{
	char working_directory[1024];
	const char audience[] = "SomeAudience";
	const char issuer[] = "SomeIssuer";
	const char user_name_claim[] = "preferred_user_name";
	char kid[64];
	const char user_name[] = "SomeUser";
	const char typ[] = "JWT";
	const char alg[] = "ES256";
	time_t now = time(NULL);

	snprintf(kid, sizeof(kid), "key_%ld", now);

	if (!getcwd(working_directory, sizeof(working_directory))) {
		return 1;
	}
	strncat(working_directory, "/data", sizeof(working_directory)-1);
	working_directory[sizeof(working_directory)-1] = 0;

	cjose_jwk_t *key = create_key(kid);

	generate_config_files(working_directory, key, audience, issuer,
			      user_name_claim);

	generate_token(working_directory, "success_good", key, typ, alg, kid,
		       audience, issuer, user_name, now - 60, now - 60,
		       now + 3600);
	generate_token(working_directory, "fail_expired", key, typ, alg, kid,
		       audience, issuer, user_name, now - 7260, now - 7260,
		       now - 3600);
	generate_token(working_directory, "fail_bad_typ", key, "FOO", alg, kid,
		       audience, issuer, user_name, now - 60, now - 60,
		       now + 3600);
	generate_token(working_directory, "fail_bad_alg", key, typ, "FOO", kid,
		       audience, issuer, user_name, now - 60, now - 60,
		       now + 3600);
	generate_token(working_directory, "fail_wrong_kid", key, typ, alg,
		       "FOO", audience, issuer, user_name, now - 60, now - 60,
		       now + 3600);
	generate_token(working_directory, "fail_wrong_aud", key, typ, alg, kid,
		       "FOO", issuer, user_name, now - 60, now - 60,
		       now + 3600);
	generate_token(working_directory, "fail_wrong_iss", key, typ, alg, kid,
		       audience, "FOO", user_name, now - 60, now - 60,
		       now + 3600);

	generate_token(working_directory, "fail_missing_aud", key, typ, alg,
		       kid, NULL, issuer, user_name, now - 60, now - 60,
		       now + 3600);
	generate_token(working_directory, "fail_missing_iss", key, typ, alg,
		       kid, audience, NULL, user_name, now - 60, now - 60,
		       now + 3600);
	generate_token(working_directory, "fail_missing_user", key, typ, alg,
		       kid, audience, issuer, NULL, now - 60, now - 60,
		       now + 3600);
	generate_token(working_directory, "fail_missing_iat", key, typ, alg,
		       kid, audience, issuer, user_name, 0, now - 60,
		       now + 3600);
	generate_token(working_directory, "fail_missing_nbf", key, typ, alg,
		       kid, audience, issuer, user_name, now - 60, 0,
		       now + 3600);
	generate_token(working_directory, "fail_missing_exp", key, typ, alg,
		       kid, audience, issuer, user_name, now - 60, now - 60, 0);
	return 0;
}
