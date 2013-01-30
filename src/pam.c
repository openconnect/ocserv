#include <config.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_appl.h>

#define APP_NAME PACKAGE

#define MAX_REPLIES 2

struct local_st {
	const char* password;
	const char* username;
};

int dummy_conv(int msg_size, const struct pam_message **msg, 
		struct pam_response **resp, void *uptr)
{
struct local_st * l = uptr;
unsigned i;
struct pam_response *replies;

	if (msg_size == 0)
		return PAM_SUCCESS;

	replies = calloc(1, msg_size*sizeof(*replies));
	if (replies == NULL)
		return PAM_BUF_ERR;

	for (i=0;i<msg_size;i++) {
		/*syslog(LOG_DEBUG, "PAM message: %s\n", msg[i]->msg);*/
		if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)
			replies[i].resp = strdup(l->password);
		else if (msg[i]->msg_style == PAM_PROMPT_ECHO_ON)
			replies[i].resp = strdup(l->username);
	}

	*resp = replies;
	return PAM_SUCCESS;  
}

/* Returns 0 if the user is successfully authenticated
 */
int pam_auth_user(const char* user, const char* pass)
{
pam_handle_t * ph;
int ret, pret;
struct local_st local;
const struct pam_conv dc = { dummy_conv, &local };

	local.username = user;
	local.password = pass;

	pret = pam_start(APP_NAME, user, &dc, &ph);
	if (pret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "Error in PAM authentication initialization: %s", pam_strerror(ph, pret));
		return -1;
	}
	
	pret = pam_authenticate(ph, PAM_SILENT|PAM_DISALLOW_NULL_AUTHTOK);
	if (pret != PAM_SUCCESS) {
		syslog(LOG_AUTH, "Error in PAM authentication: %s", pam_strerror(ph, pret));
		ret = -1;
		goto fail;
	}

	ret = 0;
fail:
	pam_end(ph, pret);
	return ret;

}
