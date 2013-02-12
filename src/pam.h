#ifndef PAM_H
#define PAM_H

int pam_auth_user(const char* user, const char* pass, char *groupname, int groupname_size);

#endif
