#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <plain.h>

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
int plain_auth_user(const char* passwd, const char* user, const char* pass, char *groupname, int groupname_size)
{
FILE* fp;
char * line = NULL;
size_t len, ll;
char* p;
int ret;

	fp = fopen(passwd, "r");
	if (fp == NULL) {
		syslog(LOG_AUTH, "error in plain authentication; cannot open: %s", passwd);
		return -1;
	}
	
	while((ll=getline(&line, &len, fp)) > 0) {
		if (ll <= 2)
			continue;

		if (line[ll-1] == '\n')
			line[ll-1] = 0;
		if (line[ll-2] == '\n')
			line[ll-2] = 0;

		p = strtok(line, ":");

		if (p != NULL && strcmp(user, p) == 0) {
			p = strtok(NULL, ":");
			if (p != NULL) {
				snprintf(groupname, groupname_size, "%s", p);
				p = strtok(NULL, ":");
				if (p != NULL && strcmp(crypt(pass, p), p) == 0) {
					ret = 0;
					goto exit;
				}
			}
		}
	}
	
	ret = -1;
	syslog(LOG_AUTH, "error in plain authentication; error in user '%s'", user);
exit:
	fclose(fp);
	free(line);
	return ret;
}

