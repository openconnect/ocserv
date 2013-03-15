/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <plain.h>

/* Returns 0 if the user is successfully authenticated, and sets the appropriate group name.
 */
int plain_auth_user(const char* passwd, const char* user, const char* pass, char *groupname, int groupname_size)
{
FILE* fp;
char * line = NULL;
size_t len;
ssize_t ll;
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
				groupname_size = snprintf(groupname, groupname_size, "%s", p);
				if (groupname_size == 1) /* values like '*' or 'x' indicate empty group */
					groupname[0] = 0;

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

