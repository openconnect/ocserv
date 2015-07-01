/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sec-mod-auth.h>
#include "auth-unix.h"

#ifdef HAVE_GET_USER_AUTH_GROUP
/* Fills-in groupname, if the user is in a unix group, via getpwnam().
 * Returns -1 if the suggested group doesn't match one the groups, or
 * zero otherwise (an empty group is still success).
 */
int get_user_auth_group(const char *username, const char *suggested,
			char *groupname, int groupname_size)
{
struct passwd * pwd;
struct group *grp;
int ret;
unsigned found;

	groupname[0] = 0;

	pwd = getpwnam(username);
	if (pwd != NULL) {
		if (suggested != NULL) {
			gid_t groups[MAX_GROUPS];
			int ngroups = sizeof(groups)/sizeof(groups[0]);
			unsigned i;

			ret = getgrouplist(username, pwd->pw_gid, groups, &ngroups);
			if (ret <= 0) {
				return 0;
			}

			found = 0;
			for (i=0;i<ngroups;i++) {
				grp = getgrgid(groups[i]);
				if (grp != NULL && strcmp(suggested, grp->gr_name) == 0) {
					strlcpy(groupname, grp->gr_name, groupname_size);
					found = 1;
					break;
				}
			}

			if (found == 0) {
				syslog(LOG_AUTH,
				       "user '%s' requested group '%s' but is not a member",
				       username, suggested);
				return -1;
			}
		} else {
			struct group* grp = getgrgid(pwd->pw_gid);
			if (grp != NULL)
				strlcpy(groupname, grp->gr_name, groupname_size);
		}
	}

	return 0;
}

void unix_group_list(void *pool, unsigned gid_min, char ***groupname, unsigned *groupname_size)
{
	struct group *grp;

	setgrent();

	*groupname_size = 0;
	*groupname = talloc_size(pool, sizeof(char*)*MAX_GROUPS);
	if (*groupname == NULL) {
		goto exit;
	}

	while((grp = getgrent()) != NULL && (*groupname_size) < MAX_GROUPS) {
		if (grp->gr_gid >= gid_min) {
			(*groupname)[(*groupname_size)] = talloc_strdup(*groupname, grp->gr_name);
			if ((*groupname)[(*groupname_size)] == NULL)
				break;
			(*groupname_size)++;
		}
	}

 exit:
	endgrent();
	return;
}

#endif
