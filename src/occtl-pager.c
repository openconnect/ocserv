/*
 * Copyright (C) 2014 Red Hat
 *
 * Author: Nikos Mavrogiannopoulos
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <occtl.h>

static const char* get_pager(void)
{
char* pager;
	pager = getenv("OCCTL_PAGER");
	if (pager == NULL)
		pager = getenv("PAGER");
	if (pager == NULL)
		pager = OCCTL_PAGER;
	
	return pager;
}

/* Always succeeds */
FILE* pager_start(void)
{
FILE *fp;

#ifdef HAVE_ISATTY
	if (isatty(STDOUT_FILENO) == 0)
		return stdout;
#endif

	if (!getenv("LESS")) {
		setenv("LESS", "FRSX", 1);
	}
	fp = popen(get_pager(), "w");
	
	if (fp == NULL) { /* no pager */
		fprintf(stderr, "unable to start pager; check your $PAGER environment variable\n");
		fp = stdout;
	}
	
	return fp;
}

void pager_stop(FILE* fp)
{
	if (fp != stdout)
		pclose(fp);
}
