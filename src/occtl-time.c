/*
 * This code is from procps-ng (w.c)
 *
 * Almost entirely rewritten from scratch by Charles Blake circa
 * June 1996. Some vestigal traces of the original may exist.
 * That was done in 1993 by Larry Greenfield with some fixes by
 * Michael K. Johnson.
 *
 * Changes by Albert Cahalan, 2002.
 * Modified for occtl by Nikos Mavrogiannopoulos, 2014.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <occtl.h>

#define _(x) x

/* compact 7 char format for time intervals (belongs in libproc?) */
void print_time_ival7(char output[MAX_TMPSTR_SIZE], time_t t1, time_t t2)
{
	time_t t = t1 - t2;

	if ((long)t < (long)0) {
		/* system clock changed? */
		snprintf(output, MAX_TMPSTR_SIZE, "   ?   ");
		return;
	}
	
	if (t >= 48 * 60 * 60)
		/* 2 days or more */
		snprintf(output, MAX_TMPSTR_SIZE, _("%2ludays"), (long)t / (24 * 60 * 60));
	else if (t >= 60 * 60)
		/* 1 hour or more */
	        /* Translation Hint: Hours:Minutes */
		snprintf(output, MAX_TMPSTR_SIZE, _("%2luh:%02um"), (long)t / (60 * 60),
			(unsigned)((t / 60) % 60));
	else if (t > 60)
		/* 1 minute or more */
	        /* Translation Hint: Minutes:Seconds */
		snprintf(output, MAX_TMPSTR_SIZE, "%2lum:%02us", (long)t / 60, (unsigned)t % 60);
	else
	        /* Translation Hint: Seconds:Centiseconds */
		snprintf(output, MAX_TMPSTR_SIZE, _("%5lus"), (long)t);
}
