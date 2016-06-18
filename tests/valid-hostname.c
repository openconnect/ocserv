/*
 * Copyright (C) 2016 Nikos Mavrogiannopoulos
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/valid-hostname.c"

/* This checks whether the valid_hostname() function works
 * as expected.
 */

int main()
{
	/* check invalid hostnames */
	assert(valid_hostname("192.168.1.1") == 0);
	assert(valid_hostname("-hello") == 0);
	assert(valid_hostname("1234!") == 0);
	assert(valid_hostname("1234#abc") == 0);
	assert(valid_hostname("1234$abc") == 0);
	assert(valid_hostname("1234&abc") == 0);
	assert(valid_hostname("1234|abc") == 0);
	assert(valid_hostname("1234\aabc") == 0);
	assert(valid_hostname("1234\babc") == 0);
	assert(valid_hostname("ABC.abc") == 0);

	/* check valid hostnames */
	assert(valid_hostname("12-hello") != 0);
	assert(valid_hostname("1234abc-") != 0);
	assert(valid_hostname("1234abc-ABC") != 0);
	assert(valid_hostname("ABC-abc1") != 0);

	return 0;
}
