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
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ocserv-args.h>
#include <vpn.h>


int cmd_parser (int argc, char **argv, struct cfg_st* config)
{
	const char* cfg_file;

	memset(config, 0, sizeof(*config));

	optionProcess( &ocservOptions, argc, argv);
  
	if (HAVE_OPT(FOREGROUND))
		config->foreground = 1;
	
	if (HAVE_OPT(CONFIG)) {
		cfg_file = OPT_ARG(CONFIG);
	} else {
		fprintf(stderr, "Please use the -c option to specify a configuration file, or --help for more information.\n");
		exit(1);
	}

}
