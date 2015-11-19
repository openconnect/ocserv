/*
 * Copyright (C) 2015 Red Hat, Inc.
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
#include <talloc.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "../src/main.h"
#include "../src/main-ban.h"
#include "../src/ip-util.h"
#include "../src/main-ban.c"

/* Test the IP banning functionality */
static
unsigned check_if_banned_str(main_server_st *s, const char *ip)
{
	struct sockaddr_storage addr;
	int ret;

	if (strchr(ip, ':') != 0) {
		ret = inet_pton(AF_INET6, ip, SA_IN6_P(&addr));
		addr.ss_family = AF_INET6;
	} else {
		ret = inet_pton(AF_INET, ip, SA_IN_P(&addr));
		addr.ss_family = AF_INET;
	}

	if (ret != 1) {
		fprintf(stderr, "cannot convert IP: %s\n", ip);
		exit(1);
	}
	return check_if_banned(s, &addr, addr.ss_family==AF_INET?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6));
}

int main()
{
	main_server_st *s = talloc(NULL, struct main_server_st);
	if (s == NULL)
		exit(1);

	memset(s, 0, sizeof(*s));

	s->config = talloc(s, struct cfg_st);
	if (s->config == NULL)
		exit(1);

	memset(s->config, 0, sizeof(struct cfg_st));

	s->config->max_ban_score = 20;
	s->config->min_reauth_time = 30;

	main_ban_db_init(s);

	/* check IPv4 */
	add_str_ip_to_ban_list(s, "192.168.1.1", 5);
	add_str_ip_to_ban_list(s, "192.168.1.1", 10);
	add_str_ip_to_ban_list(s, "192.168.1.1", 5);

	add_str_ip_to_ban_list(s, "192.168.2.1", 5);

	add_str_ip_to_ban_list(s, "192.168.3.1", 40);

	cleanup_banned_entries(s);

	if (check_if_banned_str(s, "192.168.1.1") == 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (check_if_banned_str(s, "192.168.2.1") != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (check_if_banned_str(s, "192.168.3.1") == 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	/* check IPv6 */

	/* a single /64 */
	add_str_ip_to_ban_list(s, "fc8e:899a:0624:5a89:1a45:63d8:1c92:0bc1", 5);
	add_str_ip_to_ban_list(s, "fc8e:899a:0624:5a89:1a45:63d9:1c92:0bc1", 10);
	add_str_ip_to_ban_list(s, "fc8e:899a:0624:5a89:1a45:63d8:1c93:0bc1", 5);

	add_str_ip_to_ban_list(s, "fdd9:1ce6:1bee:bdea:5d8c:0840:8666:5942", 5);

	add_str_ip_to_ban_list(s, "fdc0:c81f:22ab:23a2:4479:f107:1855:bf50", 40);

	/* check /64 */
	if (check_if_banned_str(s, "fc8e:899a:0624:5a89:1a45:63d8:1c93:0bc1") == 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (check_if_banned_str(s, "fc8e:899a:0624:5a89:1a46:63d9:1c93:0bc1") == 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	/* check individual */
	if (check_if_banned_str(s, "fdd9:1ce6:1bee:bdea:5d8c:0840:8666:5942") != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (check_if_banned_str(s, "fdc0:c81f:22ab:23a2:4479:f107:1855:bf50") == 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	/* check expiration of entries */ 
	sleep(s->config->min_reauth_time+1);

	if (check_if_banned_str(s, "192.168.1.1") != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (check_if_banned_str(s, "192.168.2.1") != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (check_if_banned_str(s, "192.168.3.1") != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (check_if_banned_str(s, "fdc0:c81f:22ab:23a2:4479:f107:1855:bf50") != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	/* check cleanup */
	sleep(s->config->min_reauth_time+1);

	cleanup_banned_entries(s);

	if (main_ban_db_elems(s) != 0) {
		fprintf(stderr, "error in %d: have %d entries\n", __LINE__, main_ban_db_elems(s));
		exit(1);
	}


	talloc_free(s);
	return 0;
}
