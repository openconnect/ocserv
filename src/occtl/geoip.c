/*
 * Copyright (c) 2015-2017 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *   Nikos Mavrogiannopoulos <nmav@redhat.com>
 */

#define _GNU_SOURCE		/* asprintf */
#include <config.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>

#ifdef HAVE_GEOIP

# include <GeoIP.h>
# include <GeoIPCity.h>

extern void _GeoIP_setup_dbfilename(void);
# define p_GeoIP_setup_dbfilename _GeoIP_setup_dbfilename
# define pGeoIP_open_type GeoIP_open_type
# define pGeoIP_country_name_by_id GeoIP_country_name_by_id
# define pGeoIP_delete GeoIP_delete
# define pGeoIP_record_by_ipnum GeoIP_record_by_ipnum
# define pGeoIP_id_by_ipnum GeoIP_id_by_ipnum
# define pGeoIP_id_by_ipnum_v6 GeoIP_id_by_ipnum_v6
# define pGeoIP_record_by_ipnum_v6 GeoIP_record_by_ipnum_v6
# define pGeoIP_code_by_id GeoIP_code_by_id

int geo_setup(void)
{
	static unsigned init = 0;

	if (init == 0) {
		p_GeoIP_setup_dbfilename();
		init = 1;
	}

	return 0;
}

void geo_ipv4_lookup(struct in_addr ip, char **country, char **city, char **coord)
{
	GeoIP *gi;
	GeoIPRecord *gir;
	int country_id;
	const char *p;

	if (geo_setup() != 0)
		return;

	ip.s_addr = ntohl(ip.s_addr);

	gi = pGeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		country_id = pGeoIP_id_by_ipnum(gi, ip.s_addr);
		if (country_id < 0) {
			return;
		}
		p = pGeoIP_country_name_by_id(gi, country_id);
		if (p)
			*country = strdup(p);

		pGeoIP_delete(gi);
	}

	gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV1, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		gir = pGeoIP_record_by_ipnum(gi, ip.s_addr);

		if (gir && gir->city)
			*city = strdup(gir->city);

		if (gir && gir->longitude != 0 && gir->longitude != 0)
			asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

		pGeoIP_delete(gi);
	} else {
		gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV0, GEOIP_STANDARD | GEOIP_SILENCE);
		if (gi != NULL) {
			gi->charset = GEOIP_CHARSET_UTF8;

			gir = pGeoIP_record_by_ipnum(gi, ip.s_addr);

			if (gir && gir->city)
				*city = strdup(gir->city);

			if (gir && gir->longitude != 0 && gir->longitude != 0)
				asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

			pGeoIP_delete(gi);
		}
	}

	return;
}

void geo_ipv6_lookup(struct in6_addr *ip, char **country, char **city, char **coord)
{
	GeoIP *gi;
	GeoIPRecord *gir;
	int country_id;
	const char *p;

	if (geo_setup() != 0)
		return;

	gi = pGeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		country_id = pGeoIP_id_by_ipnum_v6(gi, (geoipv6_t)*ip);
		if (country_id < 0) {
			return;
		}
		p = pGeoIP_country_name_by_id(gi, country_id);
		if (p)
			*country = strdup(p);

		pGeoIP_delete(gi);
	}

	gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV1_V6, GEOIP_STANDARD | GEOIP_SILENCE);
	if (gi != NULL) {
		gi->charset = GEOIP_CHARSET_UTF8;

		gir = pGeoIP_record_by_ipnum_v6(gi, (geoipv6_t)*ip);

		if (gir && gir->city)
			*city = strdup(gir->city);

		if (gir && gir->longitude != 0 && gir->longitude != 0)
			asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

		pGeoIP_delete(gi);
	} else {
		gi = pGeoIP_open_type(GEOIP_CITY_EDITION_REV0_V6, GEOIP_STANDARD | GEOIP_SILENCE);
		if (gi != NULL) {
			gi->charset = GEOIP_CHARSET_UTF8;

			gir = pGeoIP_record_by_ipnum_v6(gi, (geoipv6_t)*ip);

			if (gir && gir->city)
				*city = strdup(gir->city);

			if (gir && gir->longitude != 0 && gir->longitude != 0)
				asprintf(coord, "%f,%f", gir->latitude, gir->longitude);

			pGeoIP_delete(gi);
		}
	}

	return;
}

char *geo_lookup(const char *ip, char *buf, unsigned buf_size)
{
	char *country = NULL;
	char *city = NULL;
	char *coord = NULL;

	if (strchr(ip, ':') != NULL) {
		struct in6_addr addr;

		if (inet_pton(AF_INET6, ip, &addr) == 0)
			goto fail;
		geo_ipv6_lookup(&addr, &country, &city, &coord);
	} else { /*ipv4*/
		struct in_addr addr;

		if (inet_pton(AF_INET, ip, &addr) == 0)
			goto fail;
		geo_ipv4_lookup(addr, &country, &city, &coord);
	}

	if (country && city && coord) {
		snprintf(buf, buf_size, "%s, %s (%s)", city, country, coord);
	} else if (country && city) {
		snprintf(buf, buf_size, "%s, %s", city, country);
	} else if (country) {
		snprintf(buf, buf_size, "%s", country);
	} else
		goto fail;

	free(country);
	free(city);
	free(coord);

	return buf;

 fail:
	free(country);
	free(city);
	free(coord);

	return "unknown";
}

#else
char * geo_lookup(const char *ip, char *buf, unsigned buf_size)
{
	return "unknown";
}
#endif
