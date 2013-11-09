/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#ifndef GETTIME_H
#define GETTIME_H

#include <config.h>
#include <time.h>
#include <sys/time.h>

/* emulate gnulib's gettime using gettimeofday to avoid linking to
 * librt */
inline static void
gettime (struct timespec *t)
{
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_REALTIME_COARSE)
  clock_gettime (CLOCK_REALTIME_COARSE, t);
#elif defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_REALTIME)
  clock_gettime (CLOCK_REALTIME, t);
#else
struct timeval tv;
  gettimeofday (&tv, NULL);
  t->tv_sec = tv.tv_sec;
  t->tv_nsec = tv.tv_usec * 1000;
#endif
}

inline static
unsigned int
timespec_sub_ms (struct timespec *a, struct timespec *b)
{
  return (a->tv_sec * 1000 + a->tv_nsec / (1000 * 1000) -
          (b->tv_sec * 1000 + b->tv_nsec / (1000 * 1000)));
}

#endif
