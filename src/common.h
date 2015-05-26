/*
 * Copyright (C) 2013, 2014 Nikos Mavrogiannopoulos
 * Copyright (C) 2014 Red Hat, Inc.
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
#ifndef COMMON_H
# define COMMON_H

#include <sys/socket.h>
#include <ipc.pb-c.h>
#include <talloc.h>
#include <time.h>
#include <string.h>

void _talloc_free2(void *ctx, void *ptr);
void *_talloc_size2(void *ctx, size_t size);

#define MAX_IP_STR 46

#define PROTOBUF_ALLOCATOR(name, pool) \
	ProtobufCAllocator name = {.alloc = _talloc_size2, .free = _talloc_free2, .allocator_data = pool}

#define DEFAULT_SOCKET_TIMEOUT 10

void set_non_block(int fd);
void set_block(int fd);

ssize_t force_write(int sockfd, const void *buf, size_t len);
ssize_t force_read(int sockfd, void *buf, size_t len);
ssize_t force_read_timeout(int sockfd, void *buf, size_t len, unsigned sec);
ssize_t recv_timeout(int sockfd, void *buf, size_t len, unsigned sec);
int ip_cmp(const struct sockaddr_storage *s1, const struct sockaddr_storage *s2);
char* ipv4_prefix_to_mask(void *pool, unsigned prefix);
char* ipv6_prefix_to_mask(char buf[MAX_IP_STR], unsigned prefix);
inline static int valid_ipv6_prefix(unsigned prefix)
{
	if (prefix > 10 && prefix <= 128)
		return 1;
	else
		return 0;
}

typedef size_t (*pack_func)(const void*, uint8_t *);
typedef size_t (*pack_size_func)(const void*);

typedef void* (*unpack_func)(ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);

int send_msg(void *pool, int fd, uint8_t cmd, 
	    const void* msg, pack_size_func get_size, pack_func pack);

int send_socket_msg(void *pool, int fd, uint8_t cmd, 
		    int socketfd,
		    const void* msg, pack_size_func get_size, pack_func pack);

/* the timeout is in seconds */
int recv_msg(void *pool, int fd, uint8_t cmd, 
	     void** msg, unpack_func, unsigned timeout);

int recv_socket_msg(void *pool, int fd, uint8_t cmd, 
			int *socketfd, void** msg, unpack_func, unsigned timeout);

const char* cmd_request_to_str(unsigned cmd);

ssize_t oc_recvfrom_at(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen,
                    struct sockaddr *our_addr, socklen_t *our_addrlen,
                    int def_port);

inline static
void safe_memset(void *data, int c, size_t size)
{
	volatile unsigned volatile_zero = 0;
	volatile char *vdata = (volatile char*)data;

	/* This is based on a nice trick for safe memset,
	 * sent by David Jacobson in the openssl-dev mailing list.
	 */

	if (size > 0)
		do {
			memset(data, c, size);
		} while(vdata[volatile_zero] != c);
}

inline static
void ms_sleep(unsigned ms)
{
  struct timespec tv;

  tv.tv_sec = 0;
  tv.tv_nsec = ms * 1000 * 1000;

  while(tv.tv_nsec >= 1000000000) {
  	tv.tv_nsec -= 1000000000;
  	tv.tv_sec++;
  }
  
  nanosleep(&tv, NULL);
}

#ifndef HAVE_STRLCPY
size_t oc_strlcpy(char *dst, char const *src, size_t siz);
# define strlcpy oc_strlcpy
#endif

#endif
