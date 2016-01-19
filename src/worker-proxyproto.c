/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <worker.h>

/* This file implements the Proxy Protocol v2, as described in:
 * http://www.haproxy.org/download/1.6/doc/proxy-protocol.txt
 *
 * That allows to obtain the detailed peer information even when
 * the session is received by a proxy.
 */

#define PROXY_HEADER_V2 "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define PROXY_HEADER_V2_SIZE (sizeof(PROXY_HEADER_V2)-1)

#define AVAIL_HEADER_SIZE(hsize, want) { \
	if (hsize < want) { \
		oclog(ws, LOG_ERR, "invalid TLV header"); \
		return; \
	} \
	hsize -= want; \
	}

typedef struct proxy_hdr_v2 {
	uint8_t sig[PROXY_HEADER_V2_SIZE];
	uint8_t ver_cmd;
	uint8_t family;
	uint16_t len;
	uint8_t data[520];
} _ATTR_PACKED proxy_hdr_v2;

#define PP2_TYPE_SSL           0x20
#define PP2_TYPE_SSL_CN        0x22

#define PP2_CLIENT_SSL           0x01
#define PP2_CLIENT_CERT_CONN     0x02
#define PP2_CLIENT_CERT_SESS     0x04

typedef struct pp2_tlv {
	uint8_t type;
	uint16_t length;
} _ATTR_PACKED pp2_tlv;

typedef struct pp2_tlv_ssl {
	uint8_t  client;
	uint32_t verify;
} _ATTR_PACKED pp2_tlv_ssl;

static void parse_ssl_tlvs(struct worker_st *ws, uint8_t *data, int data_size)
{
	pp2_tlv tlv;

	while(data_size > 0) {
		AVAIL_HEADER_SIZE(data_size, sizeof(pp2_tlv));
		memcpy(&tlv, data, sizeof(pp2_tlv));

		/* that seems to be in little endian */
		tlv.length = htons(tlv.length);

		data += sizeof(pp2_tlv);

		oclog(ws, LOG_INFO, "proxy-hdr: TLV type %x", (unsigned)tlv.type);
		if (tlv.type == PP2_TYPE_SSL) {
			pp2_tlv_ssl tssl;
			if (tlv.length < sizeof(pp2_tlv_ssl)) {
				oclog(ws, LOG_ERR, "proxy-hdr: TLV SSL header size is invalid");
				continue;
			}
			tlv.length = sizeof(pp2_tlv_ssl);
			AVAIL_HEADER_SIZE(data_size, tlv.length);

			memcpy(&tssl, data, sizeof(pp2_tlv_ssl));

			if ((tssl.client & PP2_CLIENT_SSL) && 
			    (tssl.client & PP2_CLIENT_CERT_SESS) &&
			    (tssl.verify == 0)) {
				oclog(ws, LOG_INFO, "proxy-hdr: user has presented valid certificate");
			    	ws->cert_auth_ok = 1;
			    	
			}
		} else if (tlv.type == PP2_TYPE_SSL_CN && ws->cert_auth_ok) {
			if (tlv.length > sizeof(ws->cert_username)-1) {
				oclog(ws, LOG_ERR, "proxy-hdr: TLV SSL CN header size is too long");
				continue;
			}

			AVAIL_HEADER_SIZE(data_size, tlv.length);

			memcpy(ws->cert_username, data, tlv.length);
			ws->cert_username[tlv.length] = 0;

			oclog(ws, LOG_INFO, "proxy-hdr: user's name is '%s'", ws->cert_username);
		} else {
			AVAIL_HEADER_SIZE(data_size, tlv.length);
		}

		data += tlv.length;
	}

}

/* This parses a version 2 Proxy protocol header (from haproxy).
 *
 * When called from a UNIX socket (where we don't have any SSL
 * info), we additionally read information about the SSL session.
 * We expect to receive the peer's certificate verification status,
 * and CN. That corresponds to send-proxy-v2-ssl-cn and send-proxy-v2-ssl
 * haproxy config options.
 */
int parse_proxy_proto_header(struct worker_st *ws, int fd)
{
	proxy_hdr_v2 hdr;
	int data_size;
	uint8_t cmd, family, proto;
	uint8_t ver;
	uint8_t *p;
	int ret;

	ret = force_read_timeout(fd, &hdr, 16, DEFAULT_SOCKET_TIMEOUT);
	if (ret < 0) {
		oclog(ws, LOG_ERR,
		      "proxy-hdr: recv timed out");
		return -1;
	}

	if (ret < 16) {
		oclog(ws, LOG_ERR, "proxy-hdr: invalid v2 header size");
		return -1;
	}

	if (memcmp(hdr.sig, PROXY_HEADER_V2, PROXY_HEADER_V2_SIZE) != 0) {
		oclog(ws, LOG_ERR, "proxy-hdr: invalid v2 header");
		return -1;
	}

	data_size = ntohs(hdr.len);

	if (data_size > sizeof(hdr.data)) {
		oclog(ws, LOG_ERR, "proxy-hdr: too long v2 header size");
		return -1;
	}

	ret = force_read_timeout(fd, hdr.data, data_size, DEFAULT_SOCKET_TIMEOUT);
	if (ret < 0) {
		oclog(ws, LOG_ERR,
		      "proxy-hdr: recv data timed out");
		return -1;
	}

	cmd = hdr.ver_cmd & 0x0f;
	ver = (hdr.ver_cmd & 0xf0) >> 4;
	if (ver != 0x02) {
		oclog(ws, LOG_ERR, "proxy-hdr: unsupported version (%x), skipping message", (unsigned)ver);
		return 0;
	}

	if (cmd != 0x01) {
		if (hdr.family == 0)
			oclog(ws, LOG_DEBUG, "proxy-hdr: received health check command");
		else
			oclog(ws, LOG_ERR, "proxy-hdr: received unsupported command %x", (unsigned)cmd);
		return -1;
	}

	family = (hdr.family & 0xf0) >> 4;
	proto = hdr.family & 0x0f;

	if (family != 0x1 && family != 0x2) {
		oclog(ws, LOG_ERR, "proxy-hdr: received unsupported family %x; skipping header", (unsigned)family);
		return 0;
	}

	if ((proto != 0x1 && proto != 0x0)) {
		oclog(ws, LOG_ERR, "proxy-hdr: received unsupported protocol %x; skipping header", (unsigned)proto);
		return 0;
	}

	p = hdr.data;

	if (family == 0x01) { /* AF_INET */
		struct sockaddr_in *sa = (void*)&ws->remote_addr;

		if (data_size < 12) {
			oclog(ws, LOG_INFO, "proxy-hdr: received not enough IPv4 data");
			return 0;
		}

		memset(&ws->remote_addr, 0, sizeof(ws->remote_addr));
		sa->sin_family = AF_INET;
		memcpy(&sa->sin_port, p+8, 2);
		memcpy(&sa->sin_addr, p, 4);
		ws->remote_addr_len = sizeof(struct sockaddr_in);

		memset(&ws->our_addr, 0, sizeof(ws->our_addr));
		sa = (void*)&ws->our_addr;
		sa->sin_family = AF_INET;
		memcpy(&sa->sin_addr, p+4, 4);
		memcpy(&sa->sin_port, p+10, 2);
		ws->our_addr_len = sizeof(struct sockaddr_in);

		p += 12;
		data_size -= 12;
	} else if (family == 0x02) { /* AF_INET6 */
		struct sockaddr_in6 *sa = (void*)&ws->remote_addr;

		if (data_size < 36) {
			oclog(ws, LOG_INFO, "proxy-hdr: received not enough IPv6 data");
			return 0;
		}

		memset(&ws->remote_addr, 0, sizeof(ws->remote_addr));
		sa->sin6_family = AF_INET6;
		sa->sin6_port = 0;
		memcpy(&sa->sin6_addr, p, 16);
		memcpy(&sa->sin6_port, p+32, 2);
		ws->remote_addr_len = sizeof(struct sockaddr_in6);

		memset(&ws->our_addr, 0, sizeof(ws->our_addr));
		sa->sin6_family = AF_INET6;
		sa = (void*)&ws->our_addr;
		memcpy(&sa->sin6_addr, p+16, 16);
		memcpy(&sa->sin6_port, p+34, 2);
		ws->our_addr_len = sizeof(struct sockaddr_in);

		p += 36;
		data_size -= 36;
	}

	/* Find CN if needed */
	if (ws->conn_type == SOCK_TYPE_UNIX && data_size > 0) {
		parse_ssl_tlvs(ws, p, data_size);
	}

	return 0;
}
