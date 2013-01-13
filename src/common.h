#ifndef COMMON_H
#define COMMON_H

#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>

#define AC_PKT_DATA             0	/* Uncompressed data */
#define AC_PKT_DPD_OUT          3	/* Dead Peer Detection */
#define AC_PKT_DPD_RESP         4	/* DPD response */
#define AC_PKT_DISCONN          5	/* Client disconnection notice */
#define AC_PKT_KEEPALIVE        7	/* Keepalive */
#define AC_PKT_COMPRESSED       8	/* Compressed data */
#define AC_PKT_TERM_SERVER      9	/* Server kick */

extern int syslog_open;

#define MAX(x,y) ((x)>(y)?(x):(y))

const char *human_addr(const struct sockaddr *sa, socklen_t salen,
			      void *buf, size_t buflen);

#endif
