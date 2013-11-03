#ifndef WORKER_BANDWIDTH_H
# define WORKER_BANDWIDTH_H

#include <time.h>
#include <unistd.h>

typedef struct bandwidth_st {
	struct timespec count_start;
	size_t transferred_bytes;
	size_t allowed_bytes;

	size_t bytes_per_sec;
} bandwidth_st;

inline static void bandwidth_init(bandwidth_st* b, size_t bytes_per_sec)
{
	memset(b, 0, sizeof(*b));
	b->bytes_per_sec = bytes_per_sec;
}

/* returns true or false, depending on whether to send
 * the bytes */
int bandwidth_update(bandwidth_st* b, size_t bytes, size_t mtu);


#endif
