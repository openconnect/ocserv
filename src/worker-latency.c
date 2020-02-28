/*
 * Copyright (C) 2013-2018 Nikos Mavrogiannopoulos
 * Copyright (C) 2015, 2016 Red Hat, Inc.
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

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <math.h>
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>
#include <worker.h>
#include <worker-latency.h>


ssize_t dtls_pull_latency(gnutls_transport_ptr_t ptr, void *data, size_t size)
{
	int err;
	dtls_transport_ptr *p = ptr;
	p->rx_time.tv_sec = 0;
	p->rx_time.tv_nsec = 0;

	if (p->msg) {
		ssize_t need = p->msg->data.len;
		if (need > size) {
			need = size;
		}
		memcpy(data, p->msg->data.data, need);

		udp_fd_msg__free_unpacked(p->msg, NULL);
		p->msg = NULL;
		return need;
	}

	char controlbuf[1024];
	struct cmsghdr * cmsg;

	struct iovec io = {
		.iov_base = data,
		.iov_len = size,
	};
	struct msghdr hdr = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_control = controlbuf,
		.msg_controllen = sizeof(controlbuf)
	};
	err = recvmsg(p->fd, &hdr, 0);
	if (err >= 0) {
		for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
			struct scm_timestamping *tss = NULL;
			if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_TIMESTAMPING) {
				continue;
			}
			tss = (struct scm_timestamping *) CMSG_DATA(cmsg);
			p->rx_time = tss->ts[0];
		}
	}
	return err;
}


void send_latency_stats_delta_to_main(worker_st * ws, time_t now)
{
	LatencyStatsDelta msg = LATENCY_STATS_DELTA__INIT;
	
	if (ws->latency.sample_set_count == 0) {
		return;
	}

	msg.median_delta = ws->latency.median_total;
	msg.rms_delta = ws->latency.rms_total;
	msg.sample_count_delta = ws->latency.sample_set_count;
	
	ws->latency.median_total = 0;
	ws->latency.rms_total = 0;
	ws->latency.sample_set_count = 0;

	send_msg_to_main(ws, CMD_LATENCY_STATS_DELTA, &msg,
			 (pack_size_func) latency_stats_delta__get_packed_size,
			 (pack_func) latency_stats_delta__pack);

	ws->latency.last_stats_msg = now;
}

static int greater_than(const void * a, const void * b)
{
    const unsigned long lhs = *(const unsigned long*)a;
    const unsigned long rhs = *(const unsigned long*)b;
    return rhs - lhs;
}

void capture_latency_sample(struct worker_st* ws, struct timespec *processing_start_time)
{
	struct timespec now;
	gettime_realtime(&now);
	unsigned long sample = (unsigned long)timespec_sub_us(&now, processing_start_time);
	if (ws->latency.next_sample == LATENCY_SAMPLE_SIZE) {
		unsigned long median;
		uint64_t total = 0;
		long double sum_of_squares = 0;
		uint64_t mean = 0;
		uint64_t rms = 0;
		int i;

		ws->latency.next_sample = 0;
		qsort(ws->latency.samples, LATENCY_SAMPLE_SIZE, sizeof(ws->latency.samples[0]), greater_than);
		median = ws->latency.samples[LATENCY_SAMPLE_SIZE - 1];

		for (i = 0; i < LATENCY_SAMPLE_SIZE; i ++) {
			total += ws->latency.samples[i];
		}

		mean = total / LATENCY_SAMPLE_SIZE;
		for (i = 0; i < LATENCY_SAMPLE_SIZE; i ++) {
			long double delta = (long double)ws->latency.samples[i];
			delta -= mean;
			sum_of_squares += delta * delta;
		}

		rms = (uint64_t)sqrt(sum_of_squares / LATENCY_SAMPLE_SIZE);

		(ws->latency.median_total) += median;
		(ws->latency.rms_total) += rms;
		(ws->latency.sample_set_count) ++;
    }
    ws->latency.samples[(ws->latency.next_sample)++] = sample;

}
