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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdbool.h>

#include <stdio.h>

#include <ip-lease.h>
#include <main.h>
#include <common.h>
#include <gnutls/crypto.h>
#include <icmp-ping.h>
#include <arpa/inet.h>

static void bignum_add (uint8_t * num, unsigned size, unsigned step)
{
  register int i;
  register unsigned tmp, y;

  for (i = size-1; i >= 0; i--)
    {
      tmp = num[i];
      
      num[i] += step;
      if (num[i] < tmp)
        y = 1;
      else
        y = 0;

      if (y == 0)
        break;
    }
}

void ip_from_seed(uint8_t *seed, unsigned seed_size,
		void *ip, size_t ip_size)
{
	uint8_t digest[20];
	int ret;

	if (ip_size > sizeof(digest)) {
		syslog(LOG_ERR, "too large IP!");
		abort();
	}

	ret = gnutls_hash_fast(GNUTLS_DIG_SHA1, seed, seed_size, digest);
	if (ret < 0) {
		syslog(LOG_ERR, "cannot hash: %s", strerror(ret));
		abort();
	}

	memcpy(ip, digest, ip_size);

}

void ip_lease_deinit(struct ip_lease_db_st* db)
{
struct ip_lease_st * cache;
struct htable_iter iter;

	cache = htable_first(&db->ht, &iter);
	while(cache != NULL) {
		/* disable the destructor */
		cache->db = NULL;
		talloc_free(cache);
		
		cache = htable_next(&db->ht, &iter);
	}
	htable_clear(&db->ht);
	
	return;
}

static size_t rehash(const void* _e, void* unused)
{
const struct ip_lease_st * e = _e;

	return hash_any(&e->rip, e->rip_len, 0);
}

void ip_lease_init(struct ip_lease_db_st* db)
{
	htable_init(&db->ht, rehash, NULL);
}

static bool ip_lease_cmp(const void* _c1, void* _c2)
{
const struct ip_lease_st* c1 = _c1;
struct ip_lease_st* c2 = _c2;

	if (c1->rip_len == c2->rip_len &&
		ip_cmp(&c1->rip, &c2->rip, c2->rip_len) == 0)
		return 1;

	return 0;
}

static int ip_lease_exists(main_server_st* s, struct sockaddr_storage* ip, size_t sockaddrlen)
{
struct ip_lease_st t;

	t.rip_len = sockaddrlen;
	memcpy(&t.rip, ip, sizeof(*ip));

 	if (htable_get(&s->ip_leases.ht, rehash(&t, NULL), ip_lease_cmp, &t) != 0)
		return 1;

	return 0;
}

void steal_ip_leases(struct proc_st* proc, struct proc_st *thief)
{
	thief->ipv4 = talloc_move(thief, &proc->ipv4);
	thief->ipv6 = talloc_move(thief, &proc->ipv6);
}

#define MAX_IP_TRIES 16

static
int get_ipv4_lease(main_server_st* s, struct proc_st* proc)
{

	struct sockaddr_storage tmp, mask, network, rnd;
	unsigned i;
	unsigned max_loops = MAX_IP_TRIES;
	int ret;
	const char* c_network, *c_netmask;
	char buf[64];
	
	if (proc->config.ipv4_network && proc->config.ipv4_netmask) {
		c_network = proc->config.ipv4_network;
		c_netmask = proc->config.ipv4_netmask;
	} else {
		c_network = s->config->network.ipv4;
		c_netmask = s->config->network.ipv4_netmask;
	}

	if (c_network && c_netmask) {
		ret =
		    inet_pton(AF_INET, c_network, SA_IN_P(&network));

		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "error reading IP: %s", c_network);
			return -1;
		}

		ret =
		    inet_pton(AF_INET, c_netmask, SA_IN_P(&mask));
	
		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "error reading mask: %s", c_netmask);
			return -1;
		}

		proc->ipv4 = talloc_zero(proc, struct ip_lease_st);
		if (proc->ipv4 == NULL)
			return ERR_MEM;
		proc->ipv4->db = &s->ip_leases;

		/* mask the network (just in case it is wrong) */
		for (i=0;i<sizeof(struct in_addr);i++)
			SA_IN_U8_P(&network)[i] &= (SA_IN_U8_P(&mask)[i]);
        	((struct sockaddr_in*)&network)->sin_family = AF_INET;
        	((struct sockaddr_in*)&network)->sin_port = 0;

        	memcpy(&tmp, &network, sizeof(tmp));
       		((struct sockaddr_in*)&tmp)->sin_family = AF_INET;
       		((struct sockaddr_in*)&tmp)->sin_port = 0;

		memset(&rnd, 0, sizeof(rnd));
		((struct sockaddr_in*)&rnd)->sin_family = AF_INET;
		((struct sockaddr_in*)&rnd)->sin_port = 0;

		do {
			if (max_loops == 0) {
				mslog(s, proc, LOG_ERR, "could not figure out a valid IPv4 IP.");
				ret = ERR_NO_IP;
				goto fail;
			}
			if (max_loops == MAX_IP_TRIES) {
				memcpy(SA_IN_U8_P(&rnd), proc->ipv4_seed, 4);
			} else {
				ip_from_seed(SA_IN_U8_P(&rnd), sizeof(struct in_addr),
						SA_IN_U8_P(&rnd), sizeof(struct in_addr));
			}
			max_loops--;

        		if (SA_IN_U8_P(&rnd)[3] == 255 || SA_IN_U8_P(&rnd)[3] == 254) /* avoid broadcast */
	        		bignum_add(SA_IN_U8_P(&rnd), sizeof(struct in_addr), 1);

			/* Mask the random number with the netmask */
        		for (i=0;i<sizeof(struct in_addr);i++) {
        			SA_IN_U8_P(&rnd)[i] &= ~(SA_IN_U8_P(&mask)[i]);
			}

			SA_IN_U8_P(&rnd)[sizeof(struct in_addr)-1] &= 0xFE;

			/* Now add the IP to the masked random number */
        		for (i=0;i<sizeof(struct in_addr);i++)
        			SA_IN_U8_P(&rnd)[i] |= (SA_IN_U8_P(&network)[i]);

 			/* check if it exists in the hash table */
			if (ip_lease_exists(s, &rnd, sizeof(struct sockaddr_in)) != 0) {
				mslog(s, proc, LOG_DEBUG, "cannot assign remote IP %s to '%s'; it is in use.", 
				      human_addr((void*)&rnd, sizeof(struct sockaddr_in), buf, sizeof(buf)), 
				      proc->username);
				continue;
			}

			memcpy(&proc->ipv4->lip, &rnd, sizeof(struct sockaddr_in));
        		proc->ipv4->lip_len = sizeof(struct sockaddr_in);

        		/* RIP = LIP + 1 */
        		memcpy(&tmp, &proc->ipv4->lip, sizeof(struct sockaddr_in));
        		bignum_add(SA_IN_U8_P(&tmp), sizeof(struct in_addr), 1);

 			/* check if it exists in the hash table */
			if (ip_lease_exists(s, &tmp, sizeof(struct sockaddr_in)) != 0) {
				mslog(s, proc, LOG_DEBUG, "cannot assign remote IP %s to '%s'; it is in use.", 
				      human_addr((void*)&tmp, sizeof(struct sockaddr_in), buf, sizeof(buf)), 
				      proc->username);
				continue;
			}

        		memcpy(&proc->ipv4->rip, &tmp, sizeof(struct sockaddr_in));
        		proc->ipv4->rip_len = sizeof(struct sockaddr_in);

        		/* mask the last IP with the netmask */
        		for (i=0;i<sizeof(struct in_addr);i++)
        			SA_IN_U8_P(&tmp)[i] &= (SA_IN_U8_P(&mask)[i]);

        		/* the result should match the network */
        		if (memcmp(SA_IN_U8_P(&network), SA_IN_U8_P(&tmp), sizeof(struct in_addr)) != 0) {
        			continue;
        		}

			mslog(s, proc, LOG_DEBUG, "selected IP for '%s': %s", proc->username,
			      human_addr((void*)&proc->ipv4->lip, proc->ipv4->lip_len, buf, sizeof(buf)));
        		
        		if (icmp_ping4(s, (void*)&proc->ipv4->lip, (void*)&proc->ipv4->rip) == 0)
        			break;
                } while(1);
	}

	return 0;

fail:
	talloc_free(proc->ipv4);
	proc->ipv4 = NULL;

	return ret;
}

static
int get_ipv6_lease(main_server_st* s, struct proc_st* proc)
{

	struct sockaddr_storage tmp, mask, network, rnd;
	unsigned i, max_loops = MAX_IP_TRIES;
	int ret;
	const char* c_network, *c_netmask;
	char buf[64];

	if (proc->config.ipv6_network && proc->config.ipv6_netmask) {
		c_network = proc->config.ipv6_network;
		c_netmask = proc->config.ipv6_netmask;
	} else {
		c_network = s->config->network.ipv6;
		c_netmask = s->config->network.ipv6_netmask;
	}

	if (c_network && c_netmask) {
		ret =
		    inet_pton(AF_INET6, c_network, SA_IN6_P(&network));

		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "error reading IP: %s", c_network);
			return -1;
		}

		ret =
		    inet_pton(AF_INET6, c_netmask, SA_IN6_P(&mask));
	
		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "error reading mask: %s", c_netmask);
			return -1;
		}
		
		proc->ipv6 = talloc_zero(proc, struct ip_lease_st);
		if (proc->ipv6 == NULL)
			return ERR_MEM;
		proc->ipv6->db = &s->ip_leases;

		/* mask the network */
		for (i=0;i<sizeof(struct in6_addr);i++)
			SA_IN6_U8_P(&network)[i] &= (SA_IN6_U8_P(&mask)[i]);
		((struct sockaddr_in6*)&network)->sin6_family = AF_INET6;
		((struct sockaddr_in6*)&network)->sin6_port = 0;

       		memcpy(&tmp, &network, sizeof(tmp));
        	((struct sockaddr_in6*)&tmp)->sin6_family = AF_INET6;
        	((struct sockaddr_in6*)&tmp)->sin6_port = 0;

        	((struct sockaddr_in6*)&rnd)->sin6_family = AF_INET6;
        	((struct sockaddr_in6*)&rnd)->sin6_port = 0;

		do {
			if (max_loops == 0) {
				mslog(s, NULL, LOG_ERR, "could not figure out a valid IPv6 IP.");
				ret = ERR_NO_IP;
				goto fail;
			}
			
			if (max_loops == MAX_IP_TRIES) {
				memset(SA_IN6_U8_P(&rnd), 0, sizeof(struct in6_addr));
				memcpy(SA_IN6_U8_P(&rnd)+sizeof(struct in6_addr)-5, proc->ipv4_seed, 4);
			} else {
				ip_from_seed(SA_IN6_U8_P(&rnd), sizeof(struct in6_addr),
						SA_IN6_U8_P(&rnd), sizeof(struct in6_addr));
			}
			max_loops--;
			
			/* Mask the random number with the netmask */
        		for (i=0;i<sizeof(struct in6_addr);i++)
        			SA_IN6_U8_P(&rnd)[i] &= ~(SA_IN6_U8_P(&mask)[i]);

			SA_IN6_U8_P(&rnd)[sizeof(struct in6_addr)-1] &= 0xFE;

			/* Now add the network to the masked random number */
        		for (i=0;i<sizeof(struct in6_addr);i++)
        			SA_IN6_U8_P(&rnd)[i] |= (SA_IN6_U8_P(&network)[i]);
        			
 			/* check if it exists in the hash table */
			if (ip_lease_exists(s, &rnd, sizeof(struct sockaddr_in6)) != 0) {
				mslog(s, proc, LOG_DEBUG, "cannot assign local IP %s to '%s'; it is in use.", 
				      human_addr((void*)&rnd, sizeof(struct sockaddr_in6), buf, sizeof(buf)), 
				      proc->username);
				continue;
			}

        		proc->ipv6->lip_len = sizeof(struct sockaddr_in6);
        		memcpy(&proc->ipv6->lip, &rnd, proc->ipv6->lip_len);

        		/* RIP = LIP + 1 */
        		memcpy(&tmp, &proc->ipv6->lip, sizeof(tmp));
        		proc->ipv6->rip_len = proc->ipv6->lip_len;

	        	bignum_add(SA_IN6_U8_P(&tmp), sizeof(struct in6_addr), 1);

 			/* check if it exists in the hash table */
			if (ip_lease_exists(s, &tmp, sizeof(struct sockaddr_in6)) != 0) {
				mslog(s, proc, LOG_DEBUG, "cannot assign remote IP %s to '%s'; it is in use.", 
				      human_addr((void*)&tmp, sizeof(struct sockaddr_in6), buf, sizeof(buf)), 
				      proc->username);
				continue;
			}

        		memcpy(&proc->ipv6->rip, &tmp, proc->ipv6->rip_len);

        		/* mask the last IP with the netmask */
        		for (i=0;i<sizeof(struct in6_addr);i++)
	        		SA_IN6_U8_P(&tmp)[i] &= (SA_IN6_U8_P(&mask)[i]);

        		/* the result should match the network */
	        	if (memcmp(SA_IN6_U8_P(&network), SA_IN6_U8_P(&tmp), sizeof(struct in6_addr)) != 0) {
		        	continue;
	        	}

			mslog(s, proc, LOG_DEBUG, "selected IP for '%s': %s", proc->username,
			      human_addr((void*)&proc->ipv6->lip, proc->ipv6->lip_len, buf, sizeof(buf)));

	        	if (icmp_ping6(s, (void*)&proc->ipv6->lip, (void*)&proc->ipv6->rip) == 0)
	        		break;
                } while(1);
	}

	return 0;
fail:
	talloc_free(proc->ipv6);
	proc->ipv6 = NULL;

	return ret;

}

static
int unref_ip_lease(struct ip_lease_st * lease)
{
	if (lease->db) {
		htable_del(&lease->db->ht, rehash(lease, NULL), lease);
	}
	return 0;
}

int get_ip_leases(main_server_st* s, struct proc_st* proc)
{
int ret;
char buf[128];

	if (proc->ipv4 == NULL) {
		ret = get_ipv4_lease(s, proc);
		if (ret < 0)
			return ret;

		if (proc->ipv4) {
			if (htable_add(&s->ip_leases.ht, rehash(proc->ipv4, NULL), proc->ipv4) == 0) {
				mslog(s, proc, LOG_ERR, "could not add IPv4 lease to hash table.");
				return -1;
			}
			talloc_set_destructor(proc->ipv4, unref_ip_lease);
		}
	}

	if (proc->ipv6 == NULL) {
		ret = get_ipv6_lease(s, proc);
		if (ret < 0)
			return ret;

		if (proc->ipv6) {
			if (htable_add(&s->ip_leases.ht, rehash(proc->ipv6, NULL), proc->ipv6) == 0) {
				mslog(s, proc, LOG_ERR, "could not add IPv6 lease to hash table.");
				return -1;
			}
			talloc_set_destructor(proc->ipv6, unref_ip_lease);
		}
	}

	if (proc->ipv4 == 0 && proc->ipv6 == 0) {
		mslog(s, proc, LOG_ERR, "no IPv4 or IPv6 addresses are configured. Cannot obtain lease.");
		return -1;
	}
	
	if (proc->ipv4)
		mslog(s, proc, LOG_INFO, "assigned IPv4 to '%s': %s", proc->username,
			human_addr((void*)&proc->ipv4->rip, proc->ipv4->rip_len, buf, sizeof(buf)));

	if (proc->ipv6)
		mslog(s, proc, LOG_INFO, "assigned IPv6 to '%s': %s", proc->username,
			human_addr((void*)&proc->ipv6->rip, proc->ipv6->rip_len, buf, sizeof(buf)));

	return 0;
}

void remove_ip_leases(main_server_st* s, struct proc_st* proc)
{
	if (proc->ipv4) {
		talloc_free(proc->ipv4);
		proc->ipv4 = NULL;
	}
	if (proc->ipv6) {
		talloc_free(proc->ipv6);
		proc->ipv6 = NULL;
	}
}

void remove_ip_lease(main_server_st* s, struct ip_lease_st * lease)
{
	talloc_free(lease);
}
