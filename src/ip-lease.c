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
#include <ip-util.h>
#include <gnutls/crypto.h>
#include <icmp-ping.h>
#include <arpa/inet.h>

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

	return hash_any(SA_IN_P_GENERIC(&e->sig, e->sig_len), SA_IN_SIZE(e->sig_len), 0);
}

void ip_lease_init(struct ip_lease_db_st* db)
{
	htable_init(&db->ht, rehash, NULL);
}

static bool ip_lease_cmp(const void* _c1, void* _c2)
{
const struct ip_lease_st* c1 = _c1;
struct ip_lease_st* c2 = _c2;

	if (c1->sig_len == c2->sig_len &&
		ip_cmp(&c1->sig, &c2->sig) == 0)
		return 1;

	return 0;
}

static int ip_lease_exists(main_server_st* s, struct sockaddr_storage* ip, size_t sockaddrlen)
{
struct ip_lease_st t;

	t.sig_len = sockaddrlen;
	memcpy(&t.sig, ip, sizeof(*ip));

 	if (htable_get(&s->ip_leases.ht, rehash(&t, NULL), ip_lease_cmp, &t) != 0)
		return 1;

	return 0;
}

void steal_ip_leases(struct proc_st* proc, struct proc_st *thief)
{
	/* here we reset the old tun device, and assign the old addresses
	 * to a new device. We cannot re-use the old device because the
	 * fd is only available to the worker process and not here (main)
	 */
	reset_tun(proc);

	thief->ipv4 = talloc_move(thief, &proc->ipv4);
	thief->ipv6 = talloc_move(thief, &proc->ipv6);
}

static int is_ipv6_ok(main_server_st *s, struct sockaddr_storage *ip, struct sockaddr_storage *net, struct sockaddr_storage *subnet)
{
	/* check that IP & mask don't match network - i.e., the network's IP is outside
	 * that subnet; we use it in the tun device */
	if (memcmp(SA_IN6_U8_P(subnet), SA_IN6_U8_P(net), 16) == 0) {
		return 0;
	}

	/* check that the IP's subnet is not registered already */
	if (ip_lease_exists(s, subnet, sizeof(struct sockaddr_in6)) != 0) {
		return 0;
	}

	return 1;
}

static int is_ipv4_ok(main_server_st *s, struct sockaddr_storage *ip, struct sockaddr_storage *net, struct sockaddr_storage *mask)
{
	struct sockaddr_storage broadcast;
	unsigned i;

	memcpy(&broadcast, net, sizeof(broadcast));
	for (i=0;i<sizeof(struct in_addr);i++) {
		SA_IN_U8_P(&broadcast)[i] |= ~(SA_IN_U8_P(mask)[i]);
	}

	if (ip_lease_exists(s, ip, sizeof(struct sockaddr_in)) != 0 ||
	    ip_cmp(ip, net) == 0 ||
	    ip_cmp(ip, &broadcast) == 0) {
	    return 0;
	}
	return 1;
}

#define MAX_IP_TRIES 16
#define FIXED_IPS 5

static
int get_ipv4_lease(main_server_st* s, struct proc_st* proc)
{

	struct sockaddr_storage tmp, mask, network, rnd;
	unsigned i;
	unsigned max_loops = MAX_IP_TRIES;
	int ret;
	const char *c_network, *c_netmask;
	char buf[64];

	/* Our IP accounting */
	if (proc->config->ipv4_net && proc->config->ipv4_netmask) {
		/* We only read from user/group configuration as this
		 * is updated with the current vhost information */
		c_network = proc->config->ipv4_net;
		c_netmask = proc->config->ipv4_netmask;
	} else {
		c_network = proc->vhost->perm_config.config->network.ipv4;
		c_netmask = proc->vhost->perm_config.config->network.ipv4_netmask;
	}

	if (c_network == NULL || c_netmask == NULL) {
		mslog(s, NULL, LOG_DEBUG, "there is no IPv4 network assigned");
		return 0;
	}

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

	/* mask the network (just in case it is wrong) */
	for (i=0;i<sizeof(struct in_addr);i++)
		SA_IN_U8_P(&network)[i] &= (SA_IN_U8_P(&mask)[i]);
       	((struct sockaddr_in*)&network)->sin_family = AF_INET;
       	((struct sockaddr_in*)&network)->sin_port = 0;

	if (proc->config->explicit_ipv4) {
		ret =
		    inet_pton(AF_INET, proc->config->explicit_ipv4, SA_IN_P(&tmp));

		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "error reading explicit IP: %s", proc->config->explicit_ipv4);
			return -1;
		}

		proc->ipv4 = talloc_zero(proc, struct ip_lease_st);
		if (proc->ipv4 == NULL)
			return ERR_MEM;

        	((struct sockaddr_in*)&tmp)->sin_family = AF_INET;
        	((struct sockaddr_in*)&tmp)->sin_port = 0;
		memcpy(&proc->ipv4->rip, &tmp, sizeof(struct sockaddr_in));
       		proc->ipv4->rip_len = sizeof(struct sockaddr_in);

		memcpy(&proc->ipv4->sig, &tmp, sizeof(struct sockaddr_in));

		if (is_ipv4_ok(s, &proc->ipv4->rip, &network, &mask) == 0) {
			mslog(s, proc, LOG_DEBUG, "cannot assign explicit IP %s; it is in use or invalid", 
			      human_addr((void*)&tmp, sizeof(struct sockaddr_in), buf, sizeof(buf)));
			ret = ERR_NO_IP;
			goto fail;
		}

		/* LIP = network address + 1 */
		memcpy(&proc->ipv4->lip, &network, sizeof(struct sockaddr_in));
		proc->ipv4->lip_len = sizeof(struct sockaddr_in);
		SA_IN_U8_P(&proc->ipv4->lip)[3] |= 1;

		if (ip_cmp(&proc->ipv4->lip, &proc->ipv4->rip) == 0) {
			mslog(s, NULL, LOG_ERR, "cannot assign explicit IP %s; network: %s", proc->config->explicit_ipv4, c_network);
			ret = ERR_NO_IP;
			goto fail;
		}

		return 0;
	}

	/* assign "random" IP */
	proc->ipv4 = talloc_zero(proc, struct ip_lease_st);
	if (proc->ipv4 == NULL)
		return ERR_MEM;
	proc->ipv4->db = &s->ip_leases;

       	memcpy(&tmp, &network, sizeof(tmp));
     	((struct sockaddr_in*)&tmp)->sin_family = AF_INET;
	((struct sockaddr_in*)&tmp)->sin_port = 0;

	memset(&rnd, 0, sizeof(rnd));
	((struct sockaddr_in*)&rnd)->sin_family = AF_INET;
	((struct sockaddr_in*)&rnd)->sin_port = 0;

	do {
		if (max_loops == 0) {
			mslog(s, proc, LOG_ERR, "could not figure out a valid IPv4 IP");
			ret = ERR_NO_IP;
			goto fail;
		}
		if (max_loops == MAX_IP_TRIES) {
			memcpy(SA_IN_U8_P(&rnd), proc->ipv4_seed, 4);
		} else {
			if (max_loops < MAX_IP_TRIES-FIXED_IPS) {
				gnutls_rnd(GNUTLS_RND_NONCE, SA_IN_U8_P(&rnd), sizeof(struct in_addr));
			} else {
				ip_from_seed(SA_IN_U8_P(&rnd), sizeof(struct in_addr),
					     SA_IN_U8_P(&rnd), sizeof(struct in_addr));
			}
		}
		max_loops--;

		/* Mask the random number with the netmask */
        	for (i=0;i<sizeof(struct in_addr);i++) {
        		SA_IN_U8_P(&rnd)[i] &= ~(SA_IN_U8_P(&mask)[i]);
		}

		/* Now add the IP to the masked random number */
        	for (i=0;i<sizeof(struct in_addr);i++)
        		SA_IN_U8_P(&rnd)[i] |= (SA_IN_U8_P(&network)[i]);

		/* check if it exists in the hash table */
		if (is_ipv4_ok(s, &rnd, &network, &mask) == 0) {
			mslog(s, proc, LOG_DEBUG, "cannot assign remote IP %s; it is in use or invalid", 
			      human_addr((void*)&rnd, sizeof(struct sockaddr_in), buf, sizeof(buf)));
			continue;
		}

		memcpy(&proc->ipv4->rip, &rnd, sizeof(struct sockaddr_in));
       		proc->ipv4->rip_len = sizeof(struct sockaddr_in);

		memcpy(&proc->ipv4->sig, &rnd, sizeof(struct sockaddr_in));

       		/* LIP = network address + 1 */
		memcpy(&proc->ipv4->lip, &network, sizeof(struct sockaddr_in));
		proc->ipv4->lip_len = sizeof(struct sockaddr_in);
		SA_IN_U8_P(&proc->ipv4->lip)[3] |= 1;

		if (memcmp(SA_IN_U8_P(&proc->ipv4->lip), SA_IN_U8_P(&proc->ipv4->rip), sizeof(struct in_addr)) == 0) {
			continue;
		}

		mslog(s, proc, LOG_DEBUG, "selected IP: %s",
		      human_addr((void*)&proc->ipv4->rip, proc->ipv4->rip_len, buf, sizeof(buf)));

       		if (icmp_ping4(s, (void*)&proc->ipv4->rip) == 0)
       			break;
	} while(1);

	return 0;

fail:
	talloc_free(proc->ipv4);
	proc->ipv4 = NULL;

	return ret;
}

static
int get_ipv6_lease(main_server_st* s, struct proc_st* proc)
{

	struct sockaddr_storage tmp, mask, network, rnd, subnet_mask;
	unsigned i, max_loops = MAX_IP_TRIES;
	const char* c_network = NULL;
	unsigned prefix, subnet_prefix ;
	int ret;
	char buf[64];

	if (proc->config->ipv6_net && proc->config->ipv6_subnet_prefix) {
		c_network = proc->config->ipv6_net;
		prefix = proc->config->ipv6_prefix;
		subnet_prefix = proc->config->ipv6_subnet_prefix;
	} else {
		c_network = proc->vhost->perm_config.config->network.ipv6;
		prefix = proc->vhost->perm_config.config->network.ipv6_prefix;
		subnet_prefix = proc->vhost->perm_config.config->network.ipv6_subnet_prefix;
	}

	if (c_network == NULL || prefix == 0 || subnet_prefix == 0) {
		return 0;
	}

	ret = ipv6_prefix_to_mask(SA_IN6_P(&mask), prefix);
	if (ret == 0) {
		mslog(s, NULL, LOG_ERR, "error reading prefix: %u", prefix);
		return -1;
	}

	ret = ipv6_prefix_to_mask(SA_IN6_P(&subnet_mask), subnet_prefix);
	if (ret == 0) {
		mslog(s, NULL, LOG_ERR, "error reading prefix: %u", subnet_prefix);
		return -1;
	}

	ret =
	    inet_pton(AF_INET6, c_network, SA_IN6_P(&network));
	if (ret != 1) {
		mslog(s, NULL, LOG_ERR, "error reading IP: %s", c_network);
		return -1;
	}

	/* mask the network */
	((struct sockaddr_in6*)&network)->sin6_family = AF_INET6;
	((struct sockaddr_in6*)&network)->sin6_port = 0;
	for (i=0;i<sizeof(struct in6_addr);i++)
		SA_IN6_U8_P(&network)[i] &= (SA_IN6_U8_P(&mask)[i]);


	if (proc->config->explicit_ipv6) {
		memset(&tmp, 0, sizeof(tmp));
		ret =
		    inet_pton(AF_INET6, proc->config->explicit_ipv6, SA_IN6_P(&tmp));

		if (ret != 1) {
			mslog(s, NULL, LOG_ERR, "error reading explicit IP %s", proc->config->explicit_ipv6);
			return -1;
		}

		proc->ipv6 = talloc_zero(proc, struct ip_lease_st);
		if (proc->ipv6 == NULL)
			return ERR_MEM;

        	((struct sockaddr_in6*)&tmp)->sin6_family = AF_INET6;
		memcpy(&proc->ipv6->rip, &tmp, sizeof(struct sockaddr_in6));
       		proc->ipv6->rip_len = sizeof(struct sockaddr_in6);

       		/* create our sig */
		for (i=0;i<sizeof(struct in6_addr);i++)
			SA_IN6_U8_P(&proc->ipv6->sig)[i] = SA_IN6_U8_P(&proc->ipv6->rip)[i] & SA_IN6_U8_P(&subnet_mask)[i];

		if (is_ipv6_ok(s, &tmp, &network, &proc->ipv6->sig) == 0) {
			mslog(s, proc, LOG_DEBUG, "cannot assign explicit IP %s; it is in use or invalid", 
			      human_addr((void*)&tmp, sizeof(struct sockaddr_in6), buf, sizeof(buf)));
			ret = ERR_NO_IP;
			goto fail;
		}

		goto finish;
	}

	/* assign "random" IP */
	proc->ipv6 = talloc_zero(proc, struct ip_lease_st);
	if (proc->ipv6 == NULL)
		return ERR_MEM;
	proc->ipv6->db = &s->ip_leases;

  	memcpy(&tmp, &network, sizeof(tmp));
       	((struct sockaddr_in6*)&tmp)->sin6_family = AF_INET6;
       	((struct sockaddr_in6*)&tmp)->sin6_port = 0;

	do {
		if (max_loops == 0) {
			mslog(s, NULL, LOG_ERR, "could not figure out a valid IPv6 IP");
			ret = ERR_NO_IP;
			goto fail;
		}

		memset(&rnd, 0, sizeof(rnd));
	       	((struct sockaddr_in6*)&rnd)->sin6_family = AF_INET6;

		if (max_loops == MAX_IP_TRIES) {
			ip_from_seed(proc->ipv4_seed, 4,
				     SA_IN6_U8_P(&rnd), sizeof(struct in6_addr));
		} else {
			if (max_loops < MAX_IP_TRIES-FIXED_IPS) {
				gnutls_rnd(GNUTLS_RND_NONCE, SA_IN_U8_P(&rnd), sizeof(struct in6_addr));
			} else {
				ip_from_seed(SA_IN6_U8_P(&rnd), sizeof(struct in6_addr),
					     SA_IN6_U8_P(&rnd), sizeof(struct in6_addr));
			}
		}
		max_loops--;

		/* Mask the random number with the netmask */
       		for (i=0;i<sizeof(struct in6_addr);i++)
       			SA_IN6_U8_P(&rnd)[i] &= ~(SA_IN6_U8_P(&mask)[i]);

		/* Now add the network to the masked random number */
       		for (i=0;i<sizeof(struct in6_addr);i++)
       			SA_IN6_U8_P(&rnd)[i] |= (SA_IN6_U8_P(&network)[i]);

		/* make the sig of our subnet */
	       	((struct sockaddr_in6*)&proc->ipv6->sig)->sin6_family = AF_INET6;
	       	((struct sockaddr_in6*)&proc->ipv6->sig)->sin6_port = 0;
		for (i=0;i<sizeof(struct in6_addr);i++) {
			SA_IN6_U8_P(&proc->ipv6->sig)[i] = SA_IN6_U8_P(&rnd)[i] & SA_IN6_U8_P(&subnet_mask)[i];
		}

		/* check if it exists in the hash table */
		if (is_ipv6_ok(s, &rnd, &network, &proc->ipv6->sig) == 0) {
			mslog(s, proc, LOG_DEBUG, "cannot assign local IP %s; it is in use or invalid", 
			      human_addr((void*)&rnd, sizeof(struct sockaddr_in6), buf, sizeof(buf)));
			continue;
		}

       		proc->ipv6->rip_len = sizeof(struct sockaddr_in6);
       		memcpy(&proc->ipv6->rip, &rnd, proc->ipv6->rip_len);

		mslog(s, proc, LOG_DEBUG, "selected IP: %s",
		      human_addr((void*)&proc->ipv6->rip, proc->ipv6->rip_len, buf, sizeof(buf)));

        	if (proc->ipv6->prefix != 128 || icmp_ping6(s, (void*)&proc->ipv6->rip) == 0)
        		break;
        } while(1);

 finish:
	/* LIP = network address + 1 */
	memcpy(&proc->ipv6->lip, &network, sizeof(struct sockaddr_in6));
	SA_IN6_U8_P(&proc->ipv6->lip)[15] |= 1;

	proc->ipv6->lip_len = sizeof(struct sockaddr_in6);

	proc->ipv6->prefix = subnet_prefix;

	return 0;
fail:
	talloc_free(proc->ipv6);
	proc->ipv6 = NULL;

	return ret;

}

static
int unref_ip_lease(struct ip_lease_st *lease)
{
	if (lease->db) {
		htable_del(&lease->db->ht, rehash(lease, NULL), lease);
	}

	return 0;
}

int get_ip_leases(main_server_st *s, struct proc_st *proc)
{
int ret;
char buf[128];

	if (proc->ipv4 == NULL) {
		ret = get_ipv4_lease(s, proc);
		if (ret < 0)
			return ret;

		if (proc->ipv4 && proc->ipv4->db) {
			if (htable_add(&s->ip_leases.ht, rehash(proc->ipv4, NULL), proc->ipv4) == 0) {
				mslog(s, proc, LOG_ERR, "could not add IPv4 lease to hash table");
				return -1;
			}
			talloc_set_destructor(proc->ipv4, unref_ip_lease);
		}
	}

	if (proc->ipv6 == NULL) {
		ret = get_ipv6_lease(s, proc);
		if (ret < 0)
			return ret;

		if (proc->ipv6 && proc->ipv6->db) {
			if (htable_add(&s->ip_leases.ht, rehash(proc->ipv6, NULL), proc->ipv6) == 0) {
				mslog(s, proc, LOG_ERR, "could not add IPv6 lease to hash table");
				return -1;
			}
			talloc_set_destructor(proc->ipv6, unref_ip_lease);
		}
	}

	if (proc->ipv4 == 0 && proc->ipv6 == 0) {
		mslog(s, proc, LOG_ERR, "no IPv4 or IPv6 addresses are configured. Cannot obtain lease");
		return -1;
	}
	
	if (proc->ipv4)
		mslog(s, proc, LOG_DEBUG, "assigned IPv4: %s",
			human_addr((void*)&proc->ipv4->rip, proc->ipv4->rip_len, buf, sizeof(buf)));

	if (proc->ipv6)
		mslog(s, proc, LOG_DEBUG, "assigned IPv6: %s/%u",
			human_addr((void*)&proc->ipv6->rip, proc->ipv6->rip_len, buf, sizeof(buf)),
			proc->ipv6->prefix);

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
