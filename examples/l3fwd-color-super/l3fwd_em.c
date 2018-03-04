/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define PRINT_ON  1
#define PRINT_OFF 0
#define PRINT PRINT_OFF

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <netinet/in.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>

#include "l3fwd.h"

//#include "city.h"
#include "cuckoohash.h"
#include "send_packet.h"

//For NASH
#include "nash.h"

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc
#else
#include <rte_jhash.h>
#define DEFAULT_HASH_FUNC       rte_jhash
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */

#define IPV6_ADDR_LEN 16

struct ipv4_5tuple {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __attribute__((__packed__));

union ipv4_5tuple_host {
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	xmm_t xmm;
};

#define XMM_NUM_IN_IPV6_5TUPLE 3

struct ipv6_5tuple {
	uint8_t  ip_dst[IPV6_ADDR_LEN];
	uint8_t  ip_src[IPV6_ADDR_LEN];
	uint16_t port_dst;
	uint16_t port_src;
	uint8_t  proto;
} __attribute__((__packed__));

union ipv6_5tuple_host {
	struct {
		uint16_t pad0;
		uint8_t  proto;
		uint8_t  pad1;
		uint8_t  ip_src[IPV6_ADDR_LEN];
		uint8_t  ip_dst[IPV6_ADDR_LEN];
		uint16_t port_src;
		uint16_t port_dst;
		uint64_t reserve;
	};
	xmm_t xmm[XMM_NUM_IN_IPV6_5TUPLE];
};



struct ipv4_l3fwd_em_route {
	struct ipv4_5tuple key;
	uint8_t if_out;
};

struct ipv6_l3fwd_em_route {
	struct ipv6_5tuple key;
	uint8_t if_out;
};

static struct ipv4_l3fwd_em_route ipv4_l3fwd_em_route_array[] = {
	{{IPv4(172, 16, 0, 1), IPv4(172, 16, 1, 1),  6, 5, IPPROTO_UDP}, 1},
	{{IPv4(172, 16, 1, 1), IPv4(172, 16, 0, 1),  5, 6, IPPROTO_UDP}, 0},
	{{IPv4(111, 0, 0, 0), IPv4(100, 30, 0, 1),  101, 11, IPPROTO_TCP}, 2},
	{{IPv4(211, 0, 0, 0), IPv4(200, 40, 0, 1),  102, 12, IPPROTO_TCP}, 3},
};

static struct ipv6_l3fwd_em_route ipv6_l3fwd_em_route_array[] = {
	{{
	{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1e, 0x67, 0xff, 0xfe, 0, 0, 0},
	{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1b, 0x21, 0xff, 0xfe, 0x91, 0x38, 0x05},
	101, 11, IPPROTO_TCP}, 0},

	{{
	{0xfe, 0x90, 0, 0, 0, 0, 0, 0, 0x02, 0x1e, 0x67, 0xff, 0xfe, 0, 0, 0},
	{0xfe, 0x90, 0, 0, 0, 0, 0, 0, 0x02, 0x1b, 0x21, 0xff, 0xfe, 0x91, 0x38, 0x05},
	102, 12, IPPROTO_TCP}, 1},

	{{
	{0xfe, 0xa0, 0, 0, 0, 0, 0, 0, 0x02, 0x1e, 0x67, 0xff, 0xfe, 0, 0, 0},
	{0xfe, 0xa0, 0, 0, 0, 0, 0, 0, 0x02, 0x1b, 0x21, 0xff, 0xfe, 0x91, 0x38, 0x05},
	101, 11, IPPROTO_TCP}, 2},

	{{
	{0xfe, 0xb0, 0, 0, 0, 0, 0, 0, 0x02, 0x1e, 0x67, 0xff, 0xfe, 0, 0, 0},
	{0xfe, 0xb0, 0, 0, 0, 0, 0, 0, 0x02, 0x1b, 0x21, 0xff, 0xfe, 0x91, 0x38, 0x05},
	102, 12, IPPROTO_TCP}, 3},
};

struct rte_hash *ipv4_l3fwd_em_lookup_struct[NB_SOCKETS];
struct rte_hash *ipv6_l3fwd_em_lookup_struct[NB_SOCKETS];
static cuckoo_hashtable_t * sid_cuckoo_struct[8]; 

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
		uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash_1word(k->ip_src, init_val);
	init_val = rte_jhash_1word(k->ip_dst, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */

	return init_val;
}

static inline uint32_t
ipv6_hash_crc(const void *data, __rte_unused uint32_t data_len,
		uint32_t init_val)
{
	const union ipv6_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;
#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
	const uint32_t  *ip_src0, *ip_src1, *ip_src2, *ip_src3;
	const uint32_t  *ip_dst0, *ip_dst1, *ip_dst2, *ip_dst3;
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
	ip_src0 = (const uint32_t *) k->ip_src;
	ip_src1 = (const uint32_t *)(k->ip_src+4);
	ip_src2 = (const uint32_t *)(k->ip_src+8);
	ip_src3 = (const uint32_t *)(k->ip_src+12);
	ip_dst0 = (const uint32_t *) k->ip_dst;
	ip_dst1 = (const uint32_t *)(k->ip_dst+4);
	ip_dst2 = (const uint32_t *)(k->ip_dst+8);
	ip_dst3 = (const uint32_t *)(k->ip_dst+12);
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(*ip_src0, init_val);
	init_val = rte_hash_crc_4byte(*ip_src1, init_val);
	init_val = rte_hash_crc_4byte(*ip_src2, init_val);
	init_val = rte_hash_crc_4byte(*ip_src3, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst0, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst1, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst2, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst3, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else /* RTE_MACHINE_CPUFLAG_SSE4_2 */
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash(k->ip_src,
			sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
	init_val = rte_jhash(k->ip_dst,
			sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif /* RTE_MACHINE_CPUFLAG_SSE4_2 */
	return init_val;
}

#define IPV4_L3FWD_EM_NUM_ROUTES \
	(sizeof(ipv4_l3fwd_em_route_array) / sizeof(ipv4_l3fwd_em_route_array[0]))

#define IPV6_L3FWD_EM_NUM_ROUTES \
	(sizeof(ipv6_l3fwd_em_route_array) / sizeof(ipv6_l3fwd_em_route_array[0]))

static uint8_t ipv4_l3fwd_out_if[L3FWD_HASH_ENTRIES] __rte_cache_aligned;
static uint8_t ipv6_l3fwd_out_if[L3FWD_HASH_ENTRIES] __rte_cache_aligned;

static rte_xmm_t mask0;
static rte_xmm_t mask1;
static rte_xmm_t mask2;

#if defined(__SSE2__)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	__m128i data = _mm_loadu_si128((__m128i *)(key));

	return _mm_and_si128(data, mask);
}
#elif defined(RTE_MACHINE_CPUFLAG_NEON)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
	int32x4_t data = vld1q_s32((int32_t *)key);

	return vandq_s32(data, mask);
}
#endif

static inline uint8_t
em_get_ipv4_dst_port(void *ipv4_hdr, uint8_t portid, void *lookup_struct)
{
	int ret = 0;
	union ipv4_5tuple_host key;
	struct rte_hash *ipv4_l3fwd_lookup_struct =
		(struct rte_hash *)lookup_struct;

	ipv4_hdr = (uint8_t *)ipv4_hdr + offsetof(struct ipv4_hdr, time_to_live);

	/*
	 * Get 5 tuple: dst port, src port, dst IP address,
	 * src IP address and protocol.
	 */
	key.xmm = em_mask_key(ipv4_hdr, mask0.x);

	/* Find destination port */
	ret = rte_hash_lookup(ipv4_l3fwd_lookup_struct, (const void *)&key);
	return (uint8_t)((ret < 0) ? portid : ipv4_l3fwd_out_if[ret]);
}

static inline uint8_t
em_get_ipv6_dst_port(void *ipv6_hdr,  uint8_t portid, void *lookup_struct)
{
	int ret = 0;
	union ipv6_5tuple_host key;
	struct rte_hash *ipv6_l3fwd_lookup_struct =
		(struct rte_hash *)lookup_struct;

	ipv6_hdr = (uint8_t *)ipv6_hdr + offsetof(struct ipv6_hdr, payload_len);
	void *data0 = ipv6_hdr;
	void *data1 = ((uint8_t *)ipv6_hdr) + sizeof(xmm_t);
	void *data2 = ((uint8_t *)ipv6_hdr) + sizeof(xmm_t) + sizeof(xmm_t);

	/* Get part of 5 tuple: src IP address lower 96 bits and protocol */
	key.xmm[0] = em_mask_key(data0, mask1.x);

	/*
	 * Get part of 5 tuple: dst IP address lower 96 bits
	 * and src IP address higher 32 bits.
	 */
	key.xmm[1] = *(xmm_t *)data1;

	/*
	 * Get part of 5 tuple: dst port and src port
	 * and dst IP address higher 32 bits.
	 */
	key.xmm[2] = em_mask_key(data2, mask2.x);

	/* Find destination port */
	ret = rte_hash_lookup(ipv6_l3fwd_lookup_struct, (const void *)&key);
	return (uint8_t)((ret < 0) ? portid : ipv6_l3fwd_out_if[ret]);
}

#if defined(__SSE4_1__)
#if defined(NO_HASH_MULTI_LOOKUP)
#include "l3fwd_em_sse.h"
#else
#include "l3fwd_em_hlm_sse.h"
#endif
#else
#include "l3fwd_em.h"
#endif

static void
convert_ipv4_5tuple(struct ipv4_5tuple *key1,
		union ipv4_5tuple_host *key2)
{
	key2->ip_dst = rte_cpu_to_be_32(key1->ip_dst);
	key2->ip_src = rte_cpu_to_be_32(key1->ip_src);
	key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
	key2->port_src = rte_cpu_to_be_16(key1->port_src);
	key2->proto = key1->proto;
	key2->pad0 = 0;
	key2->pad1 = 0;
}


static void
convert_ipv6_5tuple(struct ipv6_5tuple *key1,
		union ipv6_5tuple_host *key2)
{
	uint32_t i;

	for (i = 0; i < 16; i++) {
		key2->ip_dst[i] = key1->ip_dst[i];
		key2->ip_src[i] = key1->ip_src[i];
	}
	key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
	key2->port_src = rte_cpu_to_be_16(key1->port_src);
	key2->proto = key1->proto;
	key2->pad0 = 0;
	key2->pad1 = 0;
	key2->reserve = 0;
}

#define BYTE_VALUE_MAX 256
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00

static inline void
populate_ipv4_few_flow_into_table(const struct rte_hash *h)
{
	uint32_t i;
	int32_t ret;

	mask0 = (rte_xmm_t){.u32 = {BIT_8_TO_15, ALL_32_BITS,
				ALL_32_BITS, ALL_32_BITS} };

	for (i = 0; i < IPV4_L3FWD_EM_NUM_ROUTES; i++) {
		struct ipv4_l3fwd_em_route  entry;
		union ipv4_5tuple_host newkey;

		entry = ipv4_l3fwd_em_route_array[i];
		convert_ipv4_5tuple(&entry.key, &newkey);
		ret = rte_hash_add_key(h, (void *) &newkey);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Unable to add entry %" PRIu32
				" to the l3fwd hash.\n", i);
		}
		ipv4_l3fwd_out_if[ret] = entry.if_out;
	}
	printf("[From %s]Hash: Adding 0x%" PRIx64 " keys\n",__func__,
		(uint64_t)IPV4_L3FWD_EM_NUM_ROUTES);
}

#define BIT_16_TO_23 0x00ff0000
static inline void
populate_ipv6_few_flow_into_table(const struct rte_hash *h)
{
	uint32_t i;
	int32_t ret;

	mask1 = (rte_xmm_t){.u32 = {BIT_16_TO_23, ALL_32_BITS,
				ALL_32_BITS, ALL_32_BITS} };

	mask2 = (rte_xmm_t){.u32 = {ALL_32_BITS, ALL_32_BITS, 0, 0} };

	for (i = 0; i < IPV6_L3FWD_EM_NUM_ROUTES; i++) {
		struct ipv6_l3fwd_em_route entry;
		union ipv6_5tuple_host newkey;

		entry = ipv6_l3fwd_em_route_array[i];
		convert_ipv6_5tuple(&entry.key, &newkey);
		ret = rte_hash_add_key(h, (void *) &newkey);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Unable to add entry %" PRIu32
				" to the l3fwd hash.\n", i);
		}
		ipv6_l3fwd_out_if[ret] = entry.if_out;
	}
	printf("Hash: Adding 0x%" PRIx64 "keys\n",
		(uint64_t)IPV6_L3FWD_EM_NUM_ROUTES);
}

#define NUMBER_PORT_USED 4
static inline void
populate_ipv4_many_flow_into_table(const struct rte_hash *h,
		unsigned int nr_flow)
{
	unsigned i;

	mask0 = (rte_xmm_t){.u32 = {BIT_8_TO_15, ALL_32_BITS,
				ALL_32_BITS, ALL_32_BITS} };

	for (i = 0; i < nr_flow; i++) {
		struct ipv4_l3fwd_em_route entry;
		union ipv4_5tuple_host newkey;

		uint8_t a = (uint8_t)
			((i/NUMBER_PORT_USED)%BYTE_VALUE_MAX);
		uint8_t b = (uint8_t)
			(((i/NUMBER_PORT_USED)/BYTE_VALUE_MAX)%BYTE_VALUE_MAX);
		uint8_t c = (uint8_t)
			((i/NUMBER_PORT_USED)/(BYTE_VALUE_MAX*BYTE_VALUE_MAX));

		/* Create the ipv4 exact match flow */
		memset(&entry, 0, sizeof(entry));
		switch (i & (NUMBER_PORT_USED - 1)) {
		case 0:
			entry = ipv4_l3fwd_em_route_array[0];
			entry.key.ip_dst = IPv4(101, c, b, a);
			break;
		case 1:
			entry = ipv4_l3fwd_em_route_array[1];
			entry.key.ip_dst = IPv4(201, c, b, a);
			break;
		case 2:
			entry = ipv4_l3fwd_em_route_array[2];
			entry.key.ip_dst = IPv4(111, c, b, a);
			break;
		case 3:
			entry = ipv4_l3fwd_em_route_array[3];
			entry.key.ip_dst = IPv4(211, c, b, a);
			break;
		};
		convert_ipv4_5tuple(&entry.key, &newkey);
		int32_t ret = rte_hash_add_key(h, (void *) &newkey);

		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Unable to add entry %u\n", i);

		ipv4_l3fwd_out_if[ret] = (uint8_t) entry.if_out;

	}
	printf("Hash: Adding 0x%x keys\n", nr_flow);
}
static inline __attribute__((always_inline)) void
em_get_dst_port_ipv4x8_pumpking(struct lcore_conf *qconf, struct rte_mbuf *m[8],uint8_t portid, uint16_t dst_port[8])
{
	
	KeyType key[8];
	struct ipv4_hdr *ipv4_hdr[8];
	CoLoR_get_t * get_hdr[8];
	uint8_t next_hop1[8];	
	uint8_t next_hop2[8];	

	ipv4_hdr[0] = rte_pktmbuf_mtod_offset(m[0], struct ipv4_hdr *,sizeof(struct ether_hdr));
	ipv4_hdr[1] = rte_pktmbuf_mtod_offset(m[1], struct ipv4_hdr *,sizeof(struct ether_hdr));
	ipv4_hdr[2] = rte_pktmbuf_mtod_offset(m[2], struct ipv4_hdr *,sizeof(struct ether_hdr));
	ipv4_hdr[3] = rte_pktmbuf_mtod_offset(m[3], struct ipv4_hdr *,sizeof(struct ether_hdr));
	ipv4_hdr[4] = rte_pktmbuf_mtod_offset(m[4], struct ipv4_hdr *,sizeof(struct ether_hdr));
	ipv4_hdr[5] = rte_pktmbuf_mtod_offset(m[5], struct ipv4_hdr *,sizeof(struct ether_hdr));
	ipv4_hdr[6] = rte_pktmbuf_mtod_offset(m[6], struct ipv4_hdr *,sizeof(struct ether_hdr));
	ipv4_hdr[7] = rte_pktmbuf_mtod_offset(m[7], struct ipv4_hdr *,sizeof(struct ether_hdr));

	get_hdr[0]=(CoLoR_get_t *)( (uint8_t*)ipv4_hdr[0]+sizeof(struct ipv4_hdr ) );	
	get_hdr[1]=(CoLoR_get_t *)( (uint8_t*)ipv4_hdr[1]+sizeof(struct ipv4_hdr ) );	
	get_hdr[2]=(CoLoR_get_t *)( (uint8_t*)ipv4_hdr[2]+sizeof(struct ipv4_hdr ) );	
	get_hdr[3]=(CoLoR_get_t *)( (uint8_t*)ipv4_hdr[3]+sizeof(struct ipv4_hdr ) );	
	get_hdr[4]=(CoLoR_get_t *)( (uint8_t*)ipv4_hdr[4]+sizeof(struct ipv4_hdr ) );	
	get_hdr[5]=(CoLoR_get_t *)( (uint8_t*)ipv4_hdr[5]+sizeof(struct ipv4_hdr ) );	
	get_hdr[6]=(CoLoR_get_t *)( (uint8_t*)ipv4_hdr[6]+sizeof(struct ipv4_hdr ) );	
	get_hdr[7]=(CoLoR_get_t *)( (uint8_t*)ipv4_hdr[7]+sizeof(struct ipv4_hdr ) );	

	memcpy(&key[0],&get_hdr[0]->nid_sid[0],36);	
	memcpy(&key[1],&get_hdr[1]->nid_sid[0],36);	
	memcpy(&key[2],&get_hdr[2]->nid_sid[0],36);	
	memcpy(&key[3],&get_hdr[3]->nid_sid[0],36);	
	memcpy(&key[4],&get_hdr[4]->nid_sid[0],36);	
	memcpy(&key[5],&get_hdr[5]->nid_sid[0],36);	
	memcpy(&key[6],&get_hdr[6]->nid_sid[0],36);	
	memcpy(&key[7],&get_hdr[7]->nid_sid[0],36);	

	const void *key_array[8] = {&key[0], &key[1], &key[2], &key[3],&key[4], &key[5], &key[6], &key[7]};

	int res=cuckoo_find_bulk_batch( qconf->sid_lookup_struct,&key_array[0] , 8,&next_hop1[0] );
	int res2=cuckoo_find_bulk_batch( qconf->sid_lookup_struct_another_socket,&key_array[0] , 8,&next_hop2[0] );
	dst_port[0] = (uint8_t) ( next_hop1[0]<next_hop2[0] )? next_hop1[0]:next_hop2[0]; 
	dst_port[1] = (uint8_t) ( next_hop1[1]<next_hop2[1] )? next_hop1[1]:next_hop2[1]; 
	dst_port[2] = (uint8_t) ( next_hop1[2]<next_hop2[2] )? next_hop1[2]:next_hop2[2]; 
	dst_port[3] = (uint8_t) ( next_hop1[3]<next_hop2[3] )? next_hop1[3]:next_hop2[3]; 
	dst_port[4] = (uint8_t) ( next_hop1[4]<next_hop2[4] )? next_hop1[4]:next_hop2[4]; 
	dst_port[5] = (uint8_t) ( next_hop1[5]<next_hop2[5] )? next_hop1[5]:next_hop2[5]; 
	dst_port[6] = (uint8_t) ( next_hop1[6]<next_hop2[6] )? next_hop1[6]:next_hop2[6]; 
	dst_port[7] = (uint8_t) ( next_hop1[7]<next_hop2[7] )? next_hop1[7]:next_hop2[7]; 
	if (dst_port[0] >= RTE_MAX_ETHPORTS ||(enabled_port_mask & 1 << dst_port[0]) == 0)dst_port[0] = portid;
	if (dst_port[1] >= RTE_MAX_ETHPORTS ||(enabled_port_mask & 1 << dst_port[1]) == 0)dst_port[1] = portid;
	if (dst_port[2] >= RTE_MAX_ETHPORTS ||(enabled_port_mask & 1 << dst_port[2]) == 0)dst_port[2] = portid;
	if (dst_port[3] >= RTE_MAX_ETHPORTS ||(enabled_port_mask & 1 << dst_port[3]) == 0)dst_port[3] = portid;
	if (dst_port[4] >= RTE_MAX_ETHPORTS ||(enabled_port_mask & 1 << dst_port[4]) == 0)dst_port[4] = portid;
	if (dst_port[5] >= RTE_MAX_ETHPORTS ||(enabled_port_mask & 1 << dst_port[5]) == 0)dst_port[5] = portid;
	if (dst_port[6] >= RTE_MAX_ETHPORTS ||(enabled_port_mask & 1 << dst_port[6]) == 0)dst_port[6] = portid;
	if (dst_port[7] >= RTE_MAX_ETHPORTS ||(enabled_port_mask & 1 << dst_port[7]) == 0)dst_port[7] = portid;
}

void get_register_time(char * str)
{
	str[0]='\0';
	time_t timep;
	struct tm *p;
	time(&timep);
	p = localtime(&timep); //取得当地时间
	sprintf (str,"%d-%d-%d ", (1900+p->tm_year), (1+p->tm_mon), p->tm_mday);
	char temp[256];
	sprintf(temp,"%d:%d:%d", p->tm_hour, p->tm_min, p->tm_sec);
	strcat(str,temp);
}

/*struct timeval
{
    long tv_sec; *//*秒*//*
    long tv_usec; *//*微秒*//*
};*/

/*struct tm
{
    int tm_sec;  *//*秒，正常范围0-59， 但允许至61*//*
    int tm_min;  *//*分钟，0-59*//*
    int tm_hour; *//*小时， 0-23*//*
    int tm_mday; *//*日，即一个月中的第几天，1-31*//*
    int tm_mon;  *//*月， 从一月算起，0-11*//*  1+p->tm_mon;
    int tm_year;  *//*年， 从1900至今已经多少年*//*  1900＋ p->tm_year;
    int tm_wday; *//*星期，一周中的第几天， 从星期日算起，0-6*//*
    int tm_yday; *//*从今年1月1日到目前的天数，范围0-365*//*
    int tm_isdst; *//*日光节约时间的旗标*//*
};*/

void get_dead_time(char * str,uint8_t time_of_validity,uint8_t time_unit)
{
    uint64_t Seconds=300;
    switch (time_unit){
        case REISTER_TIME_UNIT_SECOND:
            Seconds=time_of_validity;
            break;
        case REISTER_TIME_UNIT_MINITUE:
            Seconds=time_of_validity*60;
            break;
        case REISTER_TIME_UNIT_HOUR:
            Seconds=time_of_validity*60*60;
            break;
        case REISTER_TIME_UNIT_DAY:
            Seconds=time_of_validity*60*60*24;
            break;
        case REISTER_TIME_UNIT_WEEK:
            Seconds=time_of_validity*60*60*24*7;
            break;
        case REISTER_TIME_UNIT_MONTH:
            Seconds=time_of_validity*60*60*24*30;
            break;
        case REISTER_TIME_UNIT_YEAR:
            Seconds=time_of_validity*60*60*24*365;
            break;
        default:
            //TODO:默认一个星期
            Seconds=time_of_validity*60*60*24*7;
    }

    str[0]='\0';
    time_t timep;
    struct tm *p;
    time(&timep);
    //TODO:测试过期时间
    timep += (time_t)Seconds;
    p = localtime(&timep); //取得当地时间
    sprintf (str,"%d-%d-%d ", (1900+p->tm_year), (1+p->tm_mon), p->tm_mday);
    char temp[256];
    sprintf(temp,"%d:%d:%d", p->tm_hour, p->tm_min, p->tm_sec);
    strcat(str,temp);
}

//TODO:在Json字符串中，找某个字段对应的值，真时返回True
bool Json_get_by_field(char *json_str, char *field_str, char *value_str) {
    bool result= false;
    int json_str_size = strlen(json_str);
    int field_str_size = strlen(field_str);
    int i;
    for (i = 0; i < json_str_size; i++) {
        int index_i = i;
        int index_j = 0;
        int flag = 0;
        while (index_i < json_str_size && index_j < field_str_size && json_str[index_i] == field_str[index_j]) {
            index_i++;
            index_j++;
            flag = 1;
        }
        //TODO:匹配成功,并且只返回一个
        if (index_j == field_str_size && flag == 1) {
            result= true;
            //+1是为了过掉 "
            char *temp = json_str + i + field_str_size + 1;
            while (*temp != '"') {
                temp++;
            }
            temp++;
            int index = 0;
            while (*temp != '"') {
                value_str[index++] = *(temp++);
            }
            value_str[index] = '\0';
            return result;
        }
    }
    value_str[0] = '\0';
    return result;
}
//TODO:把数组变成16进制的字符串
void arrayToHexStr(uint8_t * start, uint8_t len, char str[256]){
    str[0]='\0';
    char temp[10];
    int i=0;
    //TODO:代表16进制，可读性强
    strcat(str,"0x");
    for(i=0;i<len;i++)
    {
        //str[i]=start[i];
        temp[0]='\0';
        sprintf(temp,"%2X",start[i]);
        if(temp[0]==' ') temp[0]='0';
        strcat(str,temp);
    }
}

//TODO:转换的时候需要对应的字段名字
const char* N_SID ="sid_p";
const char* L_SID="sid_l";
const char* TYPE="tpye";
const char* NID_S="nid_s";
const char* SCOPE="scope";
const char* TIME_OF_VALIDITY="time_of_validity";
const char* TIME_UNIT="time_unit";
const char* CONTENT_SIZE="content_size";
const char* CONTENT_CLASSIFICATION="content_classification";
const char* _REGISTRATION_TIME ="_registration_time";
const char* _DEAD_TIME ="_dead_time";
#define MAX_CONVERT_LEN  256

int
insert_mongodb (control_register_t *control_register_hdr, mongoc_collection_t  *collection_local)
{
   bson_t               *insert;
   bson_error_t          error;

	char n_sid[MAX_CONVERT_LEN];
	arrayToHexStr(&control_register_hdr->n_sid[0], NID_LENGTH, n_sid);

    char type[MAX_CONVERT_LEN];
    arrayToHexStr(&control_register_hdr->type,1,type);

	char l_sid[MAX_CONVERT_LEN];
	arrayToHexStr(&control_register_hdr->l_sid[0], L_SID_LENGTH, l_sid);

	char nid_s[MAX_CONVERT_LEN];
	arrayToHexStr(&control_register_hdr->nid_s[0], NID_LENGTH, nid_s);

    char scope[MAX_CONVERT_LEN];
    sprintf(scope,"%d",control_register_hdr->scope);

    char time_of_validity[MAX_CONVERT_LEN];
    sprintf(time_of_validity,"%d",control_register_hdr->time_of_validity);

    char time_unit[MAX_CONVERT_LEN];
    sprintf(time_unit,"%d",control_register_hdr->time_unit);

    char content_size[MAX_CONVERT_LEN];
    sprintf(content_size,"%d",control_register_hdr->content_size);

    char content_classification[MAX_CONVERT_LEN];
    sprintf(content_classification,"%d",control_register_hdr->content_classification);

	char _registration_time[MAX_CONVERT_LEN];
    get_register_time(_registration_time);

    char _dead_time[MAX_CONVERT_LEN];
    get_dead_time(_dead_time,control_register_hdr->time_of_validity,control_register_hdr->time_unit);

   insert = BCON_NEW 
   	(
   		N_SID, n_sid,
        TYPE,  type,
   		L_SID, l_sid,
   		NID_S, nid_s,
        SCOPE, scope,
        TIME_OF_VALIDITY,time_of_validity,
        TIME_UNIT,time_unit,
        CONTENT_SIZE,content_size,
        CONTENT_CLASSIFICATION,content_classification,
   		//-----------
   		_REGISTRATION_TIME,_registration_time,
        _DEAD_TIME,_dead_time
   	);

   if (!mongoc_collection_insert (collection_local, MONGOC_INSERT_NONE, insert, NULL, &error)) {
      fprintf (stderr, "%s\n", error.message);
   }

   bson_destroy (insert);
   return 0;
}

int find_mongodb (CoLoR_get_t *get_hdr)
{

    mongoc_collection_t  *collection_local;
    collection_local=collection;
    if(NUM_CONN > 0){
        //TODO：根据L_SID的最后一位求余数 判断
        collection_local=collections[get_hdr->l_sid[L_SID_LENGTH-1]%NUM_CONN];
    }

    bson_t               *query;
    bson_error_t         error;
    char                 *str;

	char l_sid[MAX_CONVERT_LEN];
	arrayToHexStr(&get_hdr->l_sid[0], L_SID_LENGTH, l_sid);

	query=BCON_NEW
   	(
   		L_SID, l_sid
   	);
   	
    mongoc_cursor_t * cursor = mongoc_collection_find_with_opts (collection_local, query, NULL, NULL);
    const bson_t * doc;
	while (mongoc_cursor_next (cursor, &doc)) 
	{
		str = bson_as_json (doc, NULL);
//		printf ("[FROM %s] MongoDB %s\n", __FUNCTION__,str);

        char *field_str = "l_sid";
        char value_str[100];
        if(Json_get_by_field(str, field_str, value_str)){
            DBG_wxb("value_str=%s\n", value_str);
        }

		bson_free (str);
	}

    bson_destroy (query);
    return 0;
}

//TODO:删除mongoDB数据库的内容
int delete_mongodb (control_register_t *control_register_hdr, mongoc_collection_t  *collection_local)
{
    bson_t              * query;
    bson_error_t        error;
    char                *str;

    char l_sid[MAX_CONVERT_LEN];
    arrayToHexStr(&control_register_hdr->l_sid[0], L_SID_LENGTH, l_sid);

    query=BCON_NEW
    (
            L_SID, l_sid
    );

    mongoc_cursor_t * cursor = mongoc_collection_find_with_opts (collection_local, query, NULL, NULL);
    const bson_t * doc;
    while (mongoc_cursor_next (cursor, &doc))
    {
        str = bson_as_json (doc, NULL);
        printf ("[FROM %s] MongoDB %s\n", __FUNCTION__,str);
        bson_free (str);
    }

	//TODO:删除
	if (!mongoc_collection_remove (
			collection_local, MONGOC_REMOVE_SINGLE_REMOVE, query, NULL, &error)) {
		fprintf (stderr, "Delete failed: %s\n", error.message);
	}

    bson_destroy (query);
    return 0;
}

//TODO:更新mongoDB数据库的内容  ---》先删除，再添加！
int update_mongodb (control_register_t *control_register_hdr, mongoc_collection_t  *collection_local)
{
	delete_mongodb(control_register_hdr,collection_local);
	insert_mongodb(control_register_hdr,collection_local);
    return 0;
}

void process_register(control_register_t *control_register_hdr){

    mongoc_collection_t  *collection_local;
    collection_local=collection;
    if(NUM_CONN > 0){
        //TODO：根据L_SID的最后一位求余数 判断
        collection_local=collections[control_register_hdr->l_sid[L_SID_LENGTH-1]%NUM_CONN];
    }

    char LOG_TEMP[1024];
    switch(control_register_hdr->type)
    {
        case REGISTER_TYPE_ADD:
            sprintf(LOG_TEMP,"%s"," (添加)");
            insert_mongodb(control_register_hdr,collection_local);
            break;
        case
            REGISTER_TYPE_UPDATE:
            update_mongodb(control_register_hdr,collection_local);
            sprintf(LOG_TEMP,"%s", " (更新)");
            break;
        case REGISTER_TYPE_DELETE:
            sprintf(LOG_TEMP,"%s", " (删除)");
            delete_mongodb(control_register_hdr,collection_local);
            break;
        default:  sprintf(LOG_TEMP,"%s", " (未知)");
    }
    RTE_LOG(DEBUG , L3FWD, "type = %2X %s\n",control_register_hdr->type,LOG_TEMP);
}

static inline __attribute__((always_inline)) uint16_t
em_get_dst_port_pumpking(const struct lcore_conf *qconf, struct rte_mbuf *pkt,uint8_t portid)
{
	uint8_t next_hop;
	KeyType key;
	struct ipv4_hdr *ipv4_hdr;
	
	ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *,sizeof(struct ether_hdr));


	#if PRINT==PRINT_ON
		int i=0;
        char LOG_TEMP[1024];
        RTE_LOG(DEBUG , L3FWD, "------------------------------------------------------------\n");
        RTE_LOG(DEBUG , L3FWD, "proto_id=%2x\n",ipv4_hdr->next_proto_id);
		if(ipv4_hdr->next_proto_id == TYPE_CONTROL)
		{	
			control_public_header_t * control_public_hdr=(control_public_header_t *)(ipv4_hdr+1);
			
			if(control_public_hdr->control_type== control_type_register)
			{
                RTE_LOG(DEBUG , L3FWD, "[%s]control_type==%2x\n",__func__,control_public_hdr->control_type);
				control_register_t *control_register_hdr=(control_register_t *)(control_public_hdr+1);
                RTE_LOG(DEBUG , L3FWD, "______REGISTER___INFORMATION__________\n");

                arrayToHexStr(&control_register_hdr->n_sid[i],NID_LENGTH,LOG_TEMP);
                RTE_LOG(DEBUG , L3FWD, "sid_p = %s\n",LOG_TEMP);

                arrayToHexStr(&control_register_hdr->l_sid[i],L_SID_LENGTH,LOG_TEMP);
                RTE_LOG(DEBUG , L3FWD, "sid_l = %s\n",LOG_TEMP);

                static uint64_t usedTime=0;
                static uint64_t freeTime=0;

                //TODO:分到对应的线程上
                int select = control_register_hdr->l_sid[L_SID_LENGTH-1]%NUM_PTHREAD;
                int ret = pthread_mutex_trylock(&buffLock[select]);
                if (0 == ret) {
                    //the lock isnt used
                    //如果被锁定
                    memcpy(&registerBuff[select],control_register_hdr, sizeof(control_register_t));
                    isFull[select] = true;
                    pthread_mutex_unlock(&buffLock[select]);
                    pthread_cond_signal(&buffCond[select]);
                    freeTime++;
                } else if(EBUSY == ret){
                    //锁正在被使用;
                    usedTime++;
                    printf("buff【%d】锁正在被使用[%lu] 空闲<%lu>\n",select,usedTime,freeTime);
                }


                //TODO:线性直接处理注册包
                //process_register(control_register_hdr);

                arrayToHexStr(&control_register_hdr->nid_s[0],NID_LENGTH,LOG_TEMP);
                RTE_LOG(DEBUG , L3FWD, "nid_s = %s\n",LOG_TEMP);

				switch(control_register_hdr->scope)
				{
					case 1: sprintf(LOG_TEMP,"%s"," (默认上级)");	break;
					case 2:  sprintf(LOG_TEMP,"%s"," (本域有效)");	break;
					case 3:  sprintf(LOG_TEMP,"%s"," (对等通告)");	break;
					case 4:  sprintf(LOG_TEMP,"%s"," (服从策略)");	break;
					default:  sprintf(LOG_TEMP,"%s"," (未知)");
				}
                RTE_LOG(DEBUG , L3FWD, "scope = %2X %s\n",control_register_hdr->scope,LOG_TEMP);

                RTE_LOG(DEBUG , L3FWD, "time_of_validity = %d\n",control_register_hdr->time_of_validity);

				switch(control_register_hdr->time_unit)
				{
					case 1: sprintf(LOG_TEMP,"%s"," (秒)");	break;
					case 2: sprintf(LOG_TEMP,"%s", " (分)");	break;
					case 3: sprintf(LOG_TEMP,"%s", " (小时)");	break;
					case 4: sprintf(LOG_TEMP,"%s", " (天)");	break;
					case 5: sprintf(LOG_TEMP,"%s", " (星期)");	break;
					case 6: sprintf(LOG_TEMP,"%s", " (月)");	break;
					case 7: sprintf(LOG_TEMP,"%s", " (年)");	break;
					default: sprintf(LOG_TEMP,"%s", " (未知)");
				}
                RTE_LOG(DEBUG , L3FWD, "time_unit = %2X %s\n",control_register_hdr->time_unit,LOG_TEMP);

                RTE_LOG(DEBUG , L3FWD, "content_size = %d bytes\n", control_register_hdr->content_size);

				switch(control_register_hdr->content_classification)
				{
					case 0x1: sprintf(LOG_TEMP,"%s", " (txt)");		break;
					case 0x2: sprintf(LOG_TEMP,"%s", " (image)");	break;
					case 0x3: sprintf(LOG_TEMP,"%s", " (video)");	break;
				}
                RTE_LOG(DEBUG , L3FWD, "content_classification = %2X %s\n",control_register_hdr->content_classification,LOG_TEMP);
			}else if(control_public_hdr->control_type==control_tpye_announce){
                //TODO:协商的具体方式有待商榷
                uint64_t hz_timer = rte_get_timer_hz();
                uint64_t cur_tsc1 = rte_rdtsc();

                printf("\n\n");

                static int len=0;
                len=5;

                double a[len];
                double b[len];

                for(i=0;i<len;i++){
                    a[i]=mysrand(1,5);
                    b[i]=mysrand(1,5);
                    printf("[%d]%0.2f,%0.2f\n",i,a[i],b[i]);
                }

                int select=nash2(a,b,len);
                printf("select=%d\n",select);

                uint64_t cur_tsc2 = rte_rdtsc();
                printf("tsc_dif=%ld\n",cur_tsc2-cur_tsc1);
                printf("hz_timer=%ld\n",hz_timer);
            }
		
		}
		else if(ipv4_hdr->next_proto_id == TYPE_GET)
		{
				
			CoLoR_get_t * get_hdr=(CoLoR_get_t *)(ipv4_hdr+1);
			find_mongodb (get_hdr);
            printf("[From %s]find_mongodb over\n",__func__);
            //TODO:测试删除的功能，查找后并删除这个记录

		}
		

		//Return the original port;
		
		//printf("Return %d\n",portid);
		

	//不要改变原来数据流的方向
/*		return 1;
	 	return portid;*/

	#endif
	

	CoLoR_get_t * get_hdr=(CoLoR_get_t *)( (uint8_t*)ipv4_hdr+sizeof(struct ipv4_hdr ) );	

	memcpy(&key,&get_hdr->nid_sid[0],36);
	const void * key_array[1]={&key};
	int res=255;

    uint64_t hz_timer = rte_get_timer_hz();
    uint64_t cur_tsc1 = rte_rdtsc();
	res=cuckoo_find_bulk_batch( qconf->sid_lookup_struct,&key_array[0] , 1,&next_hop );
    uint64_t cur_tsc2 = rte_rdtsc();
    printf("hz_timer=%"PRIu64" [Local] %"PRIu64" \n",hz_timer,cur_tsc2-cur_tsc1);

	//TODO:SID在另外一个Socket的那个表上，当时有两个Socket,现在只有一个
	if(/*next_hop==255*/ 1){
        uint64_t cur_tsc1 = rte_rdtsc();
        res=cuckoo_find_bulk_batch( qconf->sid_lookup_struct_another_socket,&key_array[0] , 1,&next_hop );
        uint64_t cur_tsc2 = rte_rdtsc();
        printf("hz_timer=%"PRIu64" [Remote] %"PRIu64" \n",hz_timer,cur_tsc2-cur_tsc1);
    }


	if (next_hop >= RTE_MAX_ETHPORTS ||(enabled_port_mask & 1 << next_hop) == 0)
	{
		next_hop = portid;
	}

	return next_hop;
}

static inline
void l3fwd_em_send_packets_pumpking(int nb_rx, struct rte_mbuf **pkts_burst,uint8_t portid, struct lcore_conf *qconf)
{
	int32_t j=0;
	uint16_t dst_port[MAX_PKT_BURST];

	int32_t n = RTE_ALIGN_FLOOR(nb_rx, 8);
/*
	for (j = 0; j < n; j += 8) {
			em_get_dst_port_ipv4x8_pumpking(qconf, &pkts_burst[j], portid, &dst_port[j]);
	}
*/

//TODO:测试什么也C


	for (; j < nb_rx; j++){
		//dst_port[j]= portid;
		dst_port[j] = em_get_dst_port_pumpking(qconf, pkts_burst[j], portid);
	}
		
/*
	int ii=0;
	for(ii=0;ii<nb_rx;ii++)
	{
		if(dst_port[ii]<4)
		{
			dst_port[ii]=dst_port[ii]+4;
		}
		else
		{
			dst_port[ii]=dst_port[ii]-4;
		}
	}
*/
	send_packets_multi(qconf, pkts_burst, dst_port, nb_rx);

}

static inline void
populate_ipv6_many_flow_into_table(const struct rte_hash *h,
		unsigned int nr_flow)
{
	unsigned i;

	mask1 = (rte_xmm_t){.u32 = {BIT_16_TO_23, ALL_32_BITS,
				ALL_32_BITS, ALL_32_BITS} };
	mask2 = (rte_xmm_t){.u32 = {ALL_32_BITS, ALL_32_BITS, 0, 0} };

	for (i = 0; i < nr_flow; i++) {
		struct ipv6_l3fwd_em_route entry;
		union ipv6_5tuple_host newkey;

		uint8_t a = (uint8_t)((i/NUMBER_PORT_USED)%BYTE_VALUE_MAX);
		uint8_t b = (uint8_t)(((i/NUMBER_PORT_USED)/BYTE_VALUE_MAX)%BYTE_VALUE_MAX);
		uint8_t c = (uint8_t)((i/NUMBER_PORT_USED)/(BYTE_VALUE_MAX*BYTE_VALUE_MAX));

		/* Create the ipv6 exact match flow */
		memset(&entry, 0, sizeof(entry));
		switch (i & (NUMBER_PORT_USED - 1)) {
		case 0:
			entry = ipv6_l3fwd_em_route_array[0];
			break;
		case 1:
			entry = ipv6_l3fwd_em_route_array[1];
			break;
		case 2:
			entry = ipv6_l3fwd_em_route_array[2];
			break;
		case 3:
			entry = ipv6_l3fwd_em_route_array[3];
			break;
		};
		entry.key.ip_dst[13] = c;
		entry.key.ip_dst[14] = b;
		entry.key.ip_dst[15] = a;
		convert_ipv6_5tuple(&entry.key, &newkey);
		int32_t ret = rte_hash_add_key(h, (void *) &newkey);

		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Unable to add entry %u\n", i);

		ipv6_l3fwd_out_if[ret] = (uint8_t) entry.if_out;

	}
	printf("Hash: Adding 0x%x keys\n", nr_flow);
}

/* Requirements:
 * 1. IP packets without extension;
 * 2. L4 payload should be either TCP or UDP.
 */
int
em_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4_ext = 0;
	int ptype_l3_ipv6_ext = 0;
	int ptype_l4_tcp = 0;
	int ptype_l4_udp = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		switch (ptypes[i]) {
		case RTE_PTYPE_L3_IPV4_EXT:
			ptype_l3_ipv4_ext = 1;
			break;
		case RTE_PTYPE_L3_IPV6_EXT:
			ptype_l3_ipv6_ext = 1;
			break;
		case RTE_PTYPE_L4_TCP:
			ptype_l4_tcp = 1;
			break;
		case RTE_PTYPE_L4_UDP:
			ptype_l4_udp = 1;
			break;
		}
	}

	if (ptype_l3_ipv4_ext == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV4_EXT\n", portid);
	if (ptype_l3_ipv6_ext == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV6_EXT\n", portid);
	if (!ptype_l3_ipv4_ext || !ptype_l3_ipv6_ext)
		return 0;

	if (ptype_l4_tcp == 0)
		printf("port %d cannot parse RTE_PTYPE_L4_TCP\n", portid);
	if (ptype_l4_udp == 0)
		printf("port %d cannot parse RTE_PTYPE_L4_UDP\n", portid);
	if (ptype_l4_tcp && ptype_l4_udp)
		return 1;

	return 0;
}

static inline void
em_parse_ptype(struct rte_mbuf *m)
{
	struct ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;
	void *l3;
	int hdr_len;
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ether_type = eth_hdr->ether_type;
	l3 = (uint8_t *)eth_hdr + sizeof(struct ether_hdr);
	if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		ipv4_hdr = (struct ipv4_hdr *)l3;
		hdr_len = (ipv4_hdr->version_ihl & IPV4_HDR_IHL_MASK) *
			  IPV4_IHL_MULTIPLIER;
		if (hdr_len == sizeof(struct ipv4_hdr)) {
			packet_type |= RTE_PTYPE_L3_IPV4;
			if (ipv4_hdr->next_proto_id == IPPROTO_TCP)
				packet_type |= RTE_PTYPE_L4_TCP;
			else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
				packet_type |= RTE_PTYPE_L4_UDP;
		} else
			packet_type |= RTE_PTYPE_L3_IPV4_EXT;
	} else if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		ipv6_hdr = (struct ipv6_hdr *)l3;
		if (ipv6_hdr->proto == IPPROTO_TCP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_TCP;
		else if (ipv6_hdr->proto == IPPROTO_UDP)
			packet_type |= RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_UDP;
		else
			packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;
	}

	m->packet_type = packet_type;
}

uint16_t
em_cb_parse_ptype(uint8_t port __rte_unused, uint16_t queue __rte_unused,
		  struct rte_mbuf *pkts[], uint16_t nb_pkts,
		  uint16_t max_pkts __rte_unused,
		  void *user_param __rte_unused)
{
	unsigned i;

	for (i = 0; i < nb_pkts; ++i)
		em_parse_ptype(pkts[i]);

	return nb_pkts;
}

/**************************Wen Xingbeng***********************************/

struct sid_port_route{
	KeyType key_sid;
	ValType val_port;
};

//For Socket1  won right SID item!
static struct sid_port_route sid_port_route_array1[]={
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,0}, 0},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,1}, 1},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,2}, 2},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,3}, 3},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,4}, 0},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,5}, 1},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,6}, 2},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,7}, 3},
};
//For Socket2
static struct sid_port_route sid_port_route_array2[]={
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,0}, 0},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,1}, 1},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,2}, 2},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,3}, 3},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,4}, 0},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,5}, 1},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,6}, 2},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,7}, 3},
};

/*
//For Socket1  won right SID item!
static struct sid_port_route sid_port_route_array1[]={
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,0}, 0},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,1}, 1},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,2}, 2},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,3}, 3},
};
//For Socket2
static struct sid_port_route sid_port_route_array2[]={
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,4}, 0},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,5}, 1},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,6}, 2},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,7}, 3},
};
*/

/*
//For Socket1  won right SID item!
static struct sid_port_route sid_port_route_array1[]={
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,0}, 0},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,1}, 1},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,2}, 2},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,3}, 3},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,4}, 4},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,5}, 5},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,6}, 6},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,7}, 7},
};
//For Socket2
static struct sid_port_route sid_port_route_array2[]={
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,0}, 0},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,1}, 1},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,2}, 2},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,3}, 3},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,4}, 4},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,5}, 5},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,6}, 6},
	{ {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,   0,0,0,0,0,7}, 7},
};
*/


#define myhashpower 10
#define myhsahloader 0.80

static long long number=(2<<(myhashpower+1))*myhsahloader;
static uint64_t refresh_frequncey=(2<<(myhashpower+1))*myhsahloader*0.01*2;


static inline void
delete_socket_one_by_one( cuckoo_hashtable_t *h ,int socketid,uint32_t index){
	uint32_t i;
	uint32_t array_len=0;
	//不同的Socket插入不同的哈希表条目
	if(socketid==0)
	{
		array_len=sizeof(sid_port_route_array1)/sizeof( struct sid_port_route);
	}else
	{
		array_len=sizeof(sid_port_route_array2)/sizeof( struct sid_port_route);	
	}

	for(i=0;i<array_len;i++)
	{
		struct sid_port_route item;
		//不同的Socket插入不同的哈希表条目
		if(socketid==0){
			item=sid_port_route_array1[i];
		}else{
			item=sid_port_route_array2[i];		
		}
	}
	//超过了Hash表承载的最大条目（number）
	if(i>number)
	{
		return;
	}
	
	i=index;
	uint8_t a=i%256;
	uint8_t b=(i/256)%256;
	uint8_t c=(i/256/256)%256;
	uint8_t d=(i/256/256/256)%256;
	uint8_t e=(i/256/256/256/256)%256;
	uint8_t f=(i/256/256/256/256/256)%256;
	
	struct sid_port_route item;
	if(socketid==0){
		//We only the the first item!!!
		item=sid_port_route_array1[0];
	}else{
		item=sid_port_route_array2[0];		
	}
	item.key_sid.sid[0]=a;
	item.key_sid.sid[1]=b;
	item.key_sid.sid[2]=c;
	item.key_sid.sid[3]=d;
	item.key_sid.sid[4]=e;
	item.key_sid.sid[5]=f;
	
	//Make it different!
	item.key_sid.sid[6]=0xff;
	
	cuckoo_status st=cuckoo_delete(h, (char *)&item.key_sid);
	if(st!=ok)
	{
		  printf("\033[5;34m Delete Error!\n \033[0m");
	}
	
	//cuckoo_report(h);
}

static inline void
populate_socket_one_by_one( cuckoo_hashtable_t *h ,int socketid,uint32_t index){
	uint32_t i;
	uint32_t array_len=0;
	//不同的Socket插入不同的哈希表条目
	if(socketid==0)
	{
		array_len=sizeof(sid_port_route_array1)/sizeof( struct sid_port_route);
	}else
	{
		array_len=sizeof(sid_port_route_array2)/sizeof( struct sid_port_route);	
	}

	for(i=0;i<array_len;i++)
	{
		struct sid_port_route item;
		//不同的Socket插入不同的哈希表条目
		if(socketid==0)
		{
			item=sid_port_route_array1[i];
		}else
		{
			item=sid_port_route_array2[i];		
		}
	}
	
	if(i>number)
	{
		return;
	}
	
	i=index;
	uint8_t a=i%256;
	uint8_t b=(i/256)%256;
	uint8_t c=(i/256/256)%256;
	uint8_t d=(i/256/256/256)%256;
	uint8_t e=(i/256/256/256/256)%256;
	uint8_t f=(i/256/256/256/256/256)%256;
	
	struct sid_port_route item;
	if(socketid==0)
	{
		//We only the the first item!!!
		item=sid_port_route_array1[0];
	}else
	{
		item=sid_port_route_array2[0];		
	}
	item.key_sid.sid[0]=a;
	item.key_sid.sid[1]=b;
	item.key_sid.sid[2]=c;
	item.key_sid.sid[3]=d;
	item.key_sid.sid[4]=e;
	item.key_sid.sid[5]=f;
	
	//Make it different!
	item.key_sid.sid[6]=0xff;
	
	cuckoo_status st=cuckoo_insert(h, (char *)&item.key_sid, (char *)&item.val_port);
	if(st!=ok)
	{
		  printf("\033[5;34m Insert Error!\n \033[0m");
	}
	
	//cuckoo_report(h);
}

#define TIMER_RESOLUTION_CYCLES 20000000ULL /* around 10ms at 2 Ghz */
/* timer1 callback */
void timer1_cb( )
{
	static uint32_t cycles=0;
	int socketid=0;
	
	static uint64_t cur_tsc_timer_all=0;
	
	uint64_t cur_tsc_timer_1 = rte_rdtsc();
	populate_socket_one_by_one( (cuckoo_hashtable_t*)sid_cuckoo_struct[socketid],socketid,cycles);
	delete_socket_one_by_one( (cuckoo_hashtable_t*)sid_cuckoo_struct[socketid],socketid,cycles);
	cycles++;
	uint64_t cur_tsc_timer_2 = rte_rdtsc();
	cur_tsc_timer_all+=(cur_tsc_timer_2-cur_tsc_timer_1);
	
	if(cycles%refresh_frequncey==0)
	{
		cuckoo_report((cuckoo_hashtable_t*)sid_cuckoo_struct[socketid]);
		printf("%s/%s/%u, cycles=%u, tsc_compare_average=%lu\n",__FILE__,__func__,__LINE__,cycles,cur_tsc_timer_all/refresh_frequncey);
		cur_tsc_timer_all=0;
		fflush(stdout);
		printf("\r\033[k");
	}
}


/* main processing loop */
int
em_main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, nb_rx;
	uint8_t portid, queueid;
	struct lcore_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {

		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%hhu rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	//The lcore 1 is designed to run the timer 1;
	unsigned timer1_lcore_id =1;
	uint64_t prev_tsc_timer = 0, cur_tsc_timer, diff_tsc_timer;
	uint64_t hz_timer = rte_get_timer_hz();
	
	while (!force_quit) {

		cur_tsc = rte_rdtsc();
		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) 
		{

			for (i = 0; i < qconf->n_tx_port; ++i) 
			{
				portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;

				send_burst(qconf,qconf->tx_mbufs[portid].len,portid);
				qconf->tx_mbufs[portid].len = 0;
			}
			prev_tsc = cur_tsc;
		}
		
		
		//--------------------------------------------------
//:TODO 定时器向cuckoohash表中注册内容
//This code is a timer to insert and delete the hash entry!		
/*
		if(lcore_id==timer1_lcore_id)
		{
			cur_tsc_timer = rte_rdtsc();
			diff_tsc_timer = cur_tsc_timer - prev_tsc_timer;
			if (diff_tsc_timer > hz_timer/refresh_frequncey) 
			{
				timer1_cb();
				prev_tsc_timer = cur_tsc_timer;
			}
		}
*/

		/*
		 * Read packet from RX queues
		 */
		
		//struct rte_mbuf mbuf1;
		//struct rte_mbuf mbuf2;
		//send_mbuf(0, &mbuf1);
		//send_mbuf(1, &mbuf2);

		for (i = 0; i < qconf->n_rx_queue; ++i) 
		{
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;	
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,MAX_PKT_BURST);
			
			
			
			if (nb_rx == 0)
			{
				continue;
			}
				

#if defined(__SSE4_1__)
			//现在程序的运行路径
			l3fwd_em_send_packets_pumpking(nb_rx, pkts_burst,portid, qconf);
#else
			l3fwd_em_no_opt_send_packets(nb_rx, pkts_burst,portid, qconf);
#endif /* __SSE_4_1__ */
		}
	}

	return 0;
}

/* 
 * Initialize exact match (hash) parameters.
 */

//插入 SID->INDEX 的表
static inline void
populate_socket( cuckoo_hashtable_t *h ,int socketid){
	uint32_t i;
	uint32_t array_len=0;
	//different socket insert different cuckoo table!!!!
	if(socketid==0){
		array_len=sizeof(sid_port_route_array1)/sizeof( struct sid_port_route);
	}else{
		array_len=sizeof(sid_port_route_array2)/sizeof( struct sid_port_route);	
	}

	for(i=0;i<array_len;i++)
	{
		struct sid_port_route item;

		//different socket insert different cuckoo table!!!!
		if(socketid==0){
			item=sid_port_route_array1[i];
		}else{
			item=sid_port_route_array2[i];		
		}
		cuckoo_status st=cuckoo_insert(h, (char *)&item.key_sid, (char *)&item.val_port);
		if(st!=ok){
			  printf("\033[5;34m Insert Error!\n \033[0m");
		}
	}
	for(i=1;i<=number;i++)
	{
		uint8_t a=i%256;
		uint8_t b=(i/256)%256;
		uint8_t c=(i/256/256)%256;
		uint8_t d=(i/256/256/256)%256;
		uint8_t e=(i/256/256/256/256)%256;
		uint8_t f=(i/256/256/256/256/256)%256;
		
		struct sid_port_route item;
		if(socketid==0){
			//We only the the first item!!!
			item=sid_port_route_array1[0];
		}else{
			item=sid_port_route_array2[0];		
		}
		item.key_sid.sid[0]=a;
		item.key_sid.sid[1]=b;
		item.key_sid.sid[2]=c;
		item.key_sid.sid[3]=d;
		item.key_sid.sid[4]=e;
		item.key_sid.sid[5]=f;
		
		cuckoo_status st=cuckoo_insert(h, (char *)&item.key_sid, (char *)&item.val_port);
		if(st!=ok){
			  printf("\033[5;34m Insert Error!\n \033[0m");
		}
	}
	
	cuckoo_report(h);
}

static inline void
populate_socket_few( cuckoo_hashtable_t *h ,int socketid){
	uint32_t i;
	uint32_t array_len=0;
	//different socket insert different cuckoo table!!!!
	if(socketid==0){
		array_len=sizeof(sid_port_route_array1)/sizeof( struct sid_port_route);
	}else{
		array_len=sizeof(sid_port_route_array2)/sizeof( struct sid_port_route);	
	}

	for(i=0;i<array_len;i++)
	{
		struct sid_port_route item;

		//different socket insert different cuckoo table!!!!
		if(socketid==0){
			item=sid_port_route_array1[i];
		}else{
			item=sid_port_route_array2[i];		
		}
		cuckoo_status st=cuckoo_insert(h, (char *)&item.key_sid, (char *)&item.val_port);
		if(st!=ok){
			  printf("\033[5;34m Insert Error!\n \033[0m");
		}
	}
	cuckoo_report(h);
}

/*^^^^^^^^^^^^^^^^^^^^^^^^^Wen Xingbeng^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^*/

void
setup_hash(const int socketid)
{
	struct rte_hash_parameters ipv4_l3fwd_hash_params = {
		.name = NULL,
		.entries = L3FWD_HASH_ENTRIES,
		.key_len = sizeof(union ipv4_5tuple_host),
		.hash_func = ipv4_hash_crc,
		.hash_func_init_val = 0,
	};

	struct rte_hash_parameters ipv6_l3fwd_hash_params = {
		.name = NULL,
		.entries = L3FWD_HASH_ENTRIES,
		.key_len = sizeof(union ipv6_5tuple_host),
		.hash_func = ipv6_hash_crc,
		.hash_func_init_val = 0,
	};

	char s[64];

	/* create ipv4 hash */
	snprintf(s, sizeof(s), "ipv4_l3fwd_hash_%d", socketid);
	ipv4_l3fwd_hash_params.name = s;
	ipv4_l3fwd_hash_params.socket_id = socketid;
	ipv4_l3fwd_em_lookup_struct[socketid] =
		rte_hash_create(&ipv4_l3fwd_hash_params);
	if (ipv4_l3fwd_em_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd hash on socket %d\n",
			socketid);
			
	/**************************Wen Xingbeng***********************************/
	printf("[From %s]CACHE_LINE_SIZE=%d\n",__func__,RTE_CACHE_LINE_SIZE);
	printf("[From %s]socketid=%d\n",__func__,socketid);
	snprintf(s,sizeof(s),"cuckoohash_l3fwd_hash_%d",socketid);
	struct cuckooparameter sid_cuckparameter={
		.name=s,
		.hashpower=myhashpower,
		.socket_id=socketid,
	};
	sid_cuckoo_struct[socketid]=rte_cuckoohash_create(&sid_cuckparameter);
	if(sid_cuckoo_struct[socketid]==NULL)
	{
		rte_exit(EXIT_FAILURE,"CAN NOT CREAT CUCKOOHASH TABLE on SOCKET %d\n",socketid);
	}

	populate_socket_few( (cuckoo_hashtable_t*)sid_cuckoo_struct[socketid],socketid);
	//populate_socket_few( (cuckoo_hashtable_t*)sid_cuckoo_struct[socketid],socketid);

    printf("\033[5;34m CoLoR \n\033[0m");
	//getchar();
	/*^^^^^^^^^^^^^^^^^^^^^^^^^Wen Xingbeng^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^*/

	/* create ipv6 hash */
	snprintf(s, sizeof(s), "ipv6_l3fwd_hash_%d", socketid);
	ipv6_l3fwd_hash_params.name = s;
	ipv6_l3fwd_hash_params.socket_id = socketid;
	ipv6_l3fwd_em_lookup_struct[socketid] =
		rte_hash_create(&ipv6_l3fwd_hash_params);
	if (ipv6_l3fwd_em_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd hash on socket %d\n",
			socketid);

	if (hash_entry_number != HASH_ENTRY_NUMBER_DEFAULT) {
		/* For testing hash matching with a large number of flows we
		 * generate millions of IP 5-tuples with an incremented dst
		 * address to initialize the hash table. */
		if (ipv6 == 0) {
			/* populate the ipv4 hash */
			populate_ipv4_many_flow_into_table(
				ipv4_l3fwd_em_lookup_struct[socketid],
				hash_entry_number);
		} else {
			/* populate the ipv6 hash */
			populate_ipv6_many_flow_into_table(
				ipv6_l3fwd_em_lookup_struct[socketid],
				hash_entry_number);
		}
	} else {
		/*
		 * Use data in ipv4/ipv6 l3fwd lookup table
		 * directly to initialize the hash table.
		 */
		if (ipv6 == 0) {
			/* populate the ipv4 hash */
			populate_ipv4_few_flow_into_table(
				ipv4_l3fwd_em_lookup_struct[socketid]);
		} else {
			/* populate the ipv6 hash */
			populate_ipv6_few_flow_into_table(
				ipv6_l3fwd_em_lookup_struct[socketid]);
		}
	}
}

/* Return ipv4/ipv6 em fwd lookup struct. */
void *
em_get_ipv4_l3fwd_lookup_struct(const int socketid)
{
	return ipv4_l3fwd_em_lookup_struct[socketid];
}

void *
em_get_ipv6_l3fwd_lookup_struct(const int socketid)
{
	return ipv6_l3fwd_em_lookup_struct[socketid];
}

void *
em_get_sid_l3fwd_lookup_struct(const int socketid)
{
	return sid_cuckoo_struct[socketid];
}

void *
em_get_sid_l3fwd_lookup_struct_another_socket(const int socketid)
{
	return sid_cuckoo_struct[ (socketid+1)%2] ;
	//return sid_cuckoo_struct[socketid];
}
