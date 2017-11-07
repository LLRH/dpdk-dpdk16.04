#ifndef CITY_HASH_H_
#define CITY_HASH_H_

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
/*
从端口发出去一个rte_mbuf结构体的内容

@portid 目的端口号
@mubf 指向rte_mbuf结构体的指针
@无返回值
*/
extern inline void send_mbuf(uint8_t portid, struct rte_mbuf *mubf);
#endif
