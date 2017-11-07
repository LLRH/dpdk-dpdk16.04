/***
日期:2017年3月10日
作者:温兴泵(微信号:WenXingBeng)
--------------------------------------
DPDK版本为16.04的L3fwd程序的发包补丁
使用方法：
1.把send_packet.h和send_packet.c放到其文件下面，把send_packet.c 加到Makefile里面 把警告的错误去掉
2.把Main.c里面 170行左右的 pktmbuf_pool的static去掉，使其成为全局变量
3.然后就可以在程序里面直接调用 send_mbuf函数完成发包了
***/

#ifndef SEND_PACKET_H_
#define SEND_PACKET_H_

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
extern inline void send_mbuf(uint8_t portid, struct rte_mbuf *mubf, unsigned lcore_id);
#endif
