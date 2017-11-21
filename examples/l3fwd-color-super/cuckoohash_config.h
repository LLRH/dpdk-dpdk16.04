#ifndef _CUCKOOHASH_CONFIG_H
#define _CUCKOOHASH_CONFIG_H
#include <stdint.h>

#include "CoLoR.h"
/*
typedef union ipv4_5tuple_host_cuckoo{
	struct {
		uint8_t  pad0;
		uint8_t  proto;
		uint16_t pad1;
		uint32_t ip_src;
		uint32_t ip_dst;
		uint16_t port_src;
		uint16_t port_dst;
	};
	__m128i xmm;
} KeyType;
*/
/*
typedef union get_sid_1tuple_host_cuckoo{
        struct{
        uint8_t sid[SIDLEN];
        uint8_t pad[12];
        };__attribute__((__packed__))
        __m128i xmm[2];
}KeyType;
 */

typedef struct{
        uint8_t sid[36];
}KeyType;

typedef char ValType;

/* size of bulk cleaning */
#define DEFAULT_BULK_CLEAN 1024


/* set DEBUG to 1 to enable debug output */
#define DEBUG_CUCKOO 1


#endif
