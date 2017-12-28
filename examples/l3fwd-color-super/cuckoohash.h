#ifndef _CUCKOOHASH_H
#define _CUCKOOHASH_H

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <fcntl.h>
//#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

//my add
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

#include <tmmintrin.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_malloc.h>


#include "config.h"
#include "cuckoohash_config.h"
//#include "hash.h"
#include "city.h"
#include "util.h"

typedef enum {
    ok = 0,
    failure = 1,
    failure_key_not_found = 2,
    failure_key_duplicated = 3,
    failure_space_not_enough = 4,
    failure_function_not_supported = 5,
    failure_table_full = 6,
} cuckoo_status;

//my add
struct cuckooparameter {
	const char *name;
	unsigned int hashpower;
	int socket_id;
};

/*
 * the structure of a buckoo hash table
 */
typedef struct {
    /* number of items inserted */
    size_t hashitems;

    /* 2**hashpower is the number of buckets */
    size_t hashpower;

    /* the mask for bucket index */
    size_t hashmask;

    /* pointer to the array of buckets */
    void*  buckets;
    /*
     *  keyver_array is an array of version counters
     *  we keep keyver_count = 8192
     *
     */
    void* keyver_array;

    /* the mutex to serialize insert, delete, expand */
    pthread_mutex_t lock;

    /* record the path */
    void* cuckoo_path;

    /* number of cuckoo operations*/
    size_t kick_count;

} cuckoo_hashtable_t;



/** 
 * @brief Initialize the hash table
 * 
 * @param h handler to the hash table
 * @param hashtable_init The logarithm of the initial table size
 *
 * @return handler to the hashtable on success, NULL on failure
 */
cuckoo_hashtable_t* cuckoo_init(const int hashpower_init);

/** 
 * @brief Cleanup routine
 * 
 */
cuckoo_status cuckoo_exit(cuckoo_hashtable_t* h);


/** 
 * @brief Lookup key in the hash table
 * 
 * @param h handler to the hash table
 *
 * @param key key to search 
 * @param val value to return
 * 
 * @return ok if key is found, not_found otherwise
 */
cuckoo_status cuckoo_find(cuckoo_hashtable_t* h, const V *key, char *val);

cuckoo_status cuckoo_find_batch(cuckoo_hashtable_t* h,const char *key, char *val,uint32_t hv,uint32_t i1);

int cuckoo_find_bulk_batch(cuckoo_hashtable_t *h, const void **keys,uint32_t num_keys, char *positions);

/** 
 * @brief Insert key/value to cuckoo hash table
 * 
 *  Inserting new key/value pair. 
 *  If the key is already inserted, the new value will not be inserted
 *
 *
 * @param h handler to the hash table
 * @param key key to be inserted
 * @param val value to be inserted
 * 
 * @return ok if key/value are succesfully inserted
 */
cuckoo_status cuckoo_insert(cuckoo_hashtable_t* h, const char *key, const char* val);


/** 
 * @brief Delete key/value from cuckoo hash table
 * 
 * @param h handler to the hash table
 * @param key key to be deleted
 *
 * @return ok if key is succesfully deleted, not_found if the key is not present
 */
cuckoo_status cuckoo_delete(cuckoo_hashtable_t* h, const char *key);


/** 
 * @brief Print stats of this hash table
 * 
 * @param h handler to the hash table
 * 
 * @return Void
 */
void cuckoo_report(cuckoo_hashtable_t* h);

//my add
int cuckoo_find_bulk(cuckoo_hashtable_t *h, const void **keys, uint32_t num_keys, char *positions);
cuckoo_hashtable_t * rte_cuckoohash_create(const struct cuckooparameter *params);

#endif
