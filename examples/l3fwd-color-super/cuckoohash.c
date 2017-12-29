/*t* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/**
 * @file   cuckoohash.c
 * @author Bin Fan <binfan@cs.cmu.edu>
 * @date   Mon Feb 25 22:17:04 2013
 *
 * @brief  implementation of single-writer/multi-reader cuckoo hash
 *
 *
 */

#include "cuckoohash.h"

/*
 * default hash table size
 */
#define HASHPOWER_DEFAULT 16

/*
 * The maximum number of cuckoo operations per insert,
 */
#define MAX_CUCKOO_COUNT 500

/*
 * The number of cuckoo paths
 */
#define NUM_CUCKOO_PATH 2

#define  keyver_count ((uint32_t)1 << (13))
#define  keyver_mask  (keyver_count - 1)


/*
 * the structure of a bucket
 */
#define bucketsize 4
typedef struct {
    KeyType keys[bucketsize];    //36*4
    ValType vals[bucketsize];    //1*4
	char tags[bucketsize];       //1*4
	//char pading[40];             //40    40+(36+4+4)*4=152+40=192
}  __attribute__((__packed__))
Bucket;


/*
 //  @brief Atomic read the counter
#define start_read_keyver(h, idx)                                      \
    ((uint32_t*) h->keyver_array)[idx & keyver_mask]

#define end_read_keyver(h, idx, result)                                \  \
    result = ((uint32_t*) h->keyver_array)[idx & keyver_mask]


 // @brief Atomic increase the counter

#define start_incr_keyver(h, idx)                                      \
    do { ((uint32_t *)h->keyver_array)[idx & keyver_mask] += 1; \
	__asm__ __volatile__("" ::: "memory"); \
       } while(0)

#define end_incr_keyver(h, idx)                                      \
    do { \
    __sync_fetch_and_add(&((uint32_t*) h->keyver_array)[idx & keyver_mask], 1); \
    } while(0)
*/

/**
 *  @brief Atomic read the counter
 *
 */
#define start_read_keyver(h, idx)                                      \
    __sync_fetch_and_add(&((uint32_t*) h->keyver_array)[idx & keyver_mask], 0)

#define end_read_keyver(h, idx, result)                                \
    do { __asm__ __volatile__("" ::: "memory");  \
    result = ((uint32_t*) h->keyver_array)[idx & keyver_mask]; \
    } while (0)

/**
 * @brief Atomic increase the counter
 *
 */
#define start_incr_keyver(h, idx)                                      \
    do { ((uint32_t *)h->keyver_array)[idx & keyver_mask] += 1; \
	__asm__ __volatile__("" ::: "memory"); \
       } while(0)

#define end_incr_keyver(h, idx)                                      \
    do { \
    __sync_fetch_and_add(&((uint32_t*) h->keyver_array)[idx & keyver_mask], 1); \
    } while(0)

static inline  uint32_t _hashed_key(const char* key) {
    return CityHash32(key, sizeof(KeyType));
}

//TODO:克服2的指数增长！！！！
#define hashsize(n) ((uint64_t) ((1 << n)*(1.4)))
#define hashmask(n) (hashsize(n) - 1)



/**
 * @brief Compute the index of the first bucket
 *
 * @param hv 32-bit hash value of the key
 *
 * @return The first bucket
 */
static inline size_t _index_hash(cuckoo_hashtable_t* h, const uint32_t hv) 
{
//    return  (hv >> (32 - h->hashpower));
    return  (hv % (hashmask(h->hashpower)+1) );
}

/*
static inline size_t _index_hash(cuckoo_hashtable_t* h, const uint32_t hv)
{
//    return  (hv >> (32 - h->hashpower));
    return  (hv & hashmask(h->hashpower));
}
*/

/**
 * @brief Compute the index of the second bucket
 *
 * @param hv 32-bit hash value of the key
 * @param index The index of the first bucket
 *
 * @return  The second bucket
 */
static inline size_t _alt_index(cuckoo_hashtable_t* h,const uint32_t hv,const size_t index) 
{
    // 0x5bd1e995 is the hash constant from MurmurHash2
    //uint32_t tag = hv & 0xFF;
    uint32_t tag = hv >> 24;
    return (index ^ (tag * 0x5bd1e995)) % (hashmask(h->hashpower)+1);
}

/**
 * @brief Compute the index of the corresponding counter in keyver_array
 *
 * @param hv 32-bit hash value of the key
 *
 * @return The index of the counter
 */
static inline size_t _lock_index(const uint32_t hv) 
{
    return hv & keyver_mask;
}


#define TABLE_KEY(h, i, j) ((Bucket*) h->buckets)[i].keys[j]
#define TABLE_VAL(h, i, j) ((Bucket*) h->buckets)[i].vals[j]
#define TABLE_TAG(h, i, j) ((Bucket*) h->buckets)[i].tags[j]


static inline bool is_slot_empty(cuckoo_hashtable_t* h,size_t i,size_t j) 
{
    if (TABLE_KEY(h, i, j).sid[0] == 0
        &&TABLE_KEY(h, i, j).sid[1] == 0
        &&TABLE_KEY(h, i, j).sid[2] == 0
        &&TABLE_KEY(h, i, j).sid[3] == 0
        &&TABLE_KEY(h, i, j).sid[4] == 0
        &&TABLE_KEY(h, i, j).sid[5] == 0
        &&TABLE_KEY(h, i, j).sid[6] == 0
        &&TABLE_KEY(h, i, j).sid[7] == 0
        &&TABLE_KEY(h, i, j).sid[8] == 0
        &&TABLE_KEY(h, i, j).sid[9] == 0
        &&TABLE_KEY(h, i, j).sid[10] == 0
        &&TABLE_KEY(h, i, j).sid[11] == 0
        &&TABLE_KEY(h, i, j).sid[12] == 0
        &&TABLE_KEY(h, i, j).sid[13] == 0
        &&TABLE_KEY(h, i, j).sid[14] == 0
        &&TABLE_KEY(h, i, j).sid[15] == 0
        &&TABLE_KEY(h, i, j).sid[16] == 0
        &&TABLE_KEY(h, i, j).sid[17] == 0
        &&TABLE_KEY(h, i, j).sid[18] == 0
        &&TABLE_KEY(h, i, j).sid[19] == 0  
        &&TABLE_KEY(h, i, j).sid[20] == 0  
        &&TABLE_KEY(h, i, j).sid[21] == 0
        &&TABLE_KEY(h, i, j).sid[22] == 0
        &&TABLE_KEY(h, i, j).sid[23] == 0
        &&TABLE_KEY(h, i, j).sid[24] == 0
        &&TABLE_KEY(h, i, j).sid[25] == 0
        &&TABLE_KEY(h, i, j).sid[26] == 0
        &&TABLE_KEY(h, i, j).sid[27] == 0
        &&TABLE_KEY(h, i, j).sid[28] == 0
        &&TABLE_KEY(h, i, j).sid[29] == 0
        &&TABLE_KEY(h, i, j).sid[30] == 0  
        &&TABLE_KEY(h, i, j).sid[31] == 0
        &&TABLE_KEY(h, i, j).sid[32] == 0   
        &&TABLE_KEY(h, i, j).sid[33] == 0   
        &&TABLE_KEY(h, i, j).sid[34] == 0   
        &&TABLE_KEY(h, i, j).sid[35] == 0                    
    ) return true;
    
    return false;
}



typedef struct  {
    size_t buckets[NUM_CUCKOO_PATH];
    size_t slots[NUM_CUCKOO_PATH];
	//char tags[NUM_CUCKOO_PATH];
    KeyType keys[NUM_CUCKOO_PATH];
}  __attribute__((__packed__))
CuckooRecord;



/**
 * @brief Make bucket from[idx] slot[whichslot] available to insert a new item
 *
 * @param from:   the array of bucket index
 * @param whichslot: the slot available
 * @param  depth: the current cuckoo depth
 *
 * @return depth on success, -1 otherwise
 */
static int _cuckoopath_search(cuckoo_hashtable_t* h,size_t depth_start,size_t *cp_index) 
{
    int depth = depth_start;
    while ((h->kick_count < MAX_CUCKOO_COUNT) &&
           (depth >= 0) &&
           (depth < MAX_CUCKOO_COUNT - 1))
    {

        CuckooRecord *curr = ((CuckooRecord*) h->cuckoo_path) + depth;
        CuckooRecord *next = ((CuckooRecord*) h->cuckoo_path) + depth + 1;
		
        /*
         * Check if any slot is already free
         */
        size_t idx;
        for (idx = 0; idx < NUM_CUCKOO_PATH; idx ++) {
            size_t i;
            size_t j;
            i = curr->buckets[idx];
            for (j = 0; j < bucketsize; j ++) {
                if (is_slot_empty(h, i, j)) {
                    curr->slots[idx] = j;
                    *cp_index   = idx;
                    return depth;
                }
            }

            /* pick the victim as the j-th item */
            j = rand() % bucketsize;
            curr->slots[idx] = j;
            curr->keys[idx]  = TABLE_KEY(h, i, j);
			
            uint32_t hv = _hashed_key((char*) &TABLE_KEY(h, i, j));
            next->buckets[idx] = _alt_index(h, hv, i);
        }

        h->kick_count += NUM_CUCKOO_PATH;
        depth ++;
    }

    DBG("%zu max cuckoo achieved, abort\n", h->kick_count);
    return -1;
}

static int _cuckoopath_move(cuckoo_hashtable_t* h,size_t depth_start,size_t idx) 
{

    int depth = depth_start;
    while (depth > 0) 
    {

        /*
         * Move the key/value in  buckets[i1] slot[j1] to buckets[i2] slot[j2]
         * and make buckets[i1] slot[j1] available
         *
         */
        CuckooRecord *from = ((CuckooRecord*) h->cuckoo_path) + depth - 1;
        CuckooRecord *to   = ((CuckooRecord*) h->cuckoo_path) + depth;
        size_t i1 = from->buckets[idx];
        size_t j1 = from->slots[idx];
	
        size_t i2 = to->buckets[idx];
        size_t j2 = to->slots[idx];
		

        /*
         * We plan to kick out j1, but let's check if it is still there;
         * there's a small chance we've gotten scooped by a later cuckoo.
         * If that happened, just... try again.
         */
        if (!keycmp((char*) &TABLE_KEY(h, i1, j1), (char*) &(from->keys[idx]))) {
            /* try again */
            return depth;
        }

        assert(is_slot_empty(h, i2, j2));

        uint32_t hv = _hashed_key((char*) &TABLE_KEY(h, i1, j1));
        size_t keylock   = _lock_index(hv);

        start_incr_keyver(h, keylock);

        TABLE_KEY(h, i2, j2) = TABLE_KEY(h, i1, j1);
        TABLE_VAL(h, i2, j2) = TABLE_VAL(h, i1, j1);
		TABLE_TAG(h, i2, j2) = TABLE_TAG(h, i1, j1);
        // TABLE_KEY(h, i1, j1) = (KeyType)(0);
        // TABLE_VAL(h, i1, j1) = (KeyType)(0);

		//my add
		memset((char *)&TABLE_KEY(h, i1, j1), 0, sizeof(KeyType));
		memset((char *)&TABLE_VAL(h, i1, j1), 0, sizeof(ValType));  //修改
		memset((char *)&TABLE_TAG(h, i1, j1), 0, sizeof(char));     //修改
		//memset(&entry, 0, sizeof(entry));

        end_incr_keyver(h, keylock);
        depth --;
    }

    return depth;

}

static int _run_cuckoo(cuckoo_hashtable_t* h,size_t i1,size_t i2) 
{
    int cur;
    size_t idx;
    size_t depth = 0;
    for (idx = 0; idx < NUM_CUCKOO_PATH; idx ++) 
    {
        if (idx< NUM_CUCKOO_PATH/2)
            ((CuckooRecord*) h->cuckoo_path)[depth].buckets[idx] = i1;
        else
            ((CuckooRecord*) h->cuckoo_path)[depth].buckets[idx] = i2;
    }
    h->kick_count = 0;
    while (1) 
    {
        cur = _cuckoopath_search(h, depth, &idx);
        if (cur < 0)
            return -1;

        cur = _cuckoopath_move(h, cur, idx);
        if (cur == 0)
            return idx;

        depth = cur - 1;
    }

    return -1;
}


/**
 * @brief Try to read bucket i and check if the given key is there
 *
 * @param key The key to search
 * @param val The address to copy value to
 * @param i Index of bucket
 *
 * @return true if key is found, false otherwise
 */
static bool _try_read_from_bucket(cuckoo_hashtable_t* h,const char *key,const char *val,size_t i,char tag)
{
    size_t  j;

    for (j = 0; j < bucketsize; j ++)
    {
//Tag优化1/1处----------------
	    if(tag == TABLE_TAG(h, i, j))
	    {
            if (keycmp((char*) &TABLE_KEY(h, i, j), key))
		     {
			    //printf("the ip_src is: 0x%x\n",TABLE_KEY(h, i, j).ip_src);
			    //printf("the ip_dst is: 0x%x\n",TABLE_KEY(h, i, j).ip_dst);
			    //printf("the port_src is: 0x%x\n",TABLE_KEY(h, i, j).port_src);
			    //printf("the port_dst is: 0x%x\n",TABLE_KEY(h, i, j).port_dst);
			    //printf("the proto is: 0x%x\n",TABLE_KEY(h, i, j).proto);
        		memcpy((char *)val, (const char*) &TABLE_VAL(h, i, j), sizeof(ValType));
	            return true;
		     }
	    }
    }
    return false;
}

/**
 * @brief Try to add key/val to bucket i,
 *
 * @param key Pointer to the key to store
 * @param val Pointer to the value to store
 * @param i Bucket index
 * @param keylock The index of key version counter
 *
 *
 * @return true on success and false on failure
 */
static bool _try_add_to_bucket(cuckoo_hashtable_t* h,const char* key,const char* val,size_t i,size_t keylock,char tag) 
{
    size_t j;
//	printf("enter the _try_add_to_bucket\n");
    for (j = 0; j < bucketsize; j ++) 
    {
        if (is_slot_empty(h, i, j)) 
        {
            start_incr_keyver(h, keylock);
            memcpy(&TABLE_KEY(h, i, j), key, sizeof(KeyType));
            memcpy(&TABLE_VAL(h, i, j), val, sizeof(ValType));
			memcpy(&TABLE_TAG(h, i, j), &tag, sizeof(char));
            h->hashitems ++;
//			printf("leave the _try_add_to_bucket,succeed!\n");
            end_incr_keyver(h, keylock);
            return true;
        }
    }
//	printf("leave the _try_add_to_bucket,succeed!\n");
    return false;
}




/**
 * @brief Try to delete key and its corresponding value from bucket i,
 *
 * @param key Pointer to the key to store
 * @param i Bucket index
 * @param keylock The index of key version counter

 * @return true if key is found, false otherwise
 */
static bool _try_del_from_bucket(cuckoo_hashtable_t* h,const char*key,size_t i,size_t keylock) 
{
    size_t j;
    for (j = 0; j < bucketsize; j ++) 
    {
        if (keycmp((char*) &TABLE_KEY(h, i, j), key)) 
        {
            start_incr_keyver(h, keylock);
			memset((char *)&TABLE_KEY(h, i, j), 0, sizeof(KeyType));
			memset((char *)&TABLE_VAL(h, i, j), 0, sizeof(ValType));
            //TABLE_KEY(h, i, j) = 0;
            //TABLE_VAL(h, i, j) = 0;
            /* buckets[i].keys[j] = 0; */
            /* buckets[i].vals[j] = 0; */

            h->hashitems --;

            end_incr_keyver(h, keylock);
            return true;
        }
    }
    return false;
}


/**
 * @brief internal of cuckoo_find
 *
 * @param key
 * @param val
 * @param i1
 * @param i2
 * @param keylock
 *
 * @return
 */
 
static cuckoo_status _cuckoo_find_batch(cuckoo_hashtable_t* h,const char *key,char *val,size_t i1,size_t keylock,uint32_t hv) 
{
    bool result;
    uint32_t vs, ve;
TryRead:
    vs = start_read_keyver(h, keylock);
	//printf("the vs is %d",(unsigned int)vs);
	char tag = (char)(hv>>24);
    result = _try_read_from_bucket(h, key, val, i1,tag);
    if (!result) {
		size_t i2      = _alt_index(h, hv, i1);
        result = _try_read_from_bucket(h, key, val, i2,tag);
    }

    end_read_keyver(h, keylock, ve);
	//printf("the ve is %d",(unsigned int)ve);

    if (vs & 1 || vs != ve)
        goto TryRead;

    if (result)
        return ok;
    else
        return failure_key_not_found;
}


static cuckoo_status _cuckoo_find(cuckoo_hashtable_t* h,const char *key,const char *val,size_t i1,size_t i2,size_t keylock,char tag)
{
    bool result;

    uint32_t vs, ve;
TryRead:
    vs = start_read_keyver(h, keylock);
	//printf("enter the populate_ipv4_many_flow_into_table2\n");
	//printf("the vs is %d",(unsigned int)vs);
    result = _try_read_from_bucket(h, key, val, i1,tag);
    if (!result) {
        result = _try_read_from_bucket(h, key, val, i2,tag);
    }

    end_read_keyver(h, keylock, ve);
	//printf("the ve is %d",(unsigned int)ve);

    if (vs & 1 || vs != ve)
        goto TryRead;

    if (result)
        return ok;
    else
        return failure_key_not_found;
}


static cuckoo_status _cuckoo_insert(cuckoo_hashtable_t* h,const char* key,const char * val,size_t i1,size_t i2,size_t keylock,char tag)
{

    /*
     * try to add new key to bucket i1 first, then try bucket i2
     */
 
    if (_try_add_to_bucket(h, key, val, i1, keylock, tag))
        return ok;
	

    if (_try_add_to_bucket(h, key, val, i2, keylock, tag))
        return ok;


    /*
     * we are unlucky, so let's perform cuckoo hashing
     */
    int idx = _run_cuckoo(h, i1, i2);
    if (idx >= 0) {
        size_t i;
        i = ((CuckooRecord*) h->cuckoo_path)[0].buckets[idx];
        //j = cuckoo_path[0].slots[idx];
        if (_try_add_to_bucket(h, key, val, i, keylock,tag)) {
            return ok;
        }
    }

    DBG("hash table is full (hashpower = %zu, hash_items = %zu, load factor = %.2f), need to increase hashpower\n",
        h->hashpower, h->hashitems, 1.0 * h->hashitems / bucketsize / hashsize(h->hashpower));

    return failure_table_full;

}

static cuckoo_status _cuckoo_delete(cuckoo_hashtable_t* h,const char* key,size_t i1,size_t i2,size_t keylock) 
{
    if (_try_del_from_bucket(h, key, i1, keylock))
        return ok;

    if (_try_del_from_bucket(h, key, i2, keylock))
        return ok;

    return failure_key_not_found;
}

/********************************************************************
 *               Interface of cuckoo hash table
 *********************************************************************/

cuckoo_hashtable_t *
rte_cuckoohash_create(const struct cuckooparameter *params)
{   
	RTE_LOG(ERR, HASH, "enter the rte_cuckoohash_create\n");
	char hash_name[32] = "cuckhashtable";

//Hugepage修改1/4处---------------
	cuckoo_hashtable_t* h = (cuckoo_hashtable_t*)rte_zmalloc_socket(hash_name, sizeof(cuckoo_hashtable_t), RTE_CACHE_LINE_SIZE, params->socket_id);	printf("[From %s]采用Hugepage\n",__func__);
//	cuckoo_hashtable_t* h = (cuckoo_hashtable_t*)malloc(sizeof(cuckoo_hashtable_t));printf("[From %s]不采用Hugepage\n",__func__);

	if (h == NULL) 
	{
		printf("first_failed!\n");
		RTE_LOG(ERR, HASH, "cuckoo_hashtable_t memory allocation failed\n");
		goto exit;
	}

	// h->hashpower  = (hashtable_init > 0) ? hashtable_init : HASHPOWER_DEFAULT;
	h->hashitems  = 0;
	h->kick_count = 0;
	pthread_mutex_init(&h->lock, NULL);
	h->hashpower = params->hashpower;

//Hugepage修改2/4处---------------
	printf("[From %s]2 start !\n",__func__);
	printf("[From %s]entry hashsize:%ld\n", __func__,hashsize(params->hashpower)*4);
	printf("[From %s]sizeof bucket:%ld\n",__func__,sizeof(Bucket));
	printf("[From %s]size：%ld\n",__func__,hashsize(params->hashpower)*sizeof(Bucket));
	h->buckets = rte_zmalloc_socket(hash_name,hashsize(params->hashpower) * sizeof(Bucket),RTE_CACHE_LINE_SIZE, params->socket_id);
//	h->buckets = malloc(hashsize(params->hashpower) * sizeof(Bucket));

	if (! h->buckets) {
		printf("second failed!\n");
		RTE_LOG(ERR, HASH, "cuckoo_hashtable_t Failed to init hashtable.\n");
        goto  exit;
	}

//Hugepage修改3/4处---------------
	h->keyver_array = rte_zmalloc_socket(hash_name,keyver_count * sizeof(uint32_t),RTE_CACHE_LINE_SIZE, params->socket_id);
//	h->keyver_array = malloc(keyver_count * sizeof(uint32_t));

	if (! h->keyver_array) {
		RTE_LOG(ERR, HASH, "Failed to init key version array.\n");
       		goto  exit;
	}

//Hugepage修改4/4处---------------
	h->cuckoo_path = rte_zmalloc_socket(hash_name,MAX_CUCKOO_COUNT * sizeof(CuckooRecord),RTE_CACHE_LINE_SIZE, params->socket_id);
//	h->cuckoo_path = malloc(MAX_CUCKOO_COUNT * sizeof(CuckooRecord));

    if (! h->cuckoo_path) {
		RTE_LOG(ERR, HASH, "cuckoo_hashtable_t Failed to init cuckoo path.\n");
        goto  exit;
    }

    memset(h->buckets, 0, hashsize(h->hashpower) * sizeof(Bucket));
    memset(h->keyver_array, 0, keyver_count * sizeof(uint32_t));
    memset(h->cuckoo_path, 0, MAX_CUCKOO_COUNT * sizeof(CuckooRecord));

	cuckoo_report(h);
	//TAILQ_INSERT_TAIL(hash_list, h, next);

exit:
	//rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);
	RTE_LOG(ERR, HASH, "leave the rte_cuckoohash_create\n");
	return h;
}

cuckoo_hashtable_t* cuckoo_init(const int hashtable_init) 
{
    cuckoo_hashtable_t* h = (cuckoo_hashtable_t*) malloc(sizeof(cuckoo_hashtable_t));
    if (!h)
        goto Cleanup;

    h->hashpower  = (hashtable_init > 0) ? hashtable_init : HASHPOWER_DEFAULT;
    h->hashitems  = 0;
    h->kick_count = 0;
    pthread_mutex_init(&h->lock, NULL);

    h->buckets = malloc(hashsize(h->hashpower) * sizeof(Bucket));
    if (! h->buckets) {
        fprintf(stderr, "Failed to init hashtable.\n");
        goto Cleanup;
    }

    h->keyver_array = malloc(keyver_count * sizeof(uint32_t));
    if (! h->keyver_array) {
        fprintf(stderr, "Failed to init key version array.\n");
        goto Cleanup;
    }

    h->cuckoo_path = malloc(MAX_CUCKOO_COUNT * sizeof(CuckooRecord));
    if (! h->cuckoo_path) {
        fprintf(stderr, "Failed to init cuckoo path.\n");
        goto Cleanup;
    }

    memset(h->buckets, 0, hashsize(h->hashpower) * sizeof(Bucket));
    memset(h->keyver_array, 0, keyver_count * sizeof(uint32_t));
    memset(h->cuckoo_path, 0, MAX_CUCKOO_COUNT * sizeof(CuckooRecord));

    return h;

Cleanup:
    if (h) {
        free(h->cuckoo_path);
        free(h->keyver_array);
        free(h->buckets);
    }
    free(h);
    return NULL;

}

cuckoo_status cuckoo_exit(cuckoo_hashtable_t* h) 
{
    pthread_mutex_destroy(&h->lock);
    free(h->buckets);
    free(h->keyver_array);
    free(h);
    return ok;
}

int
cuckoo_find_bulk_batch(cuckoo_hashtable_t *h, const void **keys,uint32_t num_keys, char *positions)
{
	uint32_t i;
//my find
//printf("sss\n");
	uint32_t hv[8];
	uint32_t i1[8];
	uint32_t i2[8];
	size_t keylock[8];
    for (i = 0; i < num_keys;i++)
    {
    	//printf("enter\n");
	    hv[i]    = _hashed_key(keys[i]);
        i1[i]    = _index_hash(h, hv[i]);
		i2[i]    = _alt_index(h, hv[i], i1[i]);
		keylock[i] = _lock_index(hv[i]);
		/*  
	    rte_prefetch1((void *) (((Bucket*) (h->buckets))+i1[i]));
	    rte_prefetch1((void *) (((Bucket*) (h->buckets))+i1[i]+1));
	    rte_prefetch1((void *) (((Bucket*) (h->buckets))+i2[i]));
        rte_prefetch1((void *) (((Bucket*) (h->buckets))+i2[i]+1));
  	    		
		rte_prefetch1((void *) &TABLE_KEY(h, i1[i],0));
		rte_prefetch1((void *) &TABLE_KEY(h, i2[i],0));
		rte_prefetch1((void *) &TABLE_VAL(h, i1[i],0));
		rte_prefetch1((void *) &TABLE_VAL(h, i2[i],0));
	*/
		//	rte_prefetch1((void *) &TABLE_KEY(h, i1[i],0));  //预取key

//prefecthing修改1/1处------------
		rte_prefetch1((void *) &TABLE_TAG(h, i1[i],0));  //预取tag
		rte_prefetch1((void *) &TABLE_VAL(h, i1[i],0));  //预取tag
			
    }

	uint32_t j =0;
	for(j = 0; j< num_keys; j++)
	{		
	    positions[j] = -1;
		char tag = (char)(hv[j]>>24);
	    cuckoo_status st = _cuckoo_find(h, keys[j], (char *)&positions[j], i1[j],i2[j], keylock[j],tag);
	
		if (st == failure_key_not_found) 
		{
		//	printf("key not found!\n");
			positions[j] = -1;
		}
	}
	return 0;
}


int
cuckoo_find_bulk(cuckoo_hashtable_t *h, const void **keys,uint32_t num_keys, char *positions)
{
	uint32_t i;
//my find
	for (i = 0; i < num_keys; i++) {
        positions[i] = -1;
        cuckoo_status st = cuckoo_find(h,keys[i],(char *)&positions[i]);
        //	printf("st:%d\n",st);
        //	printf("positions[0]:%d\n",positions[0]);
        if(st == failure_key_not_found)
        {
            positions[i] = -1;
        }
    }
	return 0;
}


cuckoo_status cuckoo_find_batch(cuckoo_hashtable_t* h,const char *key, char *val,uint32_t hv,uint32_t i1)
 {

   // uint32_t hv    = _hashed_key(key);
   // size_t i1      = _index_hash(h, hv);
   // size_t i2      = _alt_index(h, hv, i1);
    size_t keylock = _lock_index(hv);

    cuckoo_status st = _cuckoo_find_batch(h, key, val, i1, keylock,hv);
/*
    if (st == failure_key_not_found) 
    {
        //printf("miss for key  i1=%zu i2=%zu\n",i1);
    }
	else 
		printf("find succeed!\n");
*/		
    return st;
}


cuckoo_status cuckoo_find(cuckoo_hashtable_t* h,const char *key, char *val)
 {

    uint32_t hv    = _hashed_key(key);
    size_t i1      = _index_hash(h, hv);
    size_t i2      = _alt_index(h, hv, i1);
    size_t keylock = _lock_index(hv);
	char tag = (char)(hv>>24);

    cuckoo_status st = _cuckoo_find(h, key, val, i1,i2, keylock,tag);
/*
    if (st == failure_key_not_found) {
        printf("miss for key  i1=%zu i2=%zu\n",i1, i2);
    }
	else 
		printf("find succeed!\n");
		*/
    return st;
}



cuckoo_status cuckoo_insert(cuckoo_hashtable_t* h,const char *key,const char * val)
{
    uint32_t hv = _hashed_key(key);
    size_t i1   = _index_hash(h, hv);
    size_t i2   = _alt_index(h, hv, i1);
    size_t keylock = _lock_index(hv);
    char tag = (char)(hv>>24);
    ValType oldval;
    cuckoo_status st;

    mutex_lock(&h->lock);
    
    st = _cuckoo_find(h, key, (char*)&oldval, i1, i2, keylock,tag);

    if  (st == ok) {
        mutex_unlock(&h->lock);
        return failure_key_duplicated;
    }

    st =  _cuckoo_insert(h, key, val, i1, i2, keylock, tag);

    mutex_unlock(&h->lock);
//	cuckoo_report(h);
    return st;
}

cuckoo_status cuckoo_delete(cuckoo_hashtable_t* h,const char *key) 
{
    uint32_t hv = _hashed_key(key);
    size_t i1   = _index_hash(h, hv);
    size_t i2   = _alt_index(h, hv, i1);
    size_t keylock = _lock_index(hv);
    cuckoo_status st;
    mutex_lock(&h->lock);
    st = _cuckoo_delete(h, key, i1, i2, keylock);
    mutex_unlock(&h->lock);
    return st;
}

void cuckoo_report(cuckoo_hashtable_t* h) 
{
    size_t sz;
    sz = sizeof(Bucket) * hashsize(h->hashpower);
    DBG("total number of items %zu\n", h->hashitems);
	/*
	for(int i = 0; i < h->hashpower; i++){
		DBG("the items is %zu\n", h->hashitem);
		}
	*/
    DBG("total size %zu Bytes, or %.2f MB\n", sz, (float) sz / (1 <<20));
    DBG("load factor %.4f\n", 1.0 * h->hashitems / bucketsize / hashsize(h->hashpower));
}
