#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "set.h"
#include <stdint.h>

// MurmurHash3 constants
#define MURMUR_HASH_SEED 0xabcdef1234567890ULL
#define MURMUR_HASH_C1   0x87c37b91114253d5ULL
#define MURMUR_HASH_C2   0x4cf5ad432745937fULL
#define MURMUR_HASH_R1   31
#define MURMUR_HASH_R2   27
#define MURMUR_HASH_R3   33
#define MURMUR_HASH_M    5
#define MURMUR_HASH_N    0xe6546b64

static uint64_t MurmurHash3(const char* key, size_t len) {
    const uint64_t* data = (const uint64_t*)key;
    const size_t num_blocks = len / 8;

    uint64_t h1 = MURMUR_HASH_SEED;

    for (size_t i = 0; i < num_blocks; i++) {
        uint64_t k1 = data[i];
        k1 *= MURMUR_HASH_C1;
        k1 = (k1 << MURMUR_HASH_R1) | (k1 >> (64 - MURMUR_HASH_R1));
        k1 *= MURMUR_HASH_C2;

        h1 ^= k1;
        h1 = (h1 << MURMUR_HASH_R2) | (h1 >> (64 - MURMUR_HASH_R2));
        h1 = h1 * MURMUR_HASH_M + MURMUR_HASH_N;
    }

    const uint8_t* tail = (const uint8_t*)(key + num_blocks * 8);
    uint64_t k1 = 0;

    switch (len & 7) {
        case 7: k1 ^= (uint64_t)tail[6] << 48;
        case 6: k1 ^= (uint64_t)tail[5] << 40;
        case 5: k1 ^= (uint64_t)tail[4] << 32;
        case 4: k1 ^= (uint64_t)tail[3] << 24;
        case 3: k1 ^= (uint64_t)tail[2] << 16;
        case 2: k1 ^= (uint64_t)tail[1] << 8;
        case 1:
            k1 ^= (uint64_t)tail[0];
            k1 *= MURMUR_HASH_C1;
            k1 = (k1 << MURMUR_HASH_R1) | (k1 >> (64 - MURMUR_HASH_R1));
            k1 *= MURMUR_HASH_C2;
            h1 ^= k1;
    }

    h1 ^= len;
    h1 ^= (h1 >> 33);
    h1 *= 0xff51afd7ed558ccdULL;
    h1 ^= (h1 >> 33);
    h1 *= 0xc4ceb9fe1a85ec53ULL;
    h1 ^= (h1 >> 33);

    return h1;
}

static uint64_t __default_hash(const char *key) {
    return MurmurHash3(key, strlen(key));
}
// Function to check if a number is prime
bool is_prime(int num) {
    if (num <= 1) {
        return false;
    }
    if (num <= 3) {
        return true;
    }
    if (num % 2 == 0 || num % 3 == 0) {
        return false;
    }

    for (int i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0) {
            return false;
        }
    }

    return true;
}

// Function to find the nearest prime greater than or equal to a given number
int find_nearest_prime(int num) {
    if (num <= 1) {
        return 2;  // Smallest prime number
    }

    while (true) {
        if (is_prime(num)) {
            return num;
        }
        num++;
    }
}

#define MAX_FULLNESS_PERCENT 0.25

/* PRIVATE FUNCTIONS */
static uint64_t __default_hash(const char *key);
static int __get_index(SimpleSet *set, const char *key, uint64_t hash, uint64_t *index);
static int __assign_node(SimpleSet *set, const char *key, uint64_t hash, uint64_t index);
static void __free_index(SimpleSet *set, uint64_t index);
static int __set_contains(SimpleSet *set, const char *key, uint64_t hash);
static int __set_add(SimpleSet *set, const char *key, uint64_t hash);
static void __relayout_nodes(SimpleSet *set, uint64_t start, short end_on_null);


// Optimize collision handling with quadratic probing
static int __get_index_and_resize(SimpleSet *set, const char *key, uint64_t hash, simple_set_node **nodes, uint64_t size, uint64_t *index) {
    uint64_t i, idx;
    idx = hash % size;
    i = idx;
    size_t len = strlen(key);
    uint64_t step = 1; // Quadratic probing step

    while (1) {
        simple_set_node *node = nodes[i];
        if (node == NULL) {
            *index = i;
            return SET_FALSE; // Not here OR first open slot
        } else if (hash == node->_hash && len == strlen(node->_key) && strncmp(key, node->_key, len) == 0) {
            *index = i;
            return SET_TRUE;
        }
        
        step += 2;
        i = (i + step) % size;
        if (i == idx) // This means we went all the way around and the set is full
            return SET_CIRCULAR_ERROR;
    }
}


// Dynamic resizing strategy
static int __resize_set(SimpleSet *set) {
    uint64_t new_size = (uint64_t)(set->number_nodes * 1.5);
    simple_set_node **new_nodes = (simple_set_node **)calloc(new_size, sizeof(simple_set_node *));

    if (new_nodes == NULL)
        return SET_MALLOC_ERROR;

    // Initialize the new nodes array
    uint64_t i;
    for (i = 0; i < new_size; ++i) {
        new_nodes[i] = NULL;
    }

    // Rehash and move existing elements to the new array
    for (i = 0; i < set->number_nodes; ++i) {
        simple_set_node *node = set->nodes[i];
        if (node != NULL) {
            uint64_t new_index;
            __get_index_and_resize(set, node->_key, node->_hash, new_nodes, new_size, &new_index);
        }
    }

    free(set->nodes);
    set->nodes = new_nodes;
    set->number_nodes = new_size;

    return SET_TRUE;
}

int set_init_alt(SimpleSet *set, uint64_t initial_capacity, set_hash_function hash) {
    // Choose a prime number as the initial capacity
    // You can use a function to find the nearest prime number or manually select one.
    uint64_t prime_capacity = find_nearest_prime(initial_capacity);

    set->nodes = (simple_set_node **)calloc(prime_capacity, sizeof(simple_set_node *));
    if (set->nodes == NULL) {
        return SET_MALLOC_ERROR;
    }
    set->number_nodes = prime_capacity;
    uint64_t i;
    for (i = 0; i < set->number_nodes; ++i) {
        set->nodes[i] = NULL;
    }
    set->used_nodes = 0;
    set->hash_function = (hash == NULL) ? &__default_hash : hash;
    return SET_TRUE;
}


int set_clear(SimpleSet *set)
{
    uint64_t i;
    for (i = 0; i < set->number_nodes; ++i)
    {
        if (set->nodes[i] != NULL)
        {
            __free_index(set, i);
        }
    }
    set->used_nodes = 0;
    return SET_TRUE;
}

int set_destroy(SimpleSet *set)
{
    set_clear(set);
    free(set->nodes);
    set->number_nodes = 0;
    set->used_nodes = 0;
    set->hash_function = NULL;
    return SET_TRUE;
}

int set_add(SimpleSet *set, const char *key)
{
    uint64_t hash = set->hash_function(key);
    return __set_add(set, key, hash);
}

int set_contains(SimpleSet *set, const char *key)
{
    uint64_t index, hash = set->hash_function(key);
    return __get_index(set, key, hash, &index);
}

int set_remove(SimpleSet *set, const char *key)
{
    uint64_t index, hash = set->hash_function(key);
    int pos = __set_contains(set, key, hash);
    if (pos != SET_TRUE)
    {
        return pos;
    }
    // remove this node
    __free_index(set, index);
    // re-layout nodes
    __relayout_nodes(set, index, 0);
    --set->used_nodes;
    return SET_TRUE;
}

uint64_t set_length(SimpleSet *set)
{
    return set->used_nodes;
}

char **set_to_array(SimpleSet *set, uint64_t *size)
{
    *size = set->used_nodes;
    char **results = (char **)calloc(set->used_nodes + 1, sizeof(char *));
    uint64_t i, j = 0;
    size_t len;
    for (i = 0; i < set->number_nodes; ++i)
    {
        if (set->nodes[i] != NULL)
        {
            len = strlen(set->nodes[i]->_key);
            results[j] = (char *)calloc(len + 1, sizeof(char));
            memcpy(results[j], set->nodes[i]->_key, len);
            ++j;
        }
    }
    return results;
}

static int __add_to_set(SimpleSet *set, const char *key, uint64_t hash) {
    // Resize if needed
    if ((float)set->used_nodes / set->number_nodes > MAX_FULLNESS_PERCENT) {
        if (__resize_set(set) != SET_TRUE) {
            return SET_MALLOC_ERROR;
        }
    }

    uint64_t index;
    int contains = __get_index(set, key, hash, &index);

    if (contains == SET_TRUE)
        return SET_ALREADY_PRESENT;

    // Add element in
    if (index == SET_CIRCULAR_ERROR) {
        // Handle set full case
        return SET_CIRCULAR_ERROR;
    }

    __assign_node(set, key, hash, index);
    ++set->used_nodes;
    return SET_TRUE;
}


int set_union(SimpleSet *res, SimpleSet *s1, SimpleSet *s2)
{
    if (res->used_nodes != 0)
    {
        return SET_OCCUPIED_ERROR;
    }
    // loop over both s1 and s2 and add keys to res
    uint64_t i;
    for (i = 0; i < s1->number_nodes; ++i)
    {
        if (s1->nodes[i] != NULL)
        {
            __add_to_set(res, s1->nodes[i]->_key, s1->nodes[i]->_hash);
        }
    }
    for (i = 0; i < s2->number_nodes; ++i)
    {
        if (s2->nodes[i] != NULL)
        {
            __add_to_set(res, s2->nodes[i]->_key, s2->nodes[i]->_hash);
        }
    }
    return SET_TRUE;
}
int set_intersection(SimpleSet *res, SimpleSet *s1, SimpleSet *s2) {
    if (res->used_nodes != 0) {
        return SET_OCCUPIED_ERROR;
    }

    uint64_t i;
    for (i = 0; i < s1->number_nodes; ++i) {
        if (s1->nodes[i] != NULL) {
            const char *key = s1->nodes[i]->_key;
            uint64_t hash = s1->nodes[i]->_hash;

            if (__set_contains(s2, key, hash) == SET_TRUE) {
                __set_add(res, key, hash);
            }
        }
    }

    return SET_TRUE;
}


/* difference is s1 - s2 */
int set_difference(SimpleSet *res, SimpleSet *s1, SimpleSet *s2)
{
    if (res->used_nodes != 0)
    {
        return SET_OCCUPIED_ERROR;
    }
    // loop over s1 and keep only things not in s2
    uint64_t i;
    for (i = 0; i < s1->number_nodes; ++i)
    {
        if (s1->nodes[i] != NULL)
        {
            if (__set_contains(s2, s1->nodes[i]->_key, s1->nodes[i]->_hash) != SET_TRUE)
            {
                __set_add(res, s1->nodes[i]->_key, s1->nodes[i]->_hash);
            }
        }
    }
    return SET_TRUE;
}

int set_symmetric_difference(SimpleSet *res, SimpleSet *s1, SimpleSet *s2)
{
    if (res->used_nodes != 0)
    {
        return SET_OCCUPIED_ERROR;
    }
    uint64_t i;
    // loop over set 1 and add elements that are unique to set 1
    for (i = 0; i < s1->number_nodes; ++i)
    {
        if (s1->nodes[i] != NULL)
        {
            if (__set_contains(s2, s1->nodes[i]->_key, s1->nodes[i]->_hash) != SET_TRUE)
            {
                __set_add(res, s1->nodes[i]->_key, s1->nodes[i]->_hash);
            }
        }
    }
    // loop over set 2 and add elements that are unique to set 2
    for (i = 0; i < s2->number_nodes; ++i)
    {
        if (s2->nodes[i] != NULL)
        {
            if (__set_contains(s1, s2->nodes[i]->_key, s2->nodes[i]->_hash) != SET_TRUE)
            {
                __set_add(res, s2->nodes[i]->_key, s2->nodes[i]->_hash);
            }
        }
    }
    return SET_TRUE;
}

int set_is_subset(SimpleSet *test, SimpleSet *against)
{
    uint64_t i;
    for (i = 0; i < test->number_nodes; ++i)
    {
        if (test->nodes[i] != NULL)
        {
            if (__set_contains(against, test->nodes[i]->_key, test->nodes[i]->_hash) == SET_FALSE)
            {
                return SET_FALSE;
            }
        }
    }
    return SET_TRUE;
}

int set_is_subset_strict(SimpleSet *test, SimpleSet *against)
{
    if (test->used_nodes >= against->used_nodes)
    {
        return SET_FALSE;
    }
    return set_is_subset(test, against);
}

int set_cmp(SimpleSet *left, SimpleSet *right)
{
    if (left->used_nodes < right->used_nodes)
    {
        return SET_RIGHT_GREATER;
    }
    else if (right->used_nodes < left->used_nodes)
    {
        return SET_LEFT_GREATER;
    }
    uint64_t i;
    for (i = 0; i < left->number_nodes; ++i)
    {
        if (left->nodes[i] != NULL)
        {
            if (set_contains(right, left->nodes[i]->_key) != SET_TRUE)
            {
                return SET_UNEQUAL;
            }
        }
    }

    return SET_EQUAL;
}

static int __set_contains(SimpleSet *set, const char *key, uint64_t hash)
{
    uint64_t index;
    return __get_index(set, key, hash, &index);
}

static int __set_add(SimpleSet *set, const char *key, uint64_t hash)
{
    uint64_t index;
    int contains = __get_index(set, key, hash, &index);
    
    if (contains == SET_TRUE)
        return SET_ALREADY_PRESENT;

    // Expand nodes if we are close to our desired fullness
    if ((float)set->used_nodes / set->number_nodes > MAX_FULLNESS_PERCENT)
    {
        uint64_t num_els = set->number_nodes * 2; // we want to double each time
        simple_set_node **tmp = (simple_set_node **)realloc(set->nodes, num_els * sizeof(simple_set_node *));
        if (tmp == NULL) // realloc failure
            return SET_MALLOC_ERROR;
        set->nodes = tmp;

        set->nodes = tmp;
        uint64_t i, orig_num_els = set->number_nodes;
        for (i = orig_num_els; i < num_els; ++i)
            set->nodes[i] = NULL;

        set->number_nodes = num_els;
        // re-layout all nodes
        __relayout_nodes(set, 0, 1);
    }
    // add element in
    int res = __get_index(set, key, hash, &index);
    if (res == SET_FALSE)
    { // this is the first open slot
        __assign_node(set, key, hash, index);
        ++set->used_nodes;
        return SET_TRUE;
    }
    return res;
}
static int __get_index(SimpleSet *set, const char *key, uint64_t hash, uint64_t *index)
{
    size_t len = strlen(key);
    uint64_t i, step;
    uint64_t idx = hash % set->number_nodes;
    
    // Define a secondary hash function
    uint64_t secondary_hash = 1 + (hash % (set->number_nodes - 1));
    
    for (i = 0; i < set->number_nodes; ++i)
    {
        *index = (idx + i * secondary_hash) % set->number_nodes;

        simple_set_node *node = set->nodes[*index];
        if (node == NULL)
        {
            return SET_FALSE; // Not here OR first open slot
        }
        else if (hash == node->_hash && len == strlen(node->_key) && strncmp(key, node->_key, len) == 0)
        {
            return SET_TRUE;
        }
    }
    
    return SET_CIRCULAR_ERROR; // This means we went all the way around and the set is full
}


static int __assign_node(SimpleSet *set, const char *key, uint64_t hash, uint64_t index)
{
    size_t len = strlen(key);
    set->nodes[index] = (simple_set_node *)malloc(sizeof(simple_set_node));
    set->nodes[index]->_key = (char *)calloc(len + 1, sizeof(char));
    memcpy(set->nodes[index]->_key, key, len);
    set->nodes[index]->_hash = hash;
    return SET_TRUE;
}

static void __free_index(SimpleSet *set, uint64_t index)
{
    free(set->nodes[index]->_key);
    free(set->nodes[index]);
    set->nodes[index] = NULL;
}

static void __relayout_nodes(SimpleSet *set, uint64_t start, short end_on_null)
{
    uint64_t index = 0, i;
    for (i = start; i < set->number_nodes; ++i)
    {
        if (set->nodes[i] != NULL)
        {
            index = i;
            if (i != index)
            { // we are moving this node
                __assign_node(set, set->nodes[i]->_key, set->nodes[i]->_hash, index);
                __free_index(set, i);
            }
        }
        else if (end_on_null == 0 && i != start)
        {
            break;
        }
    }
}