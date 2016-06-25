#ifndef ROUTER_TRIE_H
#define ROUTER_TRIE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "vector/vector.h"

/****************** DEFINTIIONS ******************/

#define RT_ERROR -1
#define RT_SUCCESS 0

#define RT_IGNORED -1
#define RT_UPDATED 0
#define RT_INSERTED 1

#define RT_INITIALIZER \
	{ NULL, 0 }

#define RT_ARITY 3 /* Bits */

#define RT_UNSPECIFIED_ADDRESS \
	{ 0, 0 }

typedef uint8_t interface_t;
struct in6_addr;
typedef struct in6_addr in6_addr;

/******************* STRUCTURES ******************/

typedef struct Address {
	uint64_t upper;
	uint64_t lower;
} Address;

typedef struct Entry {
	uint8_t prefix_length;
	Address next_hop;
	interface_t interface;
} Entry;

typedef struct RTNode {
	Entry* entry;
	uint8_t bitmap;
	Vector next;
} RTNode;

typedef struct RouterTrie {
	RTNode* root;
	size_t size;
} RouterTrie;

typedef struct Input {
	Address address;
	uint8_t prefix_length;
	Address next_hop;
	interface_t interface;
} Input;

extern uint8_t popcount[256];

/******************* INTERFACE ******************/

/* Constructor / Destructor */
void rt_setup(RouterTrie* router_trie);
void rt_destroy(RouterTrie* router_trie);

/* Utility Constructor */
Input rt_create_default_gateway_input(Address next_hop, interface_t interface);

/* Access */
int rt_default_gateway(RouterTrie* router_trie, const Input* input);
int rt_insert(RouterTrie* router_trie, const Input* input);

const Entry* rt_match(const RouterTrie* router_trie, const Address* address);

/* Utility */
Address rt_convert_string_to_address(const char* address);
char* rt_convert_address_to_string(Address address,
																	 char* buffer,
																	 size_t buffer_size);

in6_addr rt_convert_address_to_in6_addr(Address address);
Address rt_convert_in6_addr_to_address(const struct in6_addr* ip);

/******************* PRIVATE ******************/

#define BIT_SIZE(thing) (sizeof(thing) * 8)
#define MASK_OF_N(N) ((1 << (N)) - 1)
#define SHIFT_COUNT(size, index) (size - index)
#define MSB_MASK_OF_N(N, size) (MASK_OF_N(N) << SHIFT_COUNT(size, N))

#define PREFIX_DISTANCE(prefix_length_in_bits) \
	((prefix_length_in_bits / RT_ARITY) + 1)
#define INDEX_MASK ((uint64_t)MASK_OF_N(RT_ARITY))
#define LAST_INDEX 43 /* ceil(128/3) */
#define MIDDLE_INDEX 21

#define ARITY_INDEX(index) (((index) + 1) * RT_ARITY)
#define ADDRESS_SHIFT(index) \
	(SHIFT_COUNT(BIT_SIZE(uint64_t), ARITY_INDEX((index))))
#define ADDRESS_INDEX_MASK(index) \
	((uint64_t)MASK_OF_N(RT_ARITY)) << ADDRESS_SHIFT(index)
#define GRAB_UPPER_BITS(value, index) \
	((value)&ADDRESS_INDEX_MASK(index)) >> ADDRESS_SHIFT(index)

/* Popcount Masks */
#define POPCOUNT_MASK1 0x55
#define POPCOUNT_MASK2 0x33
#define POPCOUNT_MASK3 0x0F

typedef struct Result {
	RTNode* node;
	int inserted;
	int error;
} Result;

void _rt_setup_popcount();
uint8_t _rt_popcount(uint8_t value);

void _rt_destroy_recursively(RTNode* node);

RTNode* _rt_create_node();
int _rt_create_node_entry(RTNode* node, const Input* input);
void _rt_destroy_node(RTNode* node);

Result _rt_insert(RTNode* node, const Input* input, size_t index);
const Entry* _rt_match(RTNode* node, const Address* address, size_t index);

uint8_t _rt_get_bits(const Address* address, uint8_t index);

RTNode*
_rt_get_next(RTNode* node, const Address* address, uint8_t address_index);
int _rt_set_next(RTNode* node,
								 const Address* address,
								 uint8_t address_index,
								 RTNode* next_node);

uint8_t _rt_bitmap_to_index(RTNode* node, uint8_t index);

bool _rt_next_is_null(RTNode* node, uint8_t index);
void _rt_set_bitmap_value(RTNode* node, uint8_t index, bool value);

void _rt_store_input_in_entry(Entry* entry, const Input* input);

#endif /* ROUTER_TRIE_H */
