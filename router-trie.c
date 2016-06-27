#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdio.h>

#include "router-trie.h"

uint8_t popcount[256];

/******************* INTERFACE ******************/

void rt_setup(RouterTrie* router_trie) {
	assert(router_trie != NULL);

	router_trie->root = _rt_create_node();
	router_trie->size = 0;

	/* Popcount of 1 should be 1, so we know when to initialize. */
	if (popcount[1] == 0) {
		_rt_setup_popcount();
	}
}

void rt_destroy(RouterTrie* router_trie) {
	_rt_destroy_recursively(router_trie->root);
}

/* Utility Constructor */
Input rt_create_default_gateway_input(Address next_hop, interface_t interface) {
	Input input;

	input.address.upper = input.address.lower = 0;
	input.prefix_length = 0;
	input.next_hop = next_hop;
	input.interface = interface;

	return input;
}

/* Access */
int rt_default_gateway(RouterTrie* router_trie, Input* input) {
	assert(router_trie != NULL);
	assert(input != NULL);

	_rt_sanitize(input);

	if (router_trie->root->entry == NULL) {
		if (_rt_create_node_entry(router_trie->root, input) == RT_ERROR) {
			return RT_ERROR;
		}
		++router_trie->size;
	} else {
		_rt_store_input_in_entry(router_trie->root->entry, input);
	}

	return RT_SUCCESS;
}

int rt_insert(RouterTrie* router_trie, Input* input) {
	Result result;
	assert(router_trie != NULL);
	assert(input != NULL);

	_rt_sanitize(input);

	if (_rt_is_default_gateway(input)) {
		return rt_default_gateway(router_trie, input);
	}

	result = _rt_insert(router_trie->root, input, 0);

	if (result.error) return RT_ERROR;
	if (result.inserted) router_trie->size++;

	return RT_SUCCESS;
}

const Entry* rt_match(const RouterTrie* router_trie, const Address* address) {
	assert(router_trie->root != NULL);
	assert(address != NULL);

	return _rt_match(router_trie->root, address, 0);
}

/* Utility */
Address rt_convert_string_to_address(const char* address) {
	in6_addr bytes;
	if (inet_pton(AF_INET6, address, &bytes) != 1) {
		fprintf(stderr, "Could not convert string to IP address\n");
		exit(-1);
	}

	return rt_convert_in6_addr_to_address(&bytes);
}

char* rt_convert_address_to_string(Address address,
																	 char* buffer,
																	 size_t buffer_size) {
	in6_addr bytes = rt_convert_address_to_in6_addr(address);

	if (inet_ntop(AF_INET6, &bytes, buffer, buffer_size) == NULL) {
		perror("Could not convert IP address to string");
		exit(-1);
	}

	return buffer;
}

in6_addr rt_convert_address_to_in6_addr(Address address) {
	in6_addr bytes;
	int byte;

	for (byte = 15; byte >= 8; --byte) {
		bytes.s6_addr[byte] = address.lower & 0xff;
		address.lower >>= 8;
	}

	for (byte = 7; byte >= 0; --byte) {
		bytes.s6_addr[byte] = address.upper & 0xff;
		address.upper >>= 8;
	}

	return bytes;
}

Address rt_convert_in6_addr_to_address(const struct in6_addr* ip) {
	Address address = {0, 0};
	size_t byte;

	assert(ip != NULL);

	for (byte = 0; byte < 8; ++byte) {
		address.lower |= ((uint64_t)ip->s6_addr[15 - byte]) << (byte * 8);
	}

	for (byte = 0; byte < 8; ++byte) {
		address.upper |= ((uint64_t)ip->s6_addr[7 - byte]) << (byte * 8);
	}

	return address;
}

/******************* PRIVATE ******************/

void _rt_sanitize(Input* input) {
	// Make sure we only insert the network address
	if (input->prefix_length > 64 && input->prefix_length < 128) {
		input->address.lower &= MSB_MASK_OF_N(input->prefix_length - 64, 64);
	} else if (input->prefix_length < 64) {
		input->address.upper &= MSB_MASK_OF_N(input->prefix_length, 64);
		input->address.lower = 0;
	}
}

bool _rt_is_default_gateway(Input* input) {
	return input->address.upper == 0 && input->address.lower == 0;
}

void _rt_setup_popcount() {
	size_t value;
	for (value = 0; value < 256; ++value) {
		popcount[value] = _rt_popcount(value);
	}
}

uint8_t _rt_popcount(uint8_t value) {
	value = (value & POPCOUNT_MASK1) + ((value >> 1) & POPCOUNT_MASK1);
	value = (value & POPCOUNT_MASK2) + ((value >> 2) & POPCOUNT_MASK2);
	value = (value & POPCOUNT_MASK3) + ((value >> 4) & POPCOUNT_MASK3);

	return value;
}

void _rt_destroy_recursively(RTNode* node) {
	Iterator iterator = vector_begin(&node->next);
	Iterator end = vector_end(&node->next);
	assert(node != NULL);
	for (; !iterator_equals(&iterator, &end); iterator_increment(&iterator)) {
		_rt_destroy_recursively(ITERATOR_GET_AS(RTNode*, &iterator));
	}
	_rt_destroy_node(node);
}

RTNode* _rt_create_node() {
	RTNode* node;

	if ((node = malloc(sizeof *node)) == NULL) {
		return NULL;
	}

	node->entry = NULL;
	node->bitmap = 0;
	if (vector_setup(&node->next, 0, sizeof(RTNode*)) == VECTOR_ERROR) {
		return NULL;
	}

	return node;
}

int _rt_create_node_entry(RTNode* node, const Input* input) {
	assert(node != NULL);
	assert(input != NULL);

	if ((node->entry = malloc(sizeof *node->entry)) == NULL) {
		return RT_ERROR;
	}

	_rt_store_input_in_entry(node->entry, input);

	return RT_SUCCESS;
}

void _rt_destroy_node(RTNode* node) {
	assert(node != NULL);

	free(node->entry);
	vector_destroy(&node->next);

	free(node);
}

Result _rt_insert(RTNode* node, const Input* input, size_t index) {
	RTNode* next;
	Result result = {NULL, RT_IGNORED, RT_SUCCESS};

	if (node == NULL) {
		if ((node = _rt_create_node()) == NULL) {
			result.error = RT_ERROR;
			return result;
		}
	}

	if (index == PREFIX_DISTANCE(input->prefix_length)) {
		if (node->entry != NULL) {
			if (input->prefix_length > node->entry->prefix_length) {
				_rt_store_input_in_entry(node->entry, input);
				result.inserted = RT_UPDATED;
			}
		} else if (_rt_create_node_entry(node, input) == RT_ERROR) {
			result.error = RT_ERROR;
		} else {
			result.inserted = RT_INSERTED;
		}
	} else {
		next = _rt_get_next(node, &input->address, index);
		result = _rt_insert(next, input, index + 1);

		if (result.error == RT_ERROR) return result;
		_rt_set_next(node, &input->address, index, result.node);
	}

	result.node = node;
	return result;
}

const Entry* _rt_match(RTNode* node, const Address* address, size_t index) {
	RTNode* next;
	const Entry* entry;

	if (node == NULL) {
		return NULL;
	}
	next = _rt_get_next(node, address, index);
	entry = _rt_match(next, address, index + 1);

	return entry ? entry : node->entry;
}

uint8_t _rt_get_bits(const Address* address, uint8_t index) {
	assert(address != NULL);

	if (index < MIDDLE_INDEX) {
		return GRAB_UPPER_BITS(address->upper, index);
	} else if (index < LAST_INDEX) {
		return GRAB_UPPER_BITS(address->lower, index - MIDDLE_INDEX);
	} else {
		return (address->lower & MASK_OF_N(2)) << 1;
	}
}

RTNode*
_rt_get_next(RTNode* node, const Address* address, uint8_t address_index) {
	uint8_t next_index;
	uint8_t address_bits;

	assert(node != NULL);

	address_bits = _rt_get_bits(address, address_index);
	if (_rt_next_is_null(node, address_bits)) return NULL;

	next_index = _rt_bitmap_to_index(node, address_bits);

	return VECTOR_GET_AS(RTNode*, &node->next, next_index);
}

int _rt_set_next(RTNode* node,
								 const Address* address,
								 uint8_t address_index,
								 RTNode* next_node) {
	uint8_t next_index;
	uint8_t address_bits;

	assert(node != NULL);

	address_bits = _rt_get_bits(address, address_index);
	next_index = _rt_bitmap_to_index(node, address_bits);

	// printf(
	// 		"Inserting %d at %d on level %d for %llx w bitmap %d at popcount of %d,
	// "
	// 		"which is %d\n",
	// 		address_bits,
	// 		next_index,
	// 		address_index,
	// 		address->upper,
	// 		node->bitmap,
	// 		node->bitmap & MSB_MASK_OF_N(address_bits, 8),
	// 		popcount[popcount[node->bitmap & MSB_MASK_OF_N(address_bits, 8)]]);

	if (_rt_next_is_null(node, address_bits)) {
		if (next_node != NULL) {
			if (vector_insert(&node->next, next_index, &next_node) == VECTOR_ERROR) {
				assert(false);
				return RT_ERROR;
			}
		}
	} else {
		if (next_node != NULL) {
			if (vector_assign(&node->next, next_index, &next_node) == VECTOR_ERROR) {
				assert(false);
				return RT_ERROR;
			}
		} else {
			if (vector_erase(&node->next, next_index) == VECTOR_ERROR) {
				assert(false);
				return RT_ERROR;
			}
		}
	}

	_rt_set_bitmap_value(node, address_bits, next_node != NULL);

	return RT_SUCCESS;
}

void _rt_set_bitmap_value(RTNode* node, uint8_t index, bool value) {
	node->bitmap &= ~REVERSE_INDEX(7, index);
	node->bitmap |= (value << SHIFT_COUNT(7, index));
}

uint8_t _rt_bitmap_to_index(RTNode* node, uint8_t index) {
	return popcount[node->bitmap & MSB_MASK_OF_N(index, 8)];
}

bool _rt_next_is_null(RTNode* node, uint8_t index) {
	return (node->bitmap & REVERSE_INDEX(7, index)) == 0;
}

void _rt_store_input_in_entry(Entry* entry, const Input* input) {
	entry->prefix_length = input->prefix_length;
	entry->next_hop = input->next_hop;
	entry->interface = input->interface;
}
