#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>

#include "router-trie.h"

int main(int argc, char const* argv[]) {
	Input default_gateway_input;
	Input address;
	const Entry* entry;

	RouterTrie rt;
	default_gateway_input = rt_create_default_gateway_input(
			rt_convert_string_to_address("2001::1"), 0);

	address.address = rt_convert_string_to_address("b001:48:db8::1");
	address.interface = 1;
	address.next_hop = rt_convert_string_to_address("123:456::0");
	address.prefix_length = 2;

	char buffer[200];
	rt_convert_address_to_string(address.address, buffer, sizeof buffer);
	printf("%s\n", buffer);

	rt_setup(&rt);

	rt_default_gateway(&rt, &default_gateway_input);

	for (int i = 1; i < 100; ++i) {
		address.address.upper++;
		address.interface = i;
		rt_insert(&rt, &address);
	}

	address.address.upper = 0xb001480000000000;
	address.address.lower = 4526563456;

	entry = rt_match(&rt, &address.address);
	printf("%d\n", entry->prefix_length);

	rt_destroy(&rt);
	return 0;
}
