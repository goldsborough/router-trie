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
	// default_gateway_input = rt_create_default_gateway_input(
	// 		rt_convert_string_to_address("2001::1"), 0);

	rt_setup(&rt);
	// rt_default_gateway(&rt, &default_gateway_input);


	address.prefix_length = 32;
	address.interface = 1;
	address.next_hop = rt_convert_string_to_address("::2");
	address.address = rt_convert_string_to_address("dead:beef:ffff::0");
	rt_insert(&rt, &address);

	address.prefix_length = 24;
	address.interface = 2;
	address.next_hop = rt_convert_string_to_address("::3");
	address.address = rt_convert_string_to_address("dead:be00::0");
	rt_insert(&rt, &address);

	address.address = rt_convert_string_to_address("dead:beef::1");

	entry = rt_match(&rt, &address.address);
	printf("%d\n", entry ? entry->interface : 0);

	rt_destroy(&rt);
	return 0;
}
