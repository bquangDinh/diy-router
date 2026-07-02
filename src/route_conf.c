#include "route_conf.h"
#include "interface.h"
#include <stddef.h>

static size_t route_entries_count = 3;

static route_t routing_table[] = {
	{
		.net	    = 0x0a000100,
		.mask	    = 0xffffff00,
		.next_hop = 0, // directed conncted
		.interface_name = ROUTER_IN0_NAME
	},
	{
		.net		= 0x0a000c01,
		.mask		= 0xffffff00,
		.next_hop	= 0,
		.interface_name = ROUTER_IN1_NAME
	},
	{
		.net		= 0x0a000200,
		.mask		= 0xffffff00,
		.next_hop	= 0x0a000c02,
		.interface_name = ROUTER_IN1_NAME
	}
};

/**
 * Returns the number of 1s in the mask. Ex: if mask is 11111 000000 ... then returns 5
 */
static int prefix_len(uint32_t mask);

void init_route_config() {
	// TODO: read config from file
	return;
}

route_t* route_table_lookup(const uint32_t dest_ip) {
	route_t* best_route = NULL;
	int best_prefix = -1;
	route_t *r = NULL;

	for (size_t i = 0; i < route_entries_count; ++i) {
		r = &routing_table[i];

		if ((dest_ip & r->mask) == r->net) {
			int pfx_len = prefix_len(r->mask);

			if (pfx_len > best_prefix) {
				best_prefix = pfx_len;
				best_route = r;
			}

		}
	}

	return best_route;
}

static int prefix_len(uint32_t mask) {
	int len = 0;

	// 0x80000000 is the number 1, then follow by 31 zeros
	// 1 00000 ... 00000
	while (mask & 0x80000000) {
		len++;
		mask <<= 1;
	}

	return len;
}