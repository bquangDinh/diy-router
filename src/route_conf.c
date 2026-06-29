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

void init_route_config() {
	// TODO: read config from file
	return;
}

route_t* route_table_lookup(const uint32_t dest_ip) {
	route_t* route = NULL;

	for (size_t i = 0; i < route_entries_count; ++i) {
		route = &routing_table[i];

		if ((dest_ip & route->mask) == route->net) {
			return route;
		}
	}

	return NULL;
}