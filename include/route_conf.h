#ifndef __ROUTE_CONF_H_
#define __ROUTE_CONF_H_

#include <stdint.h>

typedef struct route {
	uint32_t net;
	uint32_t mask;
	uint32_t next_hop;
	uint8_t* interface_name;
} route_t;

void init_route_config();

route_t* route_table_lookup(const uint32_t dest_ip);

#endif