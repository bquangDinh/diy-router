#ifndef __INTERFACE_H_
#define __INTERFACE_H_

#include <stdint.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define ROUTER_IN0_NAME "r1-eth0"
#define ROUTER_IN1_NAME "r1-eth1"

typedef struct interface {
	uint8_t mac[ETH_ALEN];
	uint32_t ip;
	struct sockaddr_ll sockaddr;
	uint8_t* intername_name;
} interface_t;

void init_interface();

interface_t* get_interface_from_name(const char* name);

interface_t* get_interface_from_idx(uint16_t interface_idx);
#endif