#include "interface.h"

#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

static interface_t interfaces[] = {
	{
		.ip = 0x0a000101,
		.mac = { 0xD2, 0x91, 0x6F, 0x71, 0x22, 0x38 },
		.intername_name = (uint8_t*)(ROUTER_IN0_NAME)
	},
	{
		.ip = 0x0a000c01,
		.mac = { 0xFA, 0x0A, 0xA6, 0x34, 0x13, 0x70 },
		.intername_name = (uint8_t*)(ROUTER_IN1_NAME)
	}
};

void init_interface() {
	interfaces[0].sockaddr.sll_family = AF_PACKET;
	interfaces[0].sockaddr.sll_ifindex = if_nametoindex(ROUTER_IN0_NAME);
	interfaces[0].sockaddr.sll_halen = ETH_ALEN;

	interfaces[1].sockaddr.sll_family = AF_PACKET;
	interfaces[1].sockaddr.sll_ifindex = if_nametoindex(ROUTER_IN1_NAME);
	interfaces[1].sockaddr.sll_halen = ETH_ALEN;

#if ENABLE_DEBUGGING
	printf("Interface (%s) is %u | Interface (%s) is %u\n", ROUTER_IN0_NAME, interfaces[0].sockaddr.sll_ifindex, ROUTER_IN1_NAME, interfaces[1].sockaddr.sll_ifindex);
#endif
}

interface_t* get_interface_from_name(const char* name) {
	for (uint8_t i = 0; i < 2; ++i) {
		if (strcmp(name, (char*)interfaces[i].intername_name) == 0) return &interfaces[i];
	}

	return NULL;
}

interface_t* get_interface_from_idx(uint16_t interface_idx) {
	for (uint8_t i = 0; i < 2; ++i) {
		if (interfaces[i].sockaddr.sll_ifindex == interface_idx) return &interfaces[i];
	}

	return NULL;
}