#ifndef __ETHERNET_H_
#define __ETHERNET_H_

#include <net/ethernet.h>

#include <stdint.h>
#include <stdbool.h>

#include "queue.h"

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_IPV6 0x86DD
#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_VLAN 0x8100

bool should_process_frame(const ppacket_t* ppkt);

uint16_t get_eth_type(const uint8_t* packet);

#endif