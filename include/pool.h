#ifndef __POOL_H_
#define __POOL_H_

#include "queue.h"
#include "utils.h"

#ifndef AF_PACKET_BUFFER_NUM_PACKETS
#define AF_PACKET_BUFFER_NUM_PACKETS 35
#endif

void init_packet_pool();

ppacket_t* packet_pool_alloc();

void free_packet(ppacket_t* ppkt);

void lock_plk(ppacket_t* ppkt);

void unlock_plk(ppacket_t* ppkt);

#endif