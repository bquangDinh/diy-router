#ifndef __VLAN_H_
#define __VLAN_H_

#include "queue.h"

int handle_vlan_packet(const ppacket_t* ppkt, int socket);

#endif