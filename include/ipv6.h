#ifndef __IPV6_H_
#define __IPV6_H_

#include "queue.h"

int handle_ipv6_packet(const ppacket_t* ppkt, int socket);

#endif