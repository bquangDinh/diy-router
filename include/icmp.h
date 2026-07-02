#ifndef __ICMP_H_
#define __ICMP_H_

#include <netinet/ip_icmp.h>
#include <stdint.h>

#include "queue.h"

int send_icmp_time_exceed(const ppacket_t* ppkt, const int socket);

int send_icmp_net_unreachable(const ppacket_t* ppkt, const int socket);

int send_icmp_host_unreachable(const ppacket_t* ppkt, const int socket);

// int send_icmp_frag_needed(const ppacket_t* ppkt, uint16_t mtu, const int socket);

// int send_icmp_redirect(const ppacket_t* ppkt, uint32_t gateway_ip, int socket);
#endif