#ifndef __TELEMETRY_H_
#define __TELEMETRY_H_

#include <stdint.h>

void increase_rx_count();

void increase_discarded_count();

void increase_pool_ring_full_drop();

void increase_arp_count();

void increase_ipv4_count();

void increase_forward_count();

void increase_ttl_drop_count();

void increase_checksum_bad_drop_count();

void increase_sendto_fail_count();

void increase_queued_count();

void increase_dequeued_count();

void increase_ethernet_outgoing_count();

void increase_ethernet_otherhost_count();

void increase_ethernet_broadcast_nonarp_count();

void increase_ethernet_mistmatch_count();

void record_pool_cap_count(uint16_t count);

void print_metrics();

#endif