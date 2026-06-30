#include "telemetry.h"
#include "pool.h"

#include <stdatomic.h>
#include <stdio.h>

static atomic_uint_fast64_t rx_count = 0;
static atomic_uint_fast64_t discarded_count = 0;
static atomic_uint_fast64_t pool_ring_drop_count = 0;
static atomic_uint_fast64_t arp_count = 0;
static atomic_uint_fast64_t ipv4_count = 0;
static atomic_uint_fast64_t forward_count = 0;
static atomic_uint_fast64_t ttldrop_count = 0;
static atomic_uint_fast64_t checksum_drop_count = 0;
static atomic_uint_fast64_t sendto_fail_count = 0;
static atomic_uint_fast64_t queued_count = 0;
static atomic_uint_fast64_t dequeued_count = 0;
static atomic_uint_fast64_t recorded_pool_used_count = 0;
static atomic_uint_fast64_t ethernet_outgoing_count = 0;
static atomic_uint_fast64_t ethernet_otherhost_count = 0;
static atomic_uint_fast64_t ethernet_broadcast_nonarp_count = 0;
static atomic_uint_fast64_t ethernet_mistmatch_count = 0;

void increase_rx_count() {
	atomic_fetch_add(&rx_count, 1);
}

void increase_discarded_count() {
	atomic_fetch_add(&discarded_count, 1);
}

void increase_pool_ring_full_drop() {
	atomic_fetch_add(&pool_ring_drop_count, 1);
}

void increase_arp_count() {
	atomic_fetch_add(&arp_count, 1);
}

void increase_ipv4_count() {
	atomic_fetch_add(&ipv4_count, 1);
}

void increase_forward_count() {
	atomic_fetch_add(&forward_count, 1);
}

void increase_ttl_drop_count() {
	atomic_fetch_add(&ttldrop_count, 1);
}

void increase_checksum_bad_drop_count() {
	atomic_fetch_add(&checksum_drop_count, 1);
}

void increase_sendto_fail_count() {
	atomic_fetch_add(&sendto_fail_count, 1);
}

void increase_queued_count() {
	atomic_fetch_add(&queued_count, 1);
}

void increase_dequeued_count() {
	atomic_fetch_add(&dequeued_count, 1);
}

void increase_ethernet_outgoing_count() {
	atomic_fetch_add(&ethernet_outgoing_count, 1);
}

void increase_ethernet_otherhost_count() {
	atomic_fetch_add(&ethernet_otherhost_count, 1);
}

void increase_ethernet_broadcast_nonarp_count() {
	atomic_fetch_add(&ethernet_broadcast_nonarp_count, 1);
}

void increase_ethernet_mistmatch_count() {
	atomic_fetch_add(&ethernet_mistmatch_count, 1);
}

void record_pool_cap_count(uint16_t count) {
	atomic_store(&recorded_pool_used_count, count);
}

void print_metrics() {
	uint64_t rx = atomic_load(&rx_count);
	uint64_t discarded = atomic_load(&discarded_count);
	// uint64_t queued = atomic_load(&queued_count);
	// uint64_t dequeued = atomic_load(&dequeued_count);
	uint64_t pool_ring_drop = atomic_load(&pool_ring_drop_count);
	uint64_t ethernet_outgoing = atomic_load(&ethernet_outgoing_count);
	uint64_t ethernet_otherhost = atomic_load(&ethernet_otherhost_count);
	uint64_t ethernet_broadcast_nonarp = atomic_load(&ethernet_broadcast_nonarp_count);
	uint64_t ethernet_mismatch = atomic_load(&ethernet_mistmatch_count);

	uint64_t arp = atomic_load(&arp_count);
	uint64_t ipv4 = atomic_load(&ipv4_count);
	uint64_t forward = atomic_load(&forward_count);
	uint64_t ttldrop = atomic_load(&ttldrop_count);
	uint64_t bad_checksum_drop = atomic_load(&checksum_drop_count);
	uint64_t sendto_fail = atomic_load(&sendto_fail_count);
	uint64_t pool_used_count = atomic_load(&recorded_pool_used_count);

	printf("rx=%lu - discarded=%lu - pool_ring_drop=%lu - pool_cap=%lu%% - eth_outgoing=%lu - eth_othhost=%lu - eth_brd_narp=%lu - eth_mismatch=%lu - arp=%lu - ipv4=%lu - forwarded=%lu - ttl_drop=%lu - bad_cks=%lu - send_fail=%lu\n",
		rx,
		discarded,
		pool_ring_drop,
		// queued,
		// dequeued,
		100 * pool_used_count / AF_PACKET_BUFFER_NUM_PACKETS,
		ethernet_outgoing,
		ethernet_otherhost,
		ethernet_broadcast_nonarp,
		ethernet_mismatch,
		arp,
		ipv4,
		forward,
		ttldrop,
		bad_checksum_drop,
		sendto_fail
	);
}