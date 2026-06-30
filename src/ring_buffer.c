#include "ring_buffer.h"

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

rx_ring_t* create_ring_buffer(uint16_t size) {
	rx_ring_t* ring = (rx_ring_t*)malloc(sizeof(rx_ring_t));

	if (ring == NULL) return NULL;

	ppacket_t** buffer = (ppacket_t**)malloc(size * sizeof(ppacket_t*));

	ring->slots = calloc(size, sizeof(ppacket_t*));

	if (ring->slots == NULL) {
		free(ring);

		return NULL;
	}

	ring->_size = size;
	atomic_init(&ring->head, 0);
	atomic_init(&ring->tail, 0);

	return ring;
}

bool rx_ring_enqueue(rx_ring_t* r, ppacket_t* ppkt) {
	unsigned tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
	unsigned head = atomic_load_explicit(&r->head, memory_order_acquire);
	uint16_t ring_mask = r->_size - 1;

	if ((tail - head) == r->_size) {
		return false;
	}

	r->slots[tail & ring_mask] = ppkt;

	atomic_store_explicit(&r->tail, tail + 1, memory_order_release);

	return true;
}

ppacket_t* rx_ring_dequeue(rx_ring_t* r) {
	unsigned tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
	unsigned head = atomic_load_explicit(&r->head, memory_order_acquire);
	uint16_t ring_mask = r->_size - 1;

	if (head == tail) {
		return NULL; // empty
	}

	ppacket_t *pkt = r->slots[head & ring_mask];

    atomic_store_explicit(&r->head, head + 1, memory_order_release);

	return pkt;
}