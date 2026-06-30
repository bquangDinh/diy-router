#ifndef __RING_BUFFER_H_
#define __RING_BUFFER_H_

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "queue.h"

typedef struct {
    ppacket_t **slots;
	uint16_t _size;
    atomic_uint head; // consumer reads from head
    atomic_uint tail; // producer writes to tail
} rx_ring_t;

rx_ring_t* create_ring_buffer(uint16_t size);

bool rx_ring_enqueue(rx_ring_t* r, ppacket_t* ppkt);

ppacket_t* rx_ring_dequeue(rx_ring_t* r);
#endif