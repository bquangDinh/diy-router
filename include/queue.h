#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stdint.h>
#include <semaphore.h>
#include <pthread.h>

typedef struct ppacket {
	uint8_t packet[1600];
	uint16_t len;
	uint8_t recv_interface_idx;
	uint8_t out_interface_idx;
	unsigned char pkttype;
} ppacket_t;

typedef struct packet_node {
	ppacket_t* ppkt;
	struct packet_node *next;
	struct packet_node *previous;
} packet_node_t;

typedef struct packet_queue {
	int cap; // if cap == 0, then queue is unlimited
	int counts;
	packet_node_t* head;
	packet_node_t* tail;

	// sem_t rx_sem;
	pthread_cond_t not_full;
	pthread_cond_t not_empty;
	pthread_mutex_t qlock;
} packet_queue_t;

void init_queue(packet_queue_t* queue, int cap);

void enqueue(packet_queue_t* queue, const ppacket_t* ppkt);

ppacket_t* dequeue(packet_queue_t* queue);

#endif