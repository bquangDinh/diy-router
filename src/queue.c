#include "queue.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static packet_node_t* create_packet_node(const ppacket_t* ppkt);

void init_queue(packet_queue_t* queue, int cap) {
	queue->cap = cap;
	queue->counts = 0;
	queue->head = NULL;
	queue->tail = NULL;

	// sem_init(&queue->rx_sem, 0, 0);

	pthread_cond_init(&queue->not_full, NULL);

	pthread_cond_init(&queue->not_empty, NULL);

	pthread_mutex_init(&queue->qlock, NULL);
}

void enqueue(packet_queue_t* queue, const ppacket_t* ppkt) {
	pthread_mutex_lock(&queue->qlock);

	if (queue->cap > 0) {
		while (queue->counts == queue->cap) {
			printf("Queue is full!\n");

			// Queue is at capacity
			// Signal the thread to wait until the queue has space
			pthread_cond_wait(&queue->not_full, &queue->qlock);
		}
	}

	packet_node_t* node = create_packet_node(ppkt);

	node->previous = queue->tail;

	if (queue->tail != NULL) {
		queue->tail->next = node;
	} else {
		// Empty queue
		queue->head = node;
	}

	queue->tail = node;

	queue->counts++;

#if ENABLE_DEBUGGING
	printf("Queue counts = %d\n", queue->counts);
#endif

	// Signal the consumer that the queue is not empty
	pthread_cond_signal(&queue->not_empty);

	pthread_mutex_unlock(&queue->qlock);
}

ppacket_t* dequeue(packet_queue_t* queue) {
	pthread_mutex_lock(&queue->qlock);

	while (queue->counts == 0) {
		// Queue is empty
		// Wait until the queue is not empty
		pthread_cond_wait(&queue->not_empty, &queue->qlock);
	}

	// if (queue->head == NULL) {
	// 	pthread_mutex_unlock(&queue->qlock);

	// 	return NULL;
	// }

	packet_node_t* node = queue->head;

	queue->head = node->next;

	if (queue->head != NULL) {
		queue->head->previous = NULL;
	} else {
		// Queue is now empty
		queue->tail = NULL;
	}

	ppacket_t* ppkt = node->ppkt;

	free(node);

	queue->counts--;

	// Signal the producer that the queue has been consumed, thus no longer full
	// So the producer can start putting items into the queue
	pthread_cond_signal(&queue->not_full);

	pthread_mutex_unlock(&queue->qlock);

	return ppkt;
}

static packet_node_t* create_packet_node(const ppacket_t* ppkt) {
	packet_node_t* node = (packet_node_t*)malloc(sizeof(packet_node_t));

	node->ppkt = ppkt;
	node->next = NULL;
	node->previous = NULL;

	return node;
}