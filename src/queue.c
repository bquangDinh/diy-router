#include "queue.h"

#include <stdlib.h>
#include <string.h>

static packet_node_t* create_packet_node(const ppacket_t* ppkt);

void init_queue(packet_queue_t* queue) {
	queue->counts = 0;
	queue->head = NULL;
	queue->tail = NULL;

	sem_init(&queue->rx_sem, 0, 0);

	pthread_mutex_init(&queue->qlock, NULL);
}

void enqueue(packet_queue_t* queue, const ppacket_t* ppkt) {
	pthread_mutex_lock(&queue->qlock);

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

	pthread_mutex_unlock(&queue->qlock);
}

ppacket_t* dequeue(packet_queue_t* queue) {
	pthread_mutex_lock(&queue->qlock);

	if (queue->head == NULL) {
		pthread_mutex_unlock(&queue->qlock);

		return NULL;
	}

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