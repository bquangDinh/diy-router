#include "pool.h"
#include "utils.h"
#include "telemetry.h"

#include <stdio.h>

static ppacket_t pool[AF_PACKET_BUFFER_NUM_PACKETS];

static bitmap_t packet_pool_bm = 0;

static pthread_mutex_t bm_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_cond_t pool_not_full = PTHREAD_COND_INITIALIZER;

static pthread_mutex_t pktpl_locks[AF_PACKET_BUFFER_NUM_PACKETS];

static uint16_t get_pkblk_pos_from_addr(ppacket_t* pkt);

static ppacket_t* get_pkt_from_pos(uint16_t pos);

void init_packet_pool() {
	for (uint16_t i = 0; i < AF_PACKET_BUFFER_NUM_PACKETS; ++i) {
		pthread_mutex_init(&pktpl_locks[i], NULL);
	}
}

ppacket_t* packet_pool_alloc() {
	// Lock bitmap
	pthread_mutex_lock(&bm_lock);

	while (1) {
		int used = 0;

		for (uint16_t i = 0; i < AF_PACKET_BUFFER_NUM_PACKETS; ++i) {
			if (read_bit_bm(packet_pool_bm, i) == 0) {
				set_bit_bm(&packet_pool_bm, i);

				pthread_mutex_unlock(&bm_lock);

				record_pool_cap_count(used);

				return get_pkt_from_pos(i);
			} else {
				used++;
			}
		}

		record_pool_cap_count(used);

		printf("Pool is full!\n");

		// Pool is full. Wait until it is not full
		pthread_cond_wait(&pool_not_full, &bm_lock);
	}

	// No available slot left
	pthread_mutex_unlock(&bm_lock);

	return NULL;
}

void free_packet(ppacket_t* ppkt) {
	uint16_t pos = get_pkblk_pos_from_addr(ppkt);

	pthread_mutex_lock(&bm_lock);

	clear_bit_from_bm(&packet_pool_bm, pos);

	// Signal the pool that it is not full
	pthread_cond_signal(&pool_not_full);

	pthread_mutex_unlock(&bm_lock);
}

void lock_plk(ppacket_t* ppkt) {
	pthread_mutex_lock(&pktpl_locks[get_pkblk_pos_from_addr(ppkt)]);
}

void unlock_plk(ppacket_t* ppkt) {
	pthread_mutex_unlock(&pktpl_locks[get_pkblk_pos_from_addr(ppkt)]);
}

static uint16_t get_pkblk_pos_from_addr(ppacket_t* pkt) {
	// pool is the base address of the pool array
	return pkt - pool;
}

static ppacket_t* get_pkt_from_pos(uint16_t pos) {
	return &pool[pos];
}