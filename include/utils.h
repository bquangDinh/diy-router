#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdint.h>
#include "queue.h"

#define BM_NUM_BLKS 1024
#define BITMAP_SIZE ((BM_NUM_BLKS + 7) / 8)

typedef unsigned char bitmap_t[BITMAP_SIZE];

/**
 * Bitmap Operations
 */
uint8_t read_bit_bm(const bitmap_t bitmap, uint16_t i);
void set_bit_bm(bitmap_t bitmap, uint16_t i);
void clear_bit_from_bm(bitmap_t bitmap, uint16_t i);

/**
 * Debugging
 */
void print_mac_addr(const uint8_t* mac);

void print_ppkt_info(const ppacket_t* ppkt);

void print_tcp_packet_info(const uint8_t* packet);

void print_icmp_packet_info(const uint8_t* packet);

/**
 * Others
 */
void swap(void* a, void* b, size_t size);
#endif
