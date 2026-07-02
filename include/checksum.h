#ifndef __CHECKSUM_H_
#define __CHECKSUM_H_

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

bool verify_checksum(const uint8_t* packet);

uint16_t compute_ip_checksum(const void* ip_hdr, size_t len);

uint16_t checksum16(const void *data, size_t len);

#endif