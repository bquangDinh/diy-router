#include "checksum.h"

#include <net/ethernet.h>
#include <netinet/ip.h>

bool verify_checksum(const uint8_t* packet) {
	struct iphdr *ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));

	uint16_t received_checksum = ntohs(ip_hdr->check);

	uint16_t computed_checksum = compute_ip_checksum(ip_hdr, ip_hdr->ihl * 4);

	return received_checksum == ntohs(computed_checksum);
}

uint16_t compute_ip_checksum(const void *ip_hdr, size_t len) {
    uint32_t sum = 0;
    const uint8_t *data = ip_hdr;

    while (len > 1) {
        uint16_t word = ((uint16_t)data[0] << 8) | data[1];
        sum += word;
        data += 2;
        len -= 2;
    }

    if (len == 1) {
        uint16_t word = ((uint16_t)data[0] << 8);
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return htons((uint16_t)(~sum));
}

uint16_t checksum16(const void *data, size_t len) {
	const uint8_t *bytes = data;
    uint32_t sum = 0;

    while (len > 1) {
        uint16_t word = ((uint16_t)bytes[0] << 8) | bytes[1];
        sum += word;
        bytes += 2;
        len -= 2;
    }

    if (len == 1) {
        uint16_t word = ((uint16_t)bytes[0] << 8);
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return htons((uint16_t)(~sum));
}
