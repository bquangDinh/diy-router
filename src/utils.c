#define _GNU_SOURCE

#include "utils.h"

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <string.h>

uint8_t read_bit_bm(bitmap_t bitmap, uint16_t i) {
	return (bitmap & (1ULL << i));
}

void set_bit_bm(bitmap_t *bitmap, uint16_t i) {
	*(bitmap) |= (1ULL << i);
}

void clear_bit_from_bm(bitmap_t *bitmap, uint16_t i) {
	*(bitmap) &= ~(1ULL << i);
}

void print_mac_addr(const uint8_t* mac) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

void print_ppkt_info(const ppacket_t* ppkt) {
	const struct ether_header* eth_hdr = (struct ether_header*)ppkt->packet;

	printf("Received a packet with len = %u at inteface = %u | shost: ", ppkt->len, ppkt->recv_interface_idx);

	print_mac_addr(eth_hdr->ether_shost);

	printf(" | dhost: ");

	print_mac_addr(eth_hdr->ether_dhost);

	printf(" | ether_type = 0x%04x\n", ntohs(eth_hdr->ether_type));
}

void print_icmp_packet_info(const uint8_t* packet) {
	const struct iphdr *ip =
        (const struct iphdr *)(packet + sizeof(struct ether_header));

    const struct icmphdr *icmp =
        (const struct icmphdr *)(
            packet +
            sizeof(struct ether_header) +
            ip->ihl * 4);

    printf("ICMP seq: %u\n",
           ntohs(icmp->un.echo.sequence));
}

void print_tcp_packet_info(const uint8_t* packet) {
	const struct iphdr *ip_hdr =
        (const struct iphdr *)(packet + sizeof(struct ether_header));

	struct tcphdr *tcp_hdr = (struct tcphdr *)((uint8_t *)ip_hdr + ip_hdr->ihl * 4);

	printf("TCP checksum: 0x%04x\n", ntohs(tcp_hdr->check));
}

void swap(void* a, void* b, size_t size) {
	unsigned char temp[size];

	memcpy(temp, a, size);
	memcpy(a, b, size);
	memcpy(b, temp, size);
}