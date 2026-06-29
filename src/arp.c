#include "arp.h"
#include "utils.h"
#include "ethernet.h"
#include "checksum.h"

#include <arpa/inet.h>
#include <netinet/ip.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

static arp_entry_t arp_cache_table[ARP_CACHE_SIZE] = {
	{
		.ip = 0x0a000102,
		.mac = { 0x5E, 0x57, 0x78, 0x6D, 0xED, 0x99 },
		.state = ARP_RESOLVED,
		.valid = true
	},
	{
		.ip = 0x0a000202,
		.mac = { 0xE6, 0x4A, 0xF5, 0x66, 0x58, 0x7F },
		.state = ARP_RESOLVED,
		.valid = true,
	},
	{
		.ip = 0x0a000c02,
		.mac = { 0XA2, 0xC6, 0x68, 0x5B, 0x4A, 0x1A },
		.state = ARP_RESOLVED,
		.valid = true
	}
};

static void flush_pending_packets(arp_entry_t* arp_entry, int socket);

int handle_arp_packet(ppacket_t* ppkt, int socket) {
	struct arp_packet *arp_pkt = (struct arp_packet*)(ppkt->packet + sizeof(struct ether_header));

	uint32_t src_ip = ntohl(arp_pkt->spa);

	// Check if this is an ARP request or reply
	uint8_t op = ntohs(arp_pkt->oper);

	if (op == 2) {
		arp_entry_t* arp_entry = get_arp_entry(src_ip);

		// Forgot to create an arp entry when first send ARP request
		assert(arp_entry != NULL);

		memcpy(arp_entry->mac, arp_pkt->sha, ETH_ALEN);

		flush_pending_packets(arp_entry, socket);

		arp_entry->state = ARP_RESOLVED;
	} else if (op == 1) {
		send_arp_response(ppkt, socket);
	} else {
		printf("Not supported ARP operation (op = %d)\n", op);

		return -1;
	}

	return 0;
}

arp_entry_t* alloc_arp_entry(const uint32_t ip, arp_state_t init_state) {
	// Find the first invalid entry
	for (uint16_t i = 0; i < ARP_CACHE_SIZE; ++i) {
		if (arp_cache_table[i].valid == 0) {
			arp_cache_table[i].ip = ip;
			arp_cache_table[i].state = init_state;
			arp_cache_table[i].valid = 1;

			return &arp_cache_table[i];
		}
	}

	// TODO: evict ARP entry, clear its queue, etc
	return NULL;
}

int send_arp_request(const uint32_t target_ip, interface_t* out_interace, int socket) {
	size_t len = sizeof(struct ether_header) + sizeof(struct arp_packet);

	uint8_t arp_req_packet[len];

	struct ether_header* eth_hdr = (struct ether_header*)arp_req_packet;
	struct arp_packet* arp = (struct arp_packet*)(arp_req_packet + sizeof(struct ether_header));

	// Make destination MAC broadcast
	// Make source MAC to be the outgoing interface's MAC
	for (uint8_t i = 0; i < ETH_ALEN; ++i) {
		eth_hdr->ether_dhost[i] = 0xFF;
		eth_hdr->ether_shost[i] = out_interace->mac[i];

		arp->sha[i] = out_interace->mac[i];
		arp->tha[i] = 0;
	}

	eth_hdr->ether_type = htons(ETHER_TYPE_ARP);

	arp->htype = htons(1); // Ethernet
	arp->ptype = htons(ETHER_TYPE_IPV4);
	arp->hlen = 6; // MAC addr length
	arp->plen = 4; // ipv4 addr length
	arp->oper = htons(1); // ARP request
	arp->spa = htonl(out_interace->ip);
	arp->tpa = htonl(target_ip);

	struct sockaddr_ll* send_addr = &out_interace->sockaddr;

	memcpy(send_addr->sll_addr, eth_hdr->ether_dhost, ETH_ALEN);

	ssize_t sent = sendto(socket, arp_req_packet, len, 0, (struct sockaddr*)send_addr, sizeof(*(send_addr)));

	if (sent < 0) {
		perror("sendto");

		return -1;
	}

	return 0;
}

int send_arp_response(ppacket_t* arp_ppkt, int socket) {
	uint8_t* packet = arp_ppkt->packet;

	struct ether_header *eth_hdr = (struct ether_header*)packet;
	struct arp_packet *arp = (struct arp_packet*)(packet + sizeof(struct arp_packet));

	interface_t* out_interface = get_interface_from_idx(arp_ppkt->recv_interface_idx);

	for (uint8_t i = 0; i < ETH_ALEN; ++i) {
		eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];

		arp->tha[i] = arp->sha[i];
		arp->sha[i] = out_interface->mac[i];
	}

	arp->oper = htons(2); // reply

	// Swap source IP and destination IP
	swap(&arp->spa, &arp->tpa, sizeof(uint32_t));

	memcpy(out_interface->sockaddr.sll_addr, eth_hdr->ether_dhost, ETH_ALEN);

	ssize_t sent = sendto(socket, packet, arp_ppkt->len, 0, (struct sockaddr*)&out_interface->sockaddr, sizeof(out_interface->sockaddr));

	if (sent < 0) {
		perror("sendto");

		return -1;
	}

	return 0;
}

arp_entry_t* get_arp_entry(const uint32_t ip) {
	for (uint16_t i = 0; i < ARP_CACHE_SIZE; ++i) {
		if (arp_cache_table[i].ip == ip) {
			return &arp_cache_table[i];
		}
	}

	return NULL;
}

void init_arp_packet_queue(arp_entry_t* arp_entry) {
	arp_entry->queue = (packet_queue_t*)malloc(sizeof(packet_queue_t));

	arp_entry->queue->counts = 0;
	arp_entry->queue->head = NULL;
	arp_entry->queue->tail = NULL;

	// If the ARP queue is being used in a multi-threaded context
	// Then init queue semaphore and mutex
}

void add_packet_to_arp_queue(arp_entry_t* arp_entry, const ppacket_t* ppkt) {
	ppacket_t* clone = (ppacket_t*)malloc(sizeof(ppacket_t));

	memcpy(clone, ppkt, sizeof(ppacket_t));

	enqueue(arp_entry->queue, clone);
}

static void flush_pending_packets(arp_entry_t* arp_entry, int socket) {
	ppacket_t* ppkt = NULL;
	struct ether_header *eth_hdr = NULL;
	struct iphdr *ip_hdr = NULL;
	uint8_t* packet = NULL;
	interface_t* out_interface = NULL;

#if ENABLE_DEBUGGING
	printf("Flushing ARP queue (%d pending)\n", arp_entry->queue->counts);
#endif

	while ((ppkt = dequeue(arp_entry->queue)) != NULL) {
		packet = ppkt->packet;

		out_interface = get_interface_from_idx(ppkt->out_interface_idx);

		assert(out_interface != NULL);

		// Assume it is a ipv4 packet
		eth_hdr = (struct ether_header*)packet;

		ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));

		ip_hdr->ttl--;

		ip_hdr->check = 0;

		ip_hdr->check = compute_ip_checksum(ip_hdr, ip_hdr->ihl * 4);

#if ENABLE_DEBUGGING
		printf("Flushing packet with ip 0x%08x\n", ip_hdr->saddr);

		print_tcp_packet_info(packet);

		printf("Computed checksum is: 0x%04x\n", ntohs(ip_hdr->check));
#endif

		memcpy(eth_hdr->ether_shost, out_interface->mac, ETH_ALEN);

		memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETH_ALEN);

		memcpy(out_interface->sockaddr.sll_addr, arp_entry->mac, ETH_ALEN);

		ssize_t sent = sendto(socket, packet, ppkt->len, 0, (struct sockaddr*)&out_interface->sockaddr, sizeof((out_interface->sockaddr)));

		if (sent < 0) {
			perror("sendto");
		}

#if ENABLE_DEBUGGING
		printf("Sent to interface %u\n", out_interface->sockaddr.sll_ifindex);
#endif

		// Make sure to free packet
		free(ppkt);

		ppkt = NULL;
	}
}