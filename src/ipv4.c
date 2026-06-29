#include "ipv4.h"
#include "route_conf.h"
#include "arp.h"
#include "interface.h"
#include "utils.h"
#include "checksum.h"

#include <netinet/ip.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

int handle_ipv4_packet(ppacket_t* ppkt, int socket) {
	uint8_t* packet = ppkt->packet;
	const uint16_t len = ppkt->len;
	// const uint16_t recv_interface = ppkt->recv_interface_idx;

	struct ether_header* eth_hdr = (struct ether_header*)packet;
	struct iphdr* ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));

	// Drop packet if it is expired
	if (ip_hdr->ttl <= 1) {
#if ENABLE_DEBUGGING
		printf("Packet has expired. Drop it\n");
#endif
		return -1;
	}

	uint32_t dest_ip = ntohl(ip_hdr->daddr);

	route_t* route = route_table_lookup(dest_ip);

	// No route for this packet, drop it
	if (route == NULL) {
#if ENABLE_DEBUGGING
		printf("No route found for this packet with ip 0x%08x. Drop it\n", dest_ip);
#endif
		return -1;
	}

	uint32_t target_ip = route->next_hop == 0 ? dest_ip : route->next_hop;

	interface_t* out_interface = get_interface_from_name((char*)route->interface_name);

	assert(out_interface != NULL);

	arp_entry_t* arp_entry = get_arp_entry(target_ip);

	if (arp_entry == NULL) {
#if ENABLE_DEBUGGING
		printf("No ARP entry found for ip 0x%08x. Allocate in cache\n", target_ip);
#endif
		arp_entry = alloc_arp_entry(target_ip, ARP_EMPTY);

		init_arp_packet_queue(arp_entry);
	}

	if (arp_entry->state == ARP_EMPTY) {
		if (send_arp_request(target_ip, out_interface, socket) == -1) {
#if ENABLE_DEBUGGING
			printf("Failed to send ARP request. Drop the packet\n");
#endif
			arp_entry->state = ARP_FAILED;

			return -1;
		}

#if ENABLE_DEBUGGING
		printf("Sent ARP request. Add the current packet to queue\n");
#endif

		// Attach the outgoing interface to the ppkt, so the queue rememebers where to send it out
		ppkt->out_interface_idx = out_interface->sockaddr.sll_ifindex;

		add_packet_to_arp_queue(arp_entry, ppkt);

		arp_entry->state = ARP_PENDING;
	} else if (arp_entry->state == ARP_PENDING) {
#if ENABLE_DEBUGGING
		printf("ARP request is still pending. Add the current packet to queue\n");
#endif
		add_packet_to_arp_queue(arp_entry, ppkt);
	} else if (arp_entry->state == ARP_FAILED) {
#if ENABLE_DEBUGGING
		printf("Host Unreachable. Drop packet\n");
#endif
		// TODO: Send Host Unreachable
		return -1;
	} else {
#if ENABLE_DEBUGGING
		printf("Found ARP entry for ip 0x%08x <-> MAC: ", target_ip);

		print_mac_addr(arp_entry->mac);

		printf("\n");
#endif

		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = compute_ip_checksum(ip_hdr, ip_hdr->ihl * 4);

#if ENABLE_DEBUGGING
		print_tcp_packet_info(packet);

		printf("Computed checksum is: 0x%04x\n", ntohs(ip_hdr->check));
#endif

		// Change source host to be the out going interface
		memcpy(eth_hdr->ether_shost, out_interface->mac, ETH_ALEN);

		// Change destination host to be the target's MAC address
		memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETH_ALEN);

		struct sockaddr_ll* send_addr = &out_interface->sockaddr;

		memcpy(send_addr->sll_addr, arp_entry->mac, ETH_ALEN);

		ssize_t sent = sendto(socket, packet, len, 0, (struct sockaddr*)send_addr, sizeof(*(send_addr)));

		if (sent < 0) {
			perror("sendto");

			return -1;
		}
	}

	return 0;
}