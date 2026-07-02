#include "icmp.h"
#include "route_conf.h"
#include "interface.h"
#include "arp.h"
#include "ethernet.h"
#include "checksum.h"
#include "utils.h"
#include "telemetry.h"

#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>

#include <string.h>
#include <assert.h>
#include <stdio.h>

static uint16_t ip_id = 0;

static int send_icmp_or_queue_arp(const ppacket_t* ppkt, const route_t* route, const interface_t* out_interface, const int socket);

static int build_icmp_packet(
	const ppacket_t* origin_ppkt,
	ppacket_t* out,
	const uint8_t type,
	const uint8_t code,
	const interface_t* out_interface
);

int send_icmp_time_exceed(const ppacket_t* ppkt, const int socket) {
	const struct iphdr* ori_ip_hdr = (struct iphdr*)(ppkt->packet + sizeof(struct ether_header));

	ppacket_t out_ppkt = { 0 };

	// Look for route
	const uint32_t dest_ip = ntohl(ori_ip_hdr->saddr);

	route_t* route = route_table_lookup(dest_ip);

	if (route == NULL) {
		printf("Route not found!\n");

		return -1;
	}

	interface_t* out_interface = get_interface_from_name(route->interface_name);

	// Build ICMP packet
	if (build_icmp_packet(ppkt, &out_ppkt, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, out_interface) == -1) {
		printf("Failed to build ICMP packet\n");

		return -1;
	}

	// Send
	return send_icmp_or_queue_arp(&out_ppkt, route, out_interface, socket);
}

int send_icmp_net_unreachable(const ppacket_t* ppkt, const int socket) {
	const struct iphdr* ori_ip_hdr = (struct iphdr*)(ppkt->packet + sizeof(struct ether_header));

	ppacket_t out_ppkt = { 0 };

	// Look for route
	const uint32_t dest_ip = ntohl(ori_ip_hdr->saddr);

	route_t* route = route_table_lookup(dest_ip);

	if (route == NULL) {
		printf("Route not found!\n");

		return -1;
	}

	interface_t* out_interface = get_interface_from_name(route->interface_name);

	// Build ICMP packet
	if (build_icmp_packet(ppkt, &out_ppkt, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, out_interface) == -1) {
		printf("Failed to build ICMP packet\n");

		return -1;
	}

	// Send
	return send_icmp_or_queue_arp(&out_ppkt, route, out_interface, socket);
}

int send_icmp_host_unreachable(const ppacket_t* ppkt, const int socket) {
	const struct iphdr* ori_ip_hdr = (struct iphdr*)(ppkt->packet + sizeof(struct ether_header));

	ppacket_t out_ppkt = { 0 };

	// Look for route
	const uint32_t dest_ip = ntohl(ori_ip_hdr->saddr);

	route_t* route = route_table_lookup(dest_ip);

	if (route == NULL) {
		printf("Route not found!\n");

		return -1;
	}

	interface_t* out_interface = get_interface_from_name(route->interface_name);

	// Build ICMP packet
	if (build_icmp_packet(ppkt, &out_ppkt, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, out_interface) == -1) {
		printf("Failed to build ICMP packet\n");

		return -1;
	}

	// Send
	return send_icmp_or_queue_arp(&out_ppkt, route, out_interface, socket);
}

static int build_icmp_packet(
	const ppacket_t* origin_ppkt,
	ppacket_t* out,
	const uint8_t type,
	const uint8_t code,
	const interface_t* out_interface
) {
	assert(origin_ppkt != NULL);
	assert(out != NULL);

	const uint8_t* origin_packet = origin_ppkt->packet;

	const struct ether_header* ori_eth_hdr = (struct ether_header*)origin_packet;
	const struct iphdr* ori_ip_hdr = (struct iphdr*)(origin_packet + sizeof(struct ether_header));

	uint8_t* out_packet = out->packet;

	struct ether_header* out_eth_hdr = (struct ether_header*)out_packet;
	struct iphdr* out_ip_hdr = (struct iphdr*)(out_packet + sizeof(struct ether_header));

	const size_t ori_ip_hdr_len = ori_ip_hdr->ihl * 4;
	const size_t ori_ip_payload_len = ori_ip_hdr->tot_len - ori_ip_hdr_len;
	const size_t icmp_hdr_len = sizeof(struct icmphdr);
	size_t icmp_tot_len = icmp_hdr_len;

	if (type == ICMP_ECHOREPLY) {
		// ICMP total length is ipv4 payload length (icmp header + icmp ping echo payload)
		icmp_tot_len = ori_ip_payload_len;
	} else if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED) {
		// ICMP total length is icmp header length + ori ip header length (likely 20 bytes) + 8 (first 8 bytes of payload)
		icmp_tot_len += ori_ip_hdr_len + 8;
	} else {
		printf("ICMP type = %u not supported\n", type);

		return -1;
	}

	struct icmphdr *out_icmp_hdr = (struct icmphdr*)(out_packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	uint8_t* out_icmp_payload = (uint8_t*)out_icmp_hdr + sizeof(struct icmphdr);

	// Build ppacket_t metadata
	out->len = sizeof(struct ether_header) + sizeof(struct iphdr) + icmp_tot_len;
	out->out_interface_idx = out_interface->sockaddr.sll_ifindex;
	out->recv_interface_idx = origin_ppkt->recv_interface_idx;

	// Build Ethernet header
	// We don't know Dest MAC yet until ARP, so leave it blank
	// -----------------------------
	// Build source MAC address
	memcpy(out_eth_hdr->ether_shost, out_interface->mac, ETH_ALEN);

	out_eth_hdr->ether_type = htons(ETHER_TYPE_IPV4);

	// Build ipv4 header
	out_ip_hdr->version = 4;
	out_ip_hdr->ihl = 5;
	out_ip_hdr->id = htons(ip_id++);
	out_ip_hdr->tos = 0;
	out_ip_hdr->tot_len = htons(20 + icmp_tot_len); // ihl = 5 * 4 = 20
	out_ip_hdr->frag_off = 0;
	out_ip_hdr->ttl = 64;
	out_ip_hdr->saddr = htonl(out_interface->ip);
	out_ip_hdr->daddr = ori_ip_hdr->saddr;

	out_ip_hdr->protocol = IPPROTO_ICMP;
	out_ip_hdr->check = 0;
	out_ip_hdr->check = compute_ip_checksum(out_ip_hdr, 20);

	// Build ICMP header
	out_icmp_hdr->type = type;
	out_icmp_hdr->code = code;
	out_icmp_hdr->checksum = 0;

	assert(type == ICMP_ECHOREPLY || type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED);

	if (type == ICMP_ECHOREPLY) {
		const uint8_t* ori_ip_payload = (uint8_t*)ori_ip_hdr + ori_ip_hdr->ihl * 4;

		memcpy(out_icmp_payload, ori_ip_payload, ori_ip_payload_len);
	} else {
		memcpy(out_icmp_payload, ori_ip_hdr, ori_ip_hdr_len + 8);
	}

	out_icmp_hdr->checksum = checksum16(out_icmp_hdr, icmp_tot_len);
}

static int send_icmp_or_queue_arp(const ppacket_t* ppkt, const route_t* route, const interface_t* out_interface, const int socket) {
	assert(ppkt != NULL);
	assert(route != NULL);
	assert(out_interface != NULL);

	const uint8_t* packet = ppkt->packet;
	struct ether_header* eth_hdr = (struct ether_header*)packet;
	const struct iphdr* ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));

	const uint32_t target_ip = route->next_hop == 0 ? ntohl(ip_hdr->daddr) : route->next_hop;

	// Look up ARP table to find which MAC addr is corresponding to this target ip
	arp_entry_t* arp_entry = get_arp_entry(target_ip);

	if (arp_entry == NULL) {
		arp_entry = alloc_arp_entry(target_ip, ARP_EMPTY);

		init_arp_packet_queue(arp_entry);
	}

	if (arp_entry->state == ARP_EMPTY) {
		if (send_arp_request(target_ip, out_interface, socket) == -1) {
			arp_entry->state = ARP_FAILED;

			return -1;
		}

		// out_ppkt could have be a malloc call because if it's not
		// out_ppkt would be destroyed the function ends (declared in stack)
		// but add_packet_arp_queue() would clone it anyway, so there is no need to do that
		add_packet_to_arp_queue(arp_entry, ppkt);

		arp_entry->state = ARP_PENDING;
	} else if (arp_entry->state == ARP_PENDING) {
		add_packet_to_arp_queue(arp_entry, ppkt);
	} else if (arp_entry->state == ARP_FAILED) {
		return -1;
	} else {
		memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETH_ALEN);

		struct sockaddr_ll send_addr = {0};

		send_addr.sll_family = AF_PACKET;
		send_addr.sll_ifindex = out_interface->sockaddr.sll_ifindex;
		send_addr.sll_halen = ETH_ALEN;

		memcpy(send_addr.sll_addr, arp_entry->mac, ETH_ALEN);

		ssize_t sent = sendto(socket, ppkt->packet, ppkt->len, 0, (struct sockaddr*)&send_addr, sizeof(send_addr));

		if (sent < 0) {
			perror("sendto");

			increase_sendto_fail_count();

			return -1;
		}
	}

	return 0;
}