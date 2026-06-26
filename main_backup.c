#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_IPV6 0x86DD
#define ETHER_TYPE_ARP  0x0806
#define ETHER_TYPE_VLAN 0x8100

#define PC1_ETH0_MAC_ADDRESS 0x16e775a7b696 // "16:e7:75:a7:b6:96"
#define PC1_IP_ADDRESS 0x0a000102 // 10.0.1.2
#define PC2_ETH0_MAC_ADDRESS 0xe64af566587f // "e6:4a:f5:66:58:7f"
#define PC2_IP_ADDRESS 0x0a000202 // 10.0.2.2

#define IN0_MAC_ADDRESS 0xd2916f712238 // "d2:91:6f:71:22:38"
#define IN0_IP_ADDRESS 0x0a000101 // "10.0.1.1"

#define IN1_MAC_ADDRESS 0xfa0aa6341370 // "fa:0a:a6:34:13:70"
#define IN1_IP_ADDRESS 0x0a000201 // "10.0.2.1"

typedef struct {
	uint32_t net;
	uint32_t mask;
	uint32_t next_hop;
	char interface[16];
} route_t;

typedef struct {
	uint32_t ip;
	uint64_t mac;
} arp_entry_t;

static pcap_t *in0 = NULL;
static pcap_t *in1 = NULL;

static route_t routing_table[] = {
	{
		.net = 0x0a000100,
		.mask = 0xffffff00,
		.next_hop = 0, // directed conncted
		.interface = "r1-eth0",
	},
	{
		.net = 0x0a000200,
		.mask = 0xffffff00,
		.next_hop = 0, // directed conncted
		.interface = "r1-eth1",
	}
};

static arp_entry_t arp_table[] = {
	{
		.ip = PC1_IP_ADDRESS,
		.mac = PC1_ETH0_MAC_ADDRESS,
	},
	{
		.ip = PC2_IP_ADDRESS,
		.mac = PC2_ETH0_MAC_ADDRESS,
	},
};

static bool verify_checksum(const uint8_t *packet);

static uint16_t compute_ip_checksum(const void *packet, const int len);

// Check whether the destination MAC address in the Ethernet header matches the MAC address of the input interface
static bool is_dest_mac_matching(const struct ether_header *eth_hdr, const pcap_t *in_handle);

static int packet_handler(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle);

static int forward_ipv4_packet(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle);

static int forward_arp_packet(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle);

static int forward_vlan_packet(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle);

static int forward_ipv6_packet(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle);

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];

	in0 = pcap_open_live("r1-eth0", 65535, 1, 1, errbuf);

	in1 = pcap_open_live("r1-eth1", 65535, 1, 1, errbuf);

	if (in0 == NULL || in1 == NULL) {
		fprintf(stderr, "Error opening device: %s\n", errbuf);
		return 1;
	}

	while (1) {
		struct pcap_pkthdr *hdr;
		const uint8_t *pkt;

		int ret = pcap_next_ex(in0, &hdr, &pkt);

		if (ret == 1) {
			printf("Packet captured on r1-eth0: length %d\n", hdr->caplen);

			packet_handler(hdr, pkt, in0, in1);
		}

		ret = pcap_next_ex(in1, &hdr, &pkt);

		if (ret == 1) {
			printf("Packet captured on r1-eth1: length %d\n", hdr->caplen);

			packet_handler(hdr, pkt, in1, in0);
		}
	}

	return 0;
}

static bool verify_checksum(const uint8_t *packet) {
	struct iphdr *ip_hdr = (struct iphdr*)(packet + 14);

	uint16_t received_checksum = ntohs(ip_hdr->check);

	printf("Received checksum: 0x%04x\n", received_checksum);

	ip_hdr->check = 0;

	uint16_t computed_checksum = compute_ip_checksum(ip_hdr, ip_hdr->ihl * 4);

	printf("Computed checksum: 0x%04x\n", computed_checksum);

	return received_checksum == ntohs(computed_checksum);
}

// No freaking idea how checksum is computed, just copy from the Internet and hope it works
static uint16_t compute_ip_checksum(const void *packet, const int len) {
	uint32_t sum = 0;
	const uint16_t *data = (const uint16_t *)packet;

	for (int i = 0; i < len / 2; i++) {
		sum += ntohs(data[i]);
	}

	if (len % 2 == 1) {
		sum += ntohs(((const uint8_t *)packet)[len - 1] << 8);
	}

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return htons(~sum);
}

static bool is_dest_mac_matching(const struct ether_header *eth_hdr, const pcap_t *in_handle) {
	uint64_t dest_mac = 0;

	// Extract the destination MAC address from the Ethernet header
	for (int i = 0; i < 6; i++) {
		dest_mac = (dest_mac << 8) | eth_hdr->ether_dhost[i];
	}

	if (in_handle == in0) {
		return dest_mac == IN0_MAC_ADDRESS;
	} else if (in_handle == in1) {
		return dest_mac == IN1_MAC_ADDRESS;
	}

	return false;
}

static int packet_handler(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle) {
	// Parse Ethernet header
	const struct ether_header *eth_hdr = (struct ether_header *)packet;

	// Verify the checksum of the packet. If the checksum is invalid, drop the packet.
	if (!verify_checksum(packet)) {
		printf("Invalid checksum, dropping packet\n");
		return -1;
	}

	if (!is_dest_mac_matching(eth_hdr, in_handle)) {
		printf("Destination MAC address does not match, dropping packet\n");
		return -1;
	}

	printf("Forwarding packet of length %d\n", header->caplen);

	// Extract EtherType
	// Only forward IPv4 packets (EtherType 0x0800)
	uint16_t ether_type = ntohs(eth_hdr->ether_type);

	if (ether_type == ETHER_TYPE_IPV4) {
		return forward_ipv4_packet(header, packet, in_handle, out_handle);
	} else if (ether_type == ETHER_TYPE_ARP) {
		return forward_arp_packet(header, packet, in_handle, out_handle);
	} else if (ether_type == ETHER_TYPE_VLAN) {
		return forward_vlan_packet(header, packet, in_handle, out_handle);
	} else if (ether_type == ETHER_TYPE_IPV6) {
		return forward_ipv6_packet(header, packet, in_handle, out_handle);
	}

	printf("Unsupported EtherType 0x%04x, dropping packet\n", ether_type);

	return -1;
}

static int forward_ipv4_packet(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle) {
	printf("Forwarding IPv4 packet\n");

	// Extract the IP header from the packet
	const struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	// Extract the destination IP address from the IP header
	uint32_t dest_ip = ntohl(ip_hdr->daddr);

	// Look up the routing table to find the next hop
	route_t *route = NULL;

	for (int i = 0; i < sizeof(routing_table) / sizeof(route_t); i++) {
		if ((dest_ip & routing_table[i].mask) == routing_table[i].net) {
			route = &routing_table[i];
			break;
		}
	}

	if (route == NULL) {
		printf("No route found for destination IP 0x%08x, dropping packet\n", dest_ip);
		return -1;
	}

	if (route->next_hop == 0) {
		// Directly connected network, forward the packet to the output interface
		printf("Next hop is directly connected, forwarding packet to interface %s\n", route->interface);

		// Check if TTL is expired
		if (ip_hdr->ttl <= 1) {
			printf("TTL expired, dropping packet\n");
			return -1;
		}

		// Build a new Ethernet header with the appropriate source and destination MAC addresses
		struct ether_header new_eth_hdr;

		new_eth_hdr.ether_type = htons(ETHER_TYPE_IPV4);

		// Build source host MAC address
		if (strcmp(route->interface, "r1-eth0") == 0) {
			for (int i = 0; i < 6; i++) {
				new_eth_hdr.ether_shost[i] = (IN0_MAC_ADDRESS >> (8 * (5 - i))) & 0xFF;
			}
		} else if (strcmp(route->interface, "r1-eth1") == 0) {
			for (int i = 0; i < 6; i++) {
				new_eth_hdr.ether_shost[i] = (IN1_MAC_ADDRESS >> (8 * (5 - i))) & 0xFF;
			}
		} else {
			printf("Unknown output interface %s, dropping packet\n", route->interface);
			return -1;
		}

		// Build destination host MAC address
		arp_entry_t *arp_entry = NULL;

		for (int i = 0; i < sizeof(arp_table) / sizeof(arp_entry_t); i++) {
			if (arp_table[i].ip == dest_ip) {
				arp_entry = &arp_table[i];
				break;
			}
		}

		if (arp_entry == NULL) {
			printf("No ARP entry found for destination IP 0x%08x, dropping packet\n", dest_ip);
			return -1;
		}

		for (int i = 0; i < 6; i++) {
			new_eth_hdr.ether_dhost[i] = (arp_entry->mac >> (8 * (5 - i))) & 0xFF;
		}

		// Decrement the TTL in the IP header
		struct iphdr *new_ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

		new_ip_hdr->ttl--;

		// Recompute the IP header checksum
		new_ip_hdr->check = 0;

		new_ip_hdr->check = compute_ip_checksum(new_ip_hdr, new_ip_hdr->ihl * 4);

		// Build the new packet with the new Ethernet header and the original IP packet
		uint8_t *new_packet = (uint8_t *)malloc(header->caplen);

		// Copy the new Ethernet header
		memcpy(new_packet, &new_eth_hdr, sizeof(struct ether_header));

		// Copy the new IP header
		memcpy(new_packet + sizeof(struct ether_header), new_ip_hdr, header->caplen - sizeof(struct ether_header));

		// Copy the rest of the packet (payload)
		memcpy(new_packet + sizeof(struct ether_header) + sizeof(struct iphdr), packet + sizeof(struct ether_header) + sizeof(struct iphdr), header->caplen - sizeof(struct ether_header) - sizeof(struct iphdr));

		// Summarize the Ethernet header and the IP header
		printf("New Ethernet header: src MAC %02x:%02x:%02x:%02x:%02x:%02x, dst MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
			new_eth_hdr.ether_shost[0], new_eth_hdr.ether_shost[1], new_eth_hdr.ether_shost[2],
			new_eth_hdr.ether_shost[3], new_eth_hdr.ether_shost[4], new_eth_hdr.ether_shost[5],
			new_eth_hdr.ether_dhost[0], new_eth_hdr.ether_dhost[1], new_eth_hdr.ether_dhost[2],
			new_eth_hdr.ether_dhost[3], new_eth_hdr.ether_dhost[4], new_eth_hdr.ether_dhost[5]);

		printf("New IP header: src IP 0x%08x, dst IP 0x%08x, TTL %d\n",
			ntohl(new_ip_hdr->saddr), ntohl(new_ip_hdr->daddr), new_ip_hdr->ttl);


		// Forward the modified packet
		printf("Forwarding packet to interface %s with destination IP 0x%08x\n", route->interface, dest_ip);

		if (pcap_sendpacket(out_handle, new_packet, header->caplen) != 0) {
			fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(out_handle));
			free(new_packet);
			return -1;
		}
	} else {
		// Next hop is not directly connected, need to perform ARP resolution
		printf("Next hop is not directly connected, ARP resolution not implemented yet\n");
		return -1;
	}

	return 0;
}

static int forward_arp_packet(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle) {
	printf("Currently not supported for forwarding ARP packets\n");
	return -1;
}

static int forward_vlan_packet(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle) {
	printf("Currently not supported for forwarding VLAN packets\n");
	return -1;
}

static int forward_ipv6_packet(const struct pcap_pkthdr *header, const uint8_t *packet, const pcap_t *in_handle, const pcap_t *out_handle) {
	printf("Currently not supported for forwarding IPv6 packets\n");
	return -1;
}