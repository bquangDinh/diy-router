#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_IPV6 0x86DD
#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_VLAN 0x8100

#define PC1_ETH0_MAC_ADDRESS 0xfe245a03482f // "fe:24:5a:03:48:2f"
#define PC1_IP_ADDRESS 0x0a000102	    // 10.0.1.2
#define PC2_ETH0_MAC_ADDRESS 0xe64af566587f // "e6:4a:f5:66:58:7f"
#define PC2_IP_ADDRESS 0x0a000202	    // 10.0.2.2

#define IN0_MAC_ADDRESS 0xd2916f712238 // "d2:91:6f:71:22:38"
#define IN0_IP_ADDRESS 0x0a000101      // "10.0.1.1"

#define IN1_MAC_ADDRESS 0xfa0aa6341370 // "fa:0a:a6:34:13:70"
#define IN1_IP_ADDRESS 0x0a000201      // "10.0.2.1"

#define ARP_CACHE_SIZE 256

typedef struct {
	uint32_t net;
	uint32_t mask;
	uint32_t next_hop;
	char	 interface[16];
} route_t;

struct arp_packet {
	uint16_t htype; // Hardware type (1 for Ethernet)
	uint16_t ptype; // Protocol type (0x0800 for IPv4)
	uint8_t	 hlen; // Hardware address length (6 for MAC)
	uint8_t	 plen; // Protocol address length (4 for IPv4)
	uint16_t oper; // Operation (1 for request, 2 for reply)
	uint8_t	 sha[6]; // Sender hardware address (MAC)
	uint32_t spa; // Sender protocol address (IP)
	uint8_t	 tha[6]; // Target hardware address (MAC)
	uint32_t tpa; // Target protocol address (IP)
} __attribute__((packed));

typedef struct pending_packet {
	uint8_t		       packet[1600];
	int		       len;
	char		       out_interface[16];
	struct pending_packet *next;
} pending_packet_t;

typedef enum { ARP_EMPTY, ARP_PENDING, ARP_RESOLVED, ARP_FAILED } arp_state_t;

typedef struct {
	uint32_t ip;
	uint64_t mac;
	uint8_t	 valid;

	arp_state_t state;

	uint16_t	  pending_packets_count;
	pending_packet_t *pending_packets;
} arp_entry_t;

static pcap_t *in0 = NULL;
static pcap_t *in1 = NULL;

static route_t routing_table[] = {{
					  .net	     = 0x0a000100,
					  .mask	     = 0xffffff00,
					  .next_hop  = 0, // directed conncted
					  .interface = "r1-eth0",
				  },
				  {
					  .net	     = 0x0a000200,
					  .mask	     = 0xffffff00,
					  .next_hop  = 0, // directed conncted
					  .interface = "r1-eth1",
				  }};

static arp_entry_t arp_table[ARP_CACHE_SIZE];

static bool verify_checksum(const uint8_t *packet);

static uint16_t compute_ip_checksum(const void *packet, const int len);

// Check whether the destination MAC address in the Ethernet header matches the
// MAC address of the input interface
static bool is_dest_mac_matching(const struct ether_header *eth_hdr,
				 const pcap_t		   *in_handle);

static bool send_arp_request(uint32_t target_ip, const char *interface);

static bool send_arp_response(const uint8_t* packet, const pcap_t *in_handle);

static arp_entry_t *add_arp_entry(uint32_t ip, uint64_t mac,
				  arp_state_t init_state);

static arp_entry_t *get_arp_entry(uint32_t ip);

static pending_packet_t *create_pending_packet(const uint8_t *packet, int len,
					       const char *out_interface);

static void add_pending_packet(arp_entry_t *arp_entry, const uint8_t *packet,
			       int len, const char *out_interface);

static void update_dest_mac_addr_packet(uint8_t *packet, uint64_t mac);

static void flush_pending_packets(uint32_t resolved_ip);

static int packet_handler(const struct pcap_pkthdr *header,
			  const uint8_t *packet, const pcap_t *in_handle);

static int forward_ipv4_packet(const struct pcap_pkthdr *header,
			       const uint8_t		*packet);

static int handle_arp_packet(const struct pcap_pkthdr *header,
			     const uint8_t	      *packet, const pcap_t* in_handle);

static int forward_vlan_packet(const struct pcap_pkthdr *header,
			       const uint8_t		*packet);

static int forward_ipv6_packet(const struct pcap_pkthdr *header,
			       const uint8_t		*packet);

static void print_icmp_req_seq(const uint8_t* packet);

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
		const uint8_t	   *pkt;

		int ret = pcap_next_ex(in0, &hdr, &pkt);

		if (ret == 1) {
			printf("Packet captured on r1-eth0: length %d\n",
			       hdr->caplen);

			packet_handler(hdr, pkt, in0);

			printf("-----------------------------------\n\n");
		}

		ret = pcap_next_ex(in1, &hdr, &pkt);

		if (ret == 1) {
			printf("Packet captured on r1-eth1: length %d\n",
			       hdr->caplen);

			packet_handler(hdr, pkt, in1);

			printf("-----------------------------------\n\n");
		}
	}

	return 0;
}

static bool verify_checksum(const uint8_t *packet) {
	struct iphdr *ip_hdr = (struct iphdr *)(packet + 14);

	uint16_t received_checksum = ntohs(ip_hdr->check);

	printf("Received checksum: 0x%04x\n", received_checksum);

	ip_hdr->check = 0;

	uint16_t computed_checksum =
		compute_ip_checksum(ip_hdr, ip_hdr->ihl * 4);

	printf("Computed checksum: 0x%04x\n", ntohs(computed_checksum));

	return received_checksum == ntohs(computed_checksum);
}

// No freaking idea how checksum is computed, just copy from the Internet and
// hope it works
static uint16_t compute_ip_checksum(const void *packet, const int len) {
	uint32_t	sum  = 0;
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

static bool is_dest_mac_matching(const struct ether_header *eth_hdr,
				 const pcap_t		   *in_handle) {
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

static bool send_arp_request(uint32_t target_ip, const char *interface) {
	// Construct a new Ethernet frame with an ARP request
	uint8_t arp_request[sizeof(struct ether_header) +
			    sizeof(struct arp_packet)];

	struct ether_header *eth_hdr = (struct ether_header *)arp_request;
	struct arp_packet   *arp_req =
		(struct arp_packet *)(arp_request +
				      sizeof(struct ether_header));

	// Set the destination MAC address to the broadcast address
	memset(eth_hdr->ether_dhost, 0xff, 6);

	long int source_ip;
	uint64_t source_mac;

	if (strcmp(interface, "r1-eth0") == 0) {
		source_ip  = IN0_IP_ADDRESS;
		source_mac = IN0_MAC_ADDRESS;
	} else if (strcmp(interface, "r1-eth1") == 0) {
		source_ip  = IN1_IP_ADDRESS;
		source_mac = IN1_MAC_ADDRESS;
	} else {
		printf("Unknown interface %s\n", interface);
		return false;
	}

	// Set the source MAC address to the MAC address of the interface
	for (int i = 0; i < 6; i++) {
		eth_hdr->ether_shost[i] = (source_mac >> (8 * (5 - i))) & 0xFF;
	}

	eth_hdr->ether_type = htons(ETHER_TYPE_ARP);

	arp_req->htype = htons(1); // Ethernet
	arp_req->ptype = htons(ETHER_TYPE_IPV4);
	arp_req->hlen  = 6;		   // MAC address length
	arp_req->plen  = 4;		   // IPv4 address length
	arp_req->oper  = htons(1);	   // ARP request
	arp_req->spa   = htonl(source_ip); // Source IP address
	arp_req->tpa   = htonl(target_ip); // Target IP address

	for (int i = 0; i < 6; i++) {
		arp_req->sha[i] = (source_mac >> (8 * (5 - i))) & 0xFF;
		arp_req->tha[i] = 0; // Target MAC address is unknown
	}

	pcap_t *out_handle = NULL;

	if (strcmp(interface, "r1-eth0") == 0)
		out_handle = in0;
	else if (strcmp(interface, "r1-eth1") == 0)
		out_handle = in1;
	else
		return false;

	if (pcap_sendpacket(out_handle, arp_request, sizeof(arp_request)) !=
	    0) {
		fprintf(stderr, "Error sending ARP request: %s\n",
			pcap_geterr(out_handle));
		return false;
	}

	return true;
}

static bool send_arp_response(const uint8_t* arp_request, const pcap_t *in_handle) {
	uint8_t arp_response[sizeof(struct ether_header) + sizeof(struct arp_packet)];

	memcpy(arp_response, arp_request, sizeof(struct ether_header) + sizeof(struct arp_packet));

	struct ether_header* eth_hdr = (struct ether_header*)arp_response;
	struct arp_packet* arp = (struct arp_packet*)(arp_response + sizeof(struct ether_header));

	// Flip the destination MAC to be the source MAC
	// Since this is the reply back to the source MAC address
	// So we want to send the Ethernet frame back to the requester
	for (int i = 0; i < 6; ++i) eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];

	uint64_t mac;
	uint32_t src_ip;
	uint32_t target_ip = arp->spa;

	if (in_handle == in0) {
		mac = IN0_MAC_ADDRESS;
		src_ip = IN0_IP_ADDRESS;
	} else if (in_handle == in1) {
		mac = IN1_MAC_ADDRESS;
		src_ip = IN1_IP_ADDRESS;
	} else {
		printf("Invalid interface\n");

		return false;
	}

	arp->oper = htons(2); // reply

	for (uint8_t i = 0; i < 6; ++i) {
		arp->tha[i] = arp->sha[i];
	}


	for (uint8_t i = 0; i < 6; ++i) {
		arp->sha[i] = (mac >> (8 * (5 - i))) & 0xFF;
	}

	arp->spa = htonl(src_ip);
	arp->tpa = target_ip;

	if (pcap_sendpacket(in_handle, arp_response, sizeof(arp_response)) !=
	    0) {
		fprintf(stderr, "Error sending ARP response: %s\n",
			pcap_geterr(in_handle));
		return false;
	}

	return true;
}

static arp_entry_t *add_arp_entry(uint32_t ip, uint64_t mac,
				  arp_state_t init_state) {
	uint16_t pos = 0;

	for (int i = 0; i < ARP_CACHE_SIZE; i++) {
		if (arp_table[i].valid == 0) {
			arp_table[i].ip	   = ip;
			arp_table[i].mac   = mac;
			arp_table[i].valid = 1;
			arp_table[i].state = init_state;

			pos = i;

			break;
		}
	}

	// ARP cache is full
	// Evict
	if (pos >= ARP_CACHE_SIZE) {
		// For now, just evict the first entry that is not in PENDING
		// state
		for (int i = 0; i < ARP_CACHE_SIZE; i++) {
			if (arp_table[i].state != ARP_PENDING) {
				pos = i;
				break;
			}
		}
	}

	arp_table[pos].ip    = ip;
	arp_table[pos].mac   = mac;
	arp_table[pos].valid = 1;
	arp_table[pos].state = init_state;

	printf("Added ARP entry: IP 0x%08x, MAC "
	       "%02lx:%02lx:%02lx:%02lx:%02lx:%02lx\n",
	       ip, (mac >> 40) & 0xFF, (mac >> 32) & 0xFF, (mac >> 24) & 0xFF,
	       (mac >> 16) & 0xFF, (mac >> 8) & 0xFF, mac & 0xFF);

	return &arp_table[pos];
}

static arp_entry_t *get_arp_entry(uint32_t ip) {
	for (int i = 0; i < ARP_CACHE_SIZE; i++) {
		if (arp_table[i].ip == ip && arp_table[i].valid == 1) {
			return &arp_table[i];
		}
	}

	return NULL;
}

static pending_packet_t *create_pending_packet(const uint8_t *packet, int len,
					       const char *out_interface) {
	pending_packet_t *new_packet =
		(pending_packet_t *)malloc(sizeof(pending_packet_t));

	if (new_packet == NULL) {
		return NULL;
	}

	memcpy(new_packet->packet, packet, len);
	new_packet->len = len;
	strncpy(new_packet->out_interface, out_interface,
		sizeof(new_packet->out_interface) - 1);
	new_packet->out_interface[sizeof(new_packet->out_interface) - 1] = '\0';
	new_packet->next						 = NULL;

	return new_packet;
}

static void add_pending_packet(arp_entry_t *arp_entry, const uint8_t *packet,
			       int len, const char *out_interface) {
	pending_packet_t *new_packet =
		create_pending_packet(packet, len, out_interface);

	if (new_packet == NULL) {
		fprintf(stderr,
			"Memory allocation failed for pending packet\n");
		return;
	}

	pending_packet_t *head	  = arp_entry->pending_packets;
	pending_packet_t *current = head;

	if (head == NULL) {
		arp_entry->pending_packets = new_packet;
	} else {
		// Traverse to the end of the list
		while (current->next != NULL) {
			current = current->next;
		}

		// Add to the end of the list
		// NOTE: I could add to the head instead tail to have O(1)
		// insertion time, but the order would mess up
		current->next = new_packet;
	}

	arp_entry->pending_packets_count++;

	print_icmp_req_seq(packet);
}

static void update_dest_mac_addr_packet(uint8_t *packet, uint64_t mac) {
	struct ether_header* eth_hdr = (struct ether_header*)packet;

	for (uint8_t i = 0; i < 6; ++i) {
		eth_hdr->ether_dhost[i] = (mac >> (8 * (5 - i))) & 0xFF;
	}
}

static void flush_pending_packets(uint32_t resolved_ip) {
	arp_entry_t *arp_entry = get_arp_entry(resolved_ip);

	if (arp_entry == NULL) {
		printf("ARP entry is NULL. It should not be NULL in flushing "
		       "packet\n");
		return;
	}

	uint64_t mac = arp_entry->mac;

	// Send all pending packets that are waiting for the resolved IP address
	pending_packet_t *current = arp_entry->pending_packets;

	printf("Flushing pending packet [%d pending] for resolved IP "
	       "0x%08x\n",
	       arp_entry->pending_packets_count, resolved_ip);

	while (current != NULL) {
		pcap_t *out_handle = NULL;

		if (strcmp(current->out_interface, "r1-eth0") == 0)
			out_handle = in0;
		else if (strcmp(current->out_interface, "r1-eth1") == 0)
			out_handle = in1;
		else {
			fprintf(stderr, "Unknown output interface %s\n",
				current->out_interface);
			return;
		}

		// Change destination MAC address to the resolved MAC address
		update_dest_mac_addr_packet(current->packet, mac);

		print_icmp_req_seq(current->packet);

		if (pcap_sendpacket(out_handle, current->packet,
				    current->len) != 0) {
			fprintf(stderr, "Error sending pending packet: %s\n",
				pcap_geterr(out_handle));
		}

		current = current->next;
	}

	printf("Done sending all pending requests\n");

	arp_entry->pending_packets_count = 0;
}

static int packet_handler(const struct pcap_pkthdr *header,
			  const uint8_t *packet, const pcap_t *in_handle) {
	// Parse Ethernet header
	const struct ether_header *eth_hdr = (struct ether_header *)packet;

	if (!is_dest_mac_matching(eth_hdr, in_handle)) {
		printf("Destination MAC address does not match, dropping "
		       "packet\n");
		return -1;
	}

	printf("Forwarding packet of length %d\n", header->caplen);

	// Extract EtherType
	// Only forward IPv4 packets (EtherType 0x0800)
	uint16_t ether_type = ntohs(eth_hdr->ether_type);

	if (ether_type == ETHER_TYPE_IPV4) {
		return forward_ipv4_packet(header, packet);
	} else if (ether_type == ETHER_TYPE_ARP) {
		return handle_arp_packet(header, packet, in_handle);
	} else if (ether_type == ETHER_TYPE_VLAN) {
		return forward_vlan_packet(header, packet);
	} else if (ether_type == ETHER_TYPE_IPV6) {
		return forward_ipv6_packet(header, packet);
	}

	printf("Unsupported EtherType 0x%04x, dropping packet\n", ether_type);

	return -1;
}

static int forward_ipv4_packet(const struct pcap_pkthdr *header,
			       const uint8_t		*packet) {
	printf("Forwarding IPv4 packet\n");

	// Verify the checksum of the packet. If the checksum is invalid, drop
	// the packet.
	if (!verify_checksum(packet)) {
		printf("Invalid checksum, dropping packet\n");
		return -1;
	}

	// Extract the IP header from the packet
	const struct iphdr *ip_hdr =
		(struct iphdr *)(packet + sizeof(struct ether_header));

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
		printf("No route found for destination IP 0x%08x, dropping "
		       "packet\n",
		       dest_ip);
		return -1;
	}

	if (route->next_hop == 0) {
		// Directly connected network, forward the packet to the output
		// interface
		printf("Next hop is directly connected, forwarding packet to "
		       "interface %s\n",
		       route->interface);

		// Build the new packet with the new Ethernet header and the
		// original IP packet
		uint8_t *new_packet = (uint8_t *)malloc(header->caplen);

		if (new_packet == NULL) {
			fprintf(stderr, "Memory allocation failed\n");
			return -1;
		}

		// Copy the original packet into the new packet
		memcpy(new_packet, packet, header->caplen);

		// Build a new Ethernet header with the appropriate source and
		// destination MAC addresses
		struct ether_header *new_eth_hdr =
			(struct ether_header *)new_packet;

		struct iphdr *new_ip_hdr =
			(struct iphdr *)(new_packet +
					 sizeof(struct ether_header));

		new_eth_hdr->ether_type = htons(ETHER_TYPE_IPV4);

		// Check if TTL is expired
		if (new_ip_hdr->ttl <= 1) {
			printf("TTL expired, dropping packet\n");
			free(new_packet);
			return -1;
		}

		// Decrement TTL and recompute CRC
		new_ip_hdr->ttl--;
		new_ip_hdr->check = 0;
		new_ip_hdr->check =
			compute_ip_checksum(new_ip_hdr, new_ip_hdr->ihl * 4);

		// Build source host MAC address
		if (strcmp(route->interface, "r1-eth0") == 0) {
			for (int i = 0; i < 6; i++) {
				new_eth_hdr->ether_shost[i] =
					(IN0_MAC_ADDRESS >> (8 * (5 - i))) &
					0xFF;
			}
		} else if (strcmp(route->interface, "r1-eth1") == 0) {
			for (int i = 0; i < 6; i++) {
				new_eth_hdr->ether_shost[i] =
					(IN1_MAC_ADDRESS >> (8 * (5 - i))) &
					0xFF;
			}
		} else {
			printf("Unknown output interface %s, dropping packet\n",
			       route->interface);
			return -1;
		}

		// Build destination host MAC address
		arp_entry_t *arp_entry = NULL;

		for (int i = 0; i < sizeof(arp_table) / sizeof(arp_entry_t);
		     i++) {
			if (arp_table[i].ip == dest_ip) {
				arp_entry = &arp_table[i];
				break;
			}
		}

		if (arp_entry == NULL) {
			bool arp_has_sent = false;

			// If the destination MAC address is not found in the
			// ARP table, send an ARP request
			printf("Destination MAC address not found in ARP "
			       "table, sending ARP request\n");

			// Check if we already have a pending arp entry
			// If not yet, then create one
			// Otherwise, just adding new packets to the queue
			arp_entry_t *arp_entry = get_arp_entry(dest_ip);

			if (arp_entry == NULL) {
				// Not yet create
				// Create one
				arp_entry = add_arp_entry(dest_ip, 0xFF,
							  ARP_PENDING);
			} else {
				// it is presence mean we have sent ARP request
				arp_has_sent = true;
			}

			// Queue the packet for later forwarding after ARP
			// resolution
			add_pending_packet(arp_entry, new_packet,
					   header->caplen, route->interface);

			// Check if an ARP request has already been sent for
			// this IP address
			if (!arp_has_sent) {
				if (!send_arp_request(dest_ip,
						      route->interface)) {
					// Just drop the packet for now
					// Add ICMP message back to the origin
					// device that the target is unreachable
					printf("Failed to send ARP request, "
					       "dropping packet\n");
					free(new_packet);
					return -1;
				}
			}

			return 0;
		}

		for (int i = 0; i < 6; i++) {
			new_eth_hdr->ether_dhost[i] =
				(arp_entry->mac >> (8 * (5 - i))) & 0xFF;
		}

		// Summarize the Ethernet header and the IP header
		printf("New Ethernet header: src MAC "
		       "%02x:%02x:%02x:%02x:%02x:%02x, dst MAC "
		       "%02x:%02x:%02x:%02x:%02x:%02x\n",
		       new_eth_hdr->ether_shost[0], new_eth_hdr->ether_shost[1],
		       new_eth_hdr->ether_shost[2], new_eth_hdr->ether_shost[3],
		       new_eth_hdr->ether_shost[4], new_eth_hdr->ether_shost[5],
		       new_eth_hdr->ether_dhost[0], new_eth_hdr->ether_dhost[1],
		       new_eth_hdr->ether_dhost[2], new_eth_hdr->ether_dhost[3],
		       new_eth_hdr->ether_dhost[4],
		       new_eth_hdr->ether_dhost[5]);

		printf("New IP header: src IP 0x%08x, dst IP 0x%08x, TTL %d\n",
		       ntohl(new_ip_hdr->saddr), ntohl(new_ip_hdr->daddr),
		       new_ip_hdr->ttl);

		// Forward the modified packet
		printf("Forwarding packet to interface %s with destination IP "
		       "0x%08x\n",
		       route->interface, dest_ip);

		pcap_t *out_handle = NULL;

		if (strcmp(route->interface, "r1-eth0") == 0)
			out_handle = in0;
		else if (strcmp(route->interface, "r1-eth1") == 0)
			out_handle = in1;
		else
			return -1;

		if (pcap_sendpacket(out_handle, new_packet, header->caplen) !=
		    0) {
			fprintf(stderr, "Error sending packet: %s\n",
				pcap_geterr(out_handle));
			free(new_packet);
			return -1;
		}

		free(new_packet);
	} else {
		// Next hop is not directly connected, need to perform ARP
		// resolution
		printf("Next hop is not directly connected, ARP resolution not "
		       "implemented yet\n");
		return -1;
	}

	return 0;
}

static int handle_arp_packet(const struct pcap_pkthdr *header,
			     const uint8_t	      *packet, const pcap_t* in_handle) {
	printf("Handling ARP packet\n");

	// Extract the ARP packet from the Ethernet frame
	const struct arp_packet *arp_pkt =
		(const struct arp_packet *)(packet +
					    sizeof(struct ether_header));

	uint32_t src_ip = ntohl(arp_pkt->spa);

	// Check if this is an ARP reply
	uint16_t op = ntohs(arp_pkt->oper);

	if (op == 2) {
		printf("Received ARP reply for IP 0x%08x\n", src_ip);

		// Add the ARP entry to the ARP table
		uint64_t mac = 0;
		for (int i = 0; i < 6; i++) {
			mac = (mac << 8) | arp_pkt->sha[i];
		}

		arp_entry_t *arp_entry = get_arp_entry(src_ip);

		if (arp_entry == NULL) {
			printf("ARP entry is NULL. It should not be NULL in "
			       "arp packet handling\n");
			return -1;
		}

		// Update MAC address
		arp_entry->mac = mac;

		// Flush any pending packets waiting for this ARP resolution
		flush_pending_packets(src_ip);

		arp_entry->state = ARP_RESOLVED;
	} else if (op == 1) {
		// ARP request
		send_arp_response(packet, in_handle);
	} else {
		printf("Unsupported ARP operation code\n");
	}

	return 0;
}

static int forward_vlan_packet(const struct pcap_pkthdr *header,
			       const uint8_t		*packet) {
	printf("Currently not supported for forwarding VLAN packets\n");
	return -1;
}

static int forward_ipv6_packet(const struct pcap_pkthdr *header,
			       const uint8_t		*packet) {
	printf("Currently not supported for forwarding IPv6 packets\n");
	return -1;
}

static void print_icmp_req_seq(const uint8_t* packet) {
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