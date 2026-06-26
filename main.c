#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#define ROUTER_IN0_NAME "r1-eth0"
#define ROUTER_IN1_NAME "r1-eth1"

#define IN0_MAC_ADDRESS 0xd2916f712238 // "d2:91:6f:71:22:38"
#define IN0_IP_ADDRESS 0x0a000101      // "10.0.1.1"

#define IN1_MAC_ADDRESS 0xfa0aa6341370 // "fa:0a:a6:34:13:70"
#define IN1_IP_ADDRESS 0x0a000c01      // "10.0.12.1"

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_IPV6 0x86DD
#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_VLAN 0x8100

#define ARP_CACHE_SIZE 256

typedef struct route {
	uint32_t net; // the network that this interface is connected to
	uint32_t mask;
	uint32_t
		next_hop; // the next neighbor ip this interface is connected to
	struct sockaddr_ll *interface;
	uint8_t* inteface_MAC;
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
	struct sockaddr_ll    *out_interface;
	struct pending_packet *next;
} pending_packet_t;

typedef enum { ARP_EMPTY, ARP_PENDING, ARP_RESOLVED, ARP_FAILED } arp_state_t;

typedef struct arp_entry {
	uint32_t ip;
	uint8_t mac[ETH_ALEN];
	uint8_t	 valid;

	arp_state_t state;

	uint16_t	  pending_packets_count;
	pending_packet_t *pending_packets;
} arp_entry_t;

static int sock = -1;

// Since we assume the router has two interfaces
// Declare them here
struct sockaddr_ll reth0_sockaddr = {0};
struct sockaddr_ll reth1_sockaddr = {0};

const uint8_t reth0_mac[ETH_ALEN] = { 0xD2, 0x91, 0x6F, 0x71, 0x22, 0x38 };
const uint8_t reth1_mac[ETH_ALEN] = { 0xFA, 0x0A, 0xA6, 0x34, 0x13, 0x70 };

static route_t routing_table[] = {
	{
		.net	    = 0x0a000100,
		.mask	    = 0xffffff00,
		.next_hop = 0, // directed conncted
		.interface = &reth0_sockaddr,
		.inteface_MAC = reth0_mac
	},
	{
		.net		= 0x0a000c01,
		.mask		= 0xffffff00,
		.next_hop	= 0,
		.interface = &reth1_sockaddr,
		.inteface_MAC = reth1_mac
	},
	{
		.net		= 0x0a000200,
		.mask		= 0xffffff00,
		.next_hop	= 0x0a000c02,
		.interface = &reth1_sockaddr,
		.inteface_MAC = reth1_mac
	}
};

static arp_entry_t arp_cache[ARP_CACHE_SIZE] = {
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
		.valid = true
	},
	{
		.ip = 0x0a000c02,
		.mac = { 0XA2, 0xC6, 0x68, 0x5B, 0x4A, 0x1A },
		.state = ARP_RESOLVED,
		.valid = true
	}
};

static void packet_handler(const uint8_t* packet, ssize_t len, struct sockaddr_ll* recv_sockaddr);

static void handle_ipv4_packet(const uint8_t* packet, ssize_t len);
static void handle_ipv6_packet(const uint8_t* packet, ssize_t len);
static void handle_vlan_packet(const uint8_t* packet, ssize_t len);
static void handle_arp_packet(const uint8_t* packet, ssize_t len);

// Check if the incoming packet is a broadcast
static bool is_dest_mac_broadcast(const uint8_t* mac);

// Check if the incoming packet is meant for this interface
static bool is_dest_mac_match(const uint8_t* mac, struct sockaddr_ll* recv_sockaddr);

static bool verify_checksum(const uint8_t* packet);

static route_t* routing_table_lookup(const uint32_t dest_ip);

static arp_entry_t* get_arp_entry(const uint32_t ip);

static bool send_arp_request(const uint32_t target_ip, const struct sockaddr_ll* out_interface);

static bool send_arp_response(const uint8_t* arp_request);

static arp_entry_t* create_empty_arp_entry(const uint32_t ip, const arp_state_t init_state);

static void add_packet_to_queue(arp_entry_t* arp_entry, const uint8_t* packet, const ssize_t len, const struct sockaddr_ll* out_interface);

static uint16_t compute_ip_checksum(const void* packet, ssize_t len);

static void remove_arp_entry(arp_entry_t* entry);

static void flush_pending_packets(arp_entry_t* arp);

static void print_icmp_req_seq(const uint8_t* packet);

int main() {
	uint8_t buffer[65535];
	struct sockaddr_ll recv_sockaddr = { 0 };
	socklen_t addrlen = sizeof(recv_sockaddr);

	// Create a AF_PACKET socket
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock < 0) {
		perror("socket");

		return -1;
	}

	memset(&reth0_sockaddr, 0, sizeof(reth0_sockaddr));

	memset(&reth1_sockaddr, 0, sizeof(reth1_sockaddr));

	reth0_sockaddr.sll_family = AF_PACKET;

	// Find out which index in Linux the interface belongs to
	reth0_sockaddr.sll_ifindex = if_nametoindex(ROUTER_IN0_NAME);

	// Specify header length is Ethernet header length (6 bytes)
	reth0_sockaddr.sll_halen = ETH_ALEN;

	reth1_sockaddr.sll_family  = AF_PACKET;
	reth1_sockaddr.sll_ifindex = if_nametoindex(ROUTER_IN1_NAME);
	reth1_sockaddr.sll_halen   = ETH_ALEN;

	printf("Two NIC interfaces are set up (%d) and (%d)\n", reth0_sockaddr.sll_ifindex, reth1_sockaddr.sll_ifindex);

	printf("Listening...\n");

	while (1) {
		ssize_t len =
			recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_sockaddr, &addrlen);

		if (len < 0) {
			perror("recvfrom");

			break;
		}

		packet_handler(buffer, len, &recv_sockaddr);
	}

	return 0;
}

static void packet_handler(const uint8_t* packet, ssize_t len, struct sockaddr_ll* recv_sockaddr) {
	const struct ether_header *eth_hdr = (struct ether_header*)packet;

	if (!is_dest_mac_broadcast(eth_hdr->ether_dhost) && !is_dest_mac_match(eth_hdr->ether_dhost, recv_sockaddr)) {
		// printf("The Ethernet packet is neither a broadcast packet nor matching the receiving interface. Drop it\n");
		return;
	}

	uint16_t ether_type = ntohs(eth_hdr->ether_type);

	switch (ether_type) {
		case ETHER_TYPE_IPV4:
			handle_ipv4_packet(packet, len);
			break;
		case ETHER_TYPE_IPV6:
			handle_ipv6_packet(packet, len);
			break;
		case ETHER_TYPE_ARP:
			handle_arp_packet(packet, len);
			break;
		case ETHER_TYPE_VLAN:
			handle_vlan_packet(packet, len);
			break;
		default:
			printf("Unsupported EtherType 0x%04x, dropping packet\n", ether_type);
	}
}

// Check if the incoming packet is a broadcast
static bool is_dest_mac_broadcast(const uint8_t* mac) {
	for (uint8_t i = 0; i < ETH_ALEN; ++i) if (mac[i] != 0xFF) return false;

	return true;
}

// Check if the incoming packet is meant for this interface
static bool is_dest_mac_match(const uint8_t* mac, struct sockaddr_ll* recv_sockaddr) {
	const uint8_t* interface_mac;

	if (recv_sockaddr->sll_ifindex == reth0_sockaddr.sll_ifindex) {
		interface_mac = reth0_mac;
	} else if (recv_sockaddr->sll_ifindex == reth1_sockaddr.sll_ifindex) {
		interface_mac = reth1_mac;
	} else {
		printf("Wrong interface argument. Interface Index = %d\n", recv_sockaddr->sll_ifindex);

		return false;
	}

	for (uint8_t i = 0; i < ETH_ALEN; ++i) if (mac[i] != interface_mac[i]) return false;

	return true;
}

static void handle_ipv4_packet(const uint8_t* packet, ssize_t len) {
	// if (!verify_checksum(packet)) {
	// 	return;
	// }

	struct iphdr *ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));

	// printf("IPv4 protocol = %u\n", ip_hdr->protocol);

	// Check TTL
	if (ip_hdr->ttl <= 1) {
		// Expired
		return;
	}

	uint32_t dest_ip = ntohl(ip_hdr->daddr);

	route_t* route = routing_table_lookup(dest_ip);

	if (route == NULL) {
		return;
	}

	arp_entry_t *arp_entry = NULL;
	uint32_t target_ip = route->next_hop == 0 ? dest_ip : route->next_hop;

	arp_entry = get_arp_entry(target_ip);

	if (arp_entry == NULL) {
		arp_entry = create_empty_arp_entry(target_ip, ARP_EMPTY);
	}

	if (arp_entry->state == ARP_EMPTY) {
		// Send ARP request
		if (!send_arp_request(target_ip, route->interface)) {
			arp_entry->state = ARP_FAILED;

			return;
		}

		add_packet_to_queue(arp_entry, packet, len, route->interface);

		arp_entry->state = ARP_PENDING;
	} else if (arp_entry->state == ARP_PENDING) {
		// Still waiting for response from target host
		// Add packet to queue for processing later
		add_packet_to_queue(arp_entry, packet, len, route->interface);
	} else if (arp_entry->state == ARP_FAILED) {
		// Failed to obtain MAC address from target host
		// Drop packet since host is unreachable
		// TODO: Send host unreachble
		return;
	} else {
		// printf("Found ARP entry for ip (%u.%u.%u.%u) - MAC: ",
		// 	(dest_ip >> 24) & 0xFF,
		// 	(dest_ip >> 16) & 0xFF,
		// 	(dest_ip >> 8) & 0xFF,
		// 	dest_ip & 0xFF
		// );

		// for (uint8_t i = 0; i < ETH_ALEN; ++i) {
		// 	printf("%02x:", arp_entry->mac[i]);
		// }

		// printf("\n");

		// MAC address is good to use
		uint8_t *new_packet = (uint8_t*)malloc(len);

		if (new_packet == NULL) {
			fprintf(stderr, "Memory allocation failed\n");

			return;
		}

		memcpy(new_packet, packet, len);

		struct ether_header *new_eth_hdr = (struct ether_header*)new_packet;

		struct iphdr *new_ip_hdr = (struct iphdr*)(new_packet + sizeof(struct ether_header));

		new_ip_hdr->ttl--;
		new_ip_hdr->check = 0;
		new_ip_hdr->check = compute_ip_checksum(new_ip_hdr, new_ip_hdr->ihl * 4);

		memcpy(new_eth_hdr->ether_shost, route->inteface_MAC, ETH_ALEN);

		memcpy(new_eth_hdr->ether_dhost, arp_entry->mac, ETH_ALEN);

		// Attach destination MAC to sockaddr_ll
		struct sockaddr_ll send_addr = *route->interface;

		memcpy(send_addr.sll_addr, arp_entry->mac, ETH_ALEN);

		ssize_t sent = sendto(sock,
                      new_packet,
                      len,
                      0,
                      (struct sockaddr *)&send_addr,
                      sizeof(send_addr));

		if (sent < 0) {
			perror("sent");

			free(new_packet);

			return;
		}

		free(new_packet);
	}
}

static void handle_ipv6_packet(const uint8_t* packet, ssize_t len) {
	printf("No supported for ipv6\n");
}

static void handle_vlan_packet(const uint8_t* packet, ssize_t len) {
	printf("No supported for VLAN\n");
}

static void handle_arp_packet(const uint8_t* packet, ssize_t len) {
	const struct arp_packet *arp_pkt = (const struct arp_packet*)(packet + sizeof(struct ether_header));

	uint32_t src_ip = ntohl(arp_pkt->spa);

	// Check if this is a ARP reply or request
	uint16_t op = ntohs(arp_pkt->oper);

	if (op == 2) {
		arp_entry_t *arp_entry = get_arp_entry(src_ip);

		if (arp_entry == NULL) {
			return;
		}

		memcpy(arp_entry->mac, arp_pkt->sha, ETH_ALEN);

		flush_pending_packets(arp_entry);

		arp_entry->state = ARP_RESOLVED;
	} else if (op == 1) {
		send_arp_response(packet);
	} else {
		printf("Not supported ARP operation (op = %d)\n", op);
	}
}

static bool verify_checksum(const uint8_t* packet) {
	struct iphdr *ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));

	uint16_t received_checksum = ntohs(ip_hdr->check);

	uint16_t computed_checksum = compute_ip_checksum(ip_hdr, ip_hdr->ihl * 4);

	return received_checksum == ntohs(computed_checksum);
}

static uint16_t compute_ip_checksum(const void* packet, ssize_t len) {
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

static route_t* routing_table_lookup(const uint32_t dest_ip) {
	for (uint16_t i = 0; i < 3; ++i) {
		route_t route = routing_table[i];

		// printf("dest + mask = 0x%08x | net = 0x%08x\n", dest_ip & route.mask, route.net);

		if ((dest_ip & route.mask) == route.net) {
			return &routing_table[i];
		}
	}

	return NULL;
}

static arp_entry_t* get_arp_entry(const uint32_t ip) {
	for (uint16_t i = 0; i < ARP_CACHE_SIZE; ++i) {
		if (arp_cache[i].ip == ip && arp_cache[i].valid == 1) {
			return &arp_cache[i];
		}
	}

	return NULL;
}

static bool send_arp_request(const uint32_t target_ip, const struct sockaddr_ll* out_interface) {
	size_t len = sizeof(struct ether_header) + sizeof(struct arp_packet);

	uint8_t packet[len];

	struct ether_header* eth_hdr = (struct ether_header*)packet;
	struct arp_packet* arp = (struct arp_packet*)(packet + sizeof(struct ether_header));

	for (int i = 0; i < ETH_ALEN; ++i) eth_hdr->ether_dhost[i] = 0xFF; // broadcast

	uint8_t* src_mac = NULL;
	uint32_t src_ip = 0;

	if (out_interface == &reth0_sockaddr) {
		src_mac = reth0_mac;
		src_ip = IN0_IP_ADDRESS;
	}
	else if (out_interface == &reth1_sockaddr) {
		src_mac = reth1_mac;
		src_ip = IN1_IP_ADDRESS;
	}
	else {
		return false;
	}

	for (int i = 0; i < ETH_ALEN; ++i) eth_hdr->ether_shost[i] = src_mac[i];

	eth_hdr->ether_type = htons(ETHER_TYPE_ARP);

	arp->htype = htons(1); // Ethernet
	arp->ptype = htons(ETHER_TYPE_IPV4);
	arp->hlen = 6; // MAC addr length
	arp->plen = 4; // ipv4 address length
	arp->oper = htons(1); // ARP request
	arp->spa = htonl(src_ip);
	arp->tpa = htonl(target_ip);

	for (int i = 0; i < ETH_ALEN; ++i) {
		arp->sha[i] = src_mac[i];
		arp->tha[i] = 0;
	}

	struct sockaddr_ll send_addr = *out_interface;

	memcpy(send_addr.sll_addr, eth_hdr->ether_dhost, ETH_ALEN);

	ssize_t sent = sendto(sock, packet, len, 0, (struct sockaddr*)&send_addr, sizeof(send_addr));

	if (sent < 0) {
		perror("sent");

		return false;
	}

	return true;
}

static bool send_arp_response(const uint8_t* arp_request) {
	size_t len = sizeof(struct ether_header) + sizeof(struct arp_packet);

	uint8_t arp_response[len];

	memcpy(arp_response, arp_request, sizeof(struct ether_header) + sizeof(struct arp_packet));

	struct ether_header *eth_hdr = (struct ether_header*)arp_request;
	struct arp_packet *arp = (struct arp_packet*)(arp_request + sizeof(struct ether_header));

	for (uint8_t i = 0; i < ETH_ALEN; ++i) eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];

	uint8_t* response_mac = NULL;
	uint32_t requested_ip = ntohs(arp->tpa);
	uint32_t requester_ip = ntohs(arp->spa);
	struct sockaddr_ll out_interface = { 0 };

	if (requested_ip == IN0_IP_ADDRESS) {
		response_mac = reth0_mac;

		out_interface = reth0_sockaddr;
	} else if (requested_ip == IN1_IP_ADDRESS) {
		response_mac = reth1_mac;

		out_interface = reth1_sockaddr;
	} else {
		// printf("The requested ip 0x%08x does not match any router IPs\n", requested_ip);

		return false;
	}

	arp->oper = htons(2); // reply

	// Target MAC address is the requester's MAC address
	for (uint8_t i = 0; i < ETH_ALEN; ++i) arp->tha[i] = arp->sha[i];

	// Source MAC address is the interface MAC address
	for (uint8_t i = 0; i < ETH_ALEN; ++i) arp->sha[i] = response_mac[i];

	// Router IP
	arp->spa = htonl(requested_ip);

	// Destination IP is the requester IP
	arp->tpa = requester_ip;

	memcpy(out_interface.sll_addr, eth_hdr->ether_dhost, ETH_ALEN);

	ssize_t sent = sendto(sock, arp_response, len, 0, (struct sockaddr*)&out_interface, sizeof(out_interface));

	if (sent < 0) {
		perror("sent");

		return false;
	}

	return true;
}

static arp_entry_t* create_empty_arp_entry(const uint32_t ip, const arp_state_t init_state) {
	int pos = -1;

	for (int i = 0; i < ARP_CACHE_SIZE; ++i) {
		if (arp_cache[i].valid == false) {
			pos = i;
			break;
		}
	}

	if (pos == -1) {
		// Cache is full
		// Evict the first non-pending entry
		for (int i = 0; i < ARP_CACHE_SIZE; ++i) {
			if (arp_cache[i].state != ARP_PENDING) {
				pos = i;
				break;
			}
		}

		if (pos != -1) {
			remove_arp_entry(&arp_cache[pos]);
		}
	}

	if (pos == -1) {
		// There are no entry that is non-pending
		// TODO: do sth with this case
		return NULL;
	}

	arp_cache[pos].ip = ip;
	arp_cache[pos].state = init_state;
	arp_cache[pos].valid = true;

	return &arp_cache[pos];
}

static void add_packet_to_queue(arp_entry_t* arp_entry, const uint8_t* packet, const ssize_t len, const struct sockaddr_ll* out_interface) {
	pending_packet_t* new_pending_packet = (pending_packet_t*)malloc(sizeof(pending_packet_t));

	if (new_pending_packet == NULL) {
		fprintf(stderr, "Allocation failed\n");

		return;
	}

	new_pending_packet->len = len;
	new_pending_packet->out_interface = out_interface;
	memcpy(new_pending_packet->packet, packet, len);

	pending_packet_t* head = arp_entry->pending_packets;

	if (head == NULL) {
		arp_entry->pending_packets = new_pending_packet;
	} else {
		pending_packet_t* current = head;

		while (current->next != NULL) current = current->next;

		current->next = new_pending_packet;
	}

	arp_entry->pending_packets_count++;
}

static void remove_arp_entry(arp_entry_t* entry) {
	entry->valid = false;
	entry->pending_packets_count = 0;

	// Clear the pending packets
	pending_packet_t* current = entry->pending_packets;

	while (current != NULL) {
		pending_packet_t* next = current->next;

		free(current);

		current = next;
	}

	entry->state = ARP_EMPTY;
}

static void flush_pending_packets(arp_entry_t* arp) {
	pending_packet_t* current = arp->pending_packets;
	pending_packet_t* next = NULL;

	uint8_t* packet = NULL;
	uint8_t* src_mac = NULL;

	struct sockaddr_ll send_addr;

	while (current != NULL) {
		next = current->next;

		packet = current->packet;

		struct ether_header *eth_hdr = (struct ether_header*)packet;

		struct iphdr *ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));

		ip_hdr->ttl--;

		ip_hdr->check = 0;

		ip_hdr->check = compute_ip_checksum(ip_hdr, ip_hdr->ihl * 4);

		if (current->out_interface == &reth0_sockaddr) {
			src_mac = reth0_mac;
		} else if (current->out_interface == &reth1_sockaddr) {
			src_mac = reth1_mac;
		} else {
			printf("Invalid interface\n");

			// Drop this packet
			free(current);

			current = next;

			break;
		}

		memcpy(eth_hdr->ether_shost, src_mac, ETH_ALEN);

		memcpy(eth_hdr->ether_dhost, arp->mac, ETH_ALEN);

		send_addr = *current->out_interface;

		memcpy(send_addr.sll_addr, arp->mac, ETH_ALEN);

		ssize_t sent = sendto(sock, packet, current->len, 0, (struct sockaddr*)&send_addr, sizeof(send_addr));

		if (sent < 0) {
			perror("sent");
		}

		free(current);

		current = next;
	}

	arp->pending_packets_count = 0;
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