#ifndef __ARP_H_
#define __ARP_H_

#include <net/ethernet.h>

#include "queue.h"
#include "interface.h"

#ifndef ARP_CACHE_SIZE
#define ARP_CACHE_SIZE 10
#endif

typedef enum {
	ARP_EMPTY,
	ARP_PENDING,
	ARP_RESOLVED,
	ARP_FAILED
} arp_state_t;

typedef struct arp_entry {
	uint32_t ip;
	uint8_t mac[ETH_ALEN];
	uint8_t valid;
	arp_state_t state;
	packet_queue_t* queue;
} arp_entry_t;

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

int handle_arp_packet(ppacket_t* ppkt, int socket);

arp_entry_t* alloc_arp_entry(const uint32_t ip, arp_state_t init_state);

int send_arp_request(const uint32_t target_ip, interface_t* out_interace, int socket);

int send_arp_response(ppacket_t* arp_ppkt, int socket);

arp_entry_t* get_arp_entry(const uint32_t ip);

void init_arp_packet_queue(arp_entry_t* arp_entry);

void add_packet_to_arp_queue(arp_entry_t* arp_entry, const ppacket_t* ppkt);
#endif