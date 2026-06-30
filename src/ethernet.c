#include "ethernet.h"
#include "interface.h"
#include "utils.h"
#include "telemetry.h"

#include <arpa/inet.h>
#include <stdio.h>

static bool is_mac_broadcast(const uint8_t* mac);

static bool is_dest_mac_match_recv_interface(const uint8_t* mac, const uint16_t recv_interface);

bool should_process_frame(const ppacket_t* ppkt) {
	if (ppkt->pkttype == PACKET_OUTGOING) {
		increase_ethernet_outgoing_count();

        return false;
    }

	if (ppkt->pkttype == PACKET_OTHERHOST) {
		increase_ethernet_otherhost_count();

        return false;
    }

	const uint8_t* packet = ppkt->packet;
	const uint16_t recv_interface = ppkt->recv_interface_idx;

	const struct ether_header *eth_hdr = (struct ether_header*)packet;

	const uint8_t* dest_mac = eth_hdr->ether_dhost;

	if (is_mac_broadcast(dest_mac)) {
		// Check if this is ARP request for the router
		if (get_eth_type(packet) == ETHER_TYPE_ARP) {
			return true;
		}

		increase_ethernet_broadcast_nonarp_count();

		return false;
	}

	if (!is_dest_mac_match_recv_interface(dest_mac, recv_interface)) {
		increase_ethernet_mistmatch_count();

		return false;
	}

	return true;
}

uint16_t get_eth_type(const uint8_t* packet) {
	const struct ether_header *eth_hdr = (struct ether_header*)packet;

	return ntohs(eth_hdr->ether_type);
}

static bool is_mac_broadcast(const uint8_t* mac) {
	for (uint8_t i = 0; i < ETH_ALEN; ++i) {
		if (mac[i] != 0xFF) return false;
	}

	return true;
}

static bool is_dest_mac_match_recv_interface(const uint8_t* mac, const uint16_t recv_interface) {
	const interface_t* interface = get_interface_from_idx(recv_interface);


	for (uint8_t i = 0; i < ETH_ALEN; ++i) {
		if (mac[i] != interface->mac[i]) {
			// printf("Dest MAC: ");

			// print_mac_addr(mac);

			// printf(" != ");

			// print_mac_addr(interface->mac);

			// printf("\n");

			return false;
		}
	}

	return true;
}
