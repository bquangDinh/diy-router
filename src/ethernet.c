#include "ethernet.h"
#include "interface.h"
#include "utils.h"

#include <arpa/inet.h>
#include <stdio.h>

static bool is_mac_broadcast(const uint8_t* mac);

static bool is_dest_mac_match_recv_interface(const uint8_t* mac, const uint16_t recv_interface);

bool should_process_frame(const ppacket_t* ppkt) {
	const uint8_t* packet = ppkt->packet;
	const uint16_t recv_interface = ppkt->recv_interface_idx;

	const struct ether_header *eth_hdr = (struct ether_header*)packet;

	const uint8_t* dest_mac = eth_hdr->ether_dhost;

	// TODO: do something with the case if mac is broadcast
	return !is_mac_broadcast(dest_mac) && is_dest_mac_match_recv_interface(dest_mac, recv_interface);
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
		if (mac[i] != interface->mac[i]) return false;
	}

	return true;
}
