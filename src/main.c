#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#include "utils.h"
#include "pool.h"
#include "ring_buffer.h"
#include "ethernet.h"
#include "ipv4.h"
#include "arp.h"
#include "vlan.h"
#include "ipv6.h"
#include "interface.h"
#include "route_conf.h"
#include "telemetry.h"

int SOCK = 0;

// static packet_queue_t rx_queue = { 0 };

static rx_ring_t* rx_ring = NULL;

static void packet_handler(ppacket_t* ppkt);

static void* worker_thread(void* arg);

static void* telemetry_worker_thread(void* arg);

int main() {
	struct sockaddr_ll recv_sockaddr = { 0 };

	socklen_t addrlen = sizeof(recv_sockaddr);

	SOCK = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (SOCK < 0) {
		perror("socket");

		return -1;
	}

	int rcvbuf = 16 * 1024 * 1024;

	if (setsockopt(SOCK, SOL_SOCKET, SO_RCVBUF,
				&rcvbuf, sizeof(rcvbuf)) < 0) {
		perror("SO_RCVBUF");

		return -1;
	}

	printf("Init rx ring buffer...\n");

	rx_ring = create_ring_buffer(AF_PACKET_BUFFER_NUM_PACKETS);

	if (rx_ring == NULL) {
		return -1;
	}

	printf("Init pool...\n");

	init_packet_pool();

	printf("Init interface...\n");

	init_interface();

	printf("Init route config...\n");

	init_route_config();

	printf("Init worker thread...\n");

	pthread_t worker;

	if (pthread_create(&worker, NULL, worker_thread, NULL) != 0) {
		perror("pthread_create");

		return -1;
	}

	printf("Init telemetry...\n");

	pthread_t telemetry_worker;

	if (pthread_create(&telemetry_worker, NULL, telemetry_worker_thread, NULL) != 0) {
		perror("pthread_create");

		return -1;
	}

	printf("Listening...\n");

	ssize_t len = 0;

	ppacket_t* ppkt = NULL;

	ppacket_t* discarded_placeholder = (ppacket_t*)malloc(sizeof(ppacket_t));

	if (discarded_placeholder == NULL) {
		perror("malloc");

		return -1;
	}

	while (1) {
		ppkt = packet_pool_alloc();

		if (ppkt == NULL) {
			recvfrom(SOCK, discarded_placeholder, 1600, 0, (struct sockaddr*)&recv_sockaddr, &addrlen);

			increase_discarded_count();

			continue;
		}

		len = recvfrom(SOCK, ppkt->packet, 1600, 0, (struct sockaddr*)&recv_sockaddr, &addrlen);

		if (len < 0) {
			perror("recvfrom");

			break;
		}

		ppkt->len = len;

		ppkt->recv_interface_idx = recv_sockaddr.sll_ifindex;

		ppkt->pkttype = recv_sockaddr.sll_pkttype;

		increase_rx_count();

		// Queue this packet for processing
		// enqueue(&rx_queue, ppkt);

		if (!rx_ring_enqueue(rx_ring, ppkt)) {
			increase_pool_ring_full_drop();

			free_packet(ppkt);

			continue;
		}
	}

	pthread_join(worker, NULL);

	pthread_join(telemetry_worker, NULL);

	return 0;
}

static void* worker_thread(void* arg) {
	(void)arg;

	ppacket_t* packet = NULL;

	while (1) {
		// Dequeue the packet
		// packet = dequeue(&rx_queue);
		packet = rx_ring_dequeue(rx_ring);

		if (packet == NULL) {
			// yield
			sched_yield();

			continue;
		}

		// Perform routing, ARP, etc here
		packet_handler(packet);

		// Give it back to the pool after finished processing packet
		free_packet(packet);
	}

	return NULL;
}

static void* telemetry_worker_thread(void* arg) {
	while (1) {
		sleep(1); // wake up every second

		print_metrics();
	}

	return NULL;
}

static void packet_handler(ppacket_t* ppkt) {
#if ENABLE_DEBUGGING
	print_ppkt_info(ppkt);
#endif

	if (!should_process_frame(ppkt)) {
#if ENABLE_DEBUGGING
		printf("Ethernet frame invalid. Drop packet\n");
#endif

		return;
	}

	uint16_t eth_type = get_eth_type(ppkt->packet);

	switch (eth_type) {
		case ETHER_TYPE_IPV4:
#if ENABLE_DEBUGGING
		printf("Received an ipv4 packet\n");
#endif
			increase_ipv4_count();

			handle_ipv4_packet(ppkt, SOCK);
			break;
		case ETHER_TYPE_IPV6:
#if ENABLE_DEBUGGING
		printf("Received an ipv6 packet\n");
#endif
			handle_ipv6_packet(ppkt, SOCK);
			break;
		case ETHER_TYPE_ARP:
#if ENABLE_DEBUGGING
		printf("Received an ARP packet\n");
#endif
			increase_arp_count();

			handle_arp_packet(ppkt, SOCK);
			break;
		case ETHER_TYPE_VLAN:
#if ENABLE_DEBUGGING
		printf("Received an VLAN packet\n");
#endif
			handle_vlan_packet(ppkt, SOCK);
			break;
		default:
#if ENABLE_DEBUGGING
		printf("Unsupported protocol. Drop packet\n");
#endif
	}
}