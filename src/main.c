#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#include "queue.h"
#include "utils.h"
#include "pool.h"
#include "ethernet.h"
#include "ipv4.h"
#include "arp.h"
#include "vlan.h"
#include "ipv6.h"
#include "interface.h"
#include "route_conf.h"

int SOCK = 0;

static packet_queue_t rx_queue = { 0 };

static void packet_handler(ppacket_t* ppkt);

static void* worker_thread(void* arg);

int main() {
	struct sockaddr_ll recv_sockaddr = { 0 };

	socklen_t addrlen = sizeof(recv_sockaddr);

	SOCK = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (SOCK < 0) {
		perror("socket");

		return -1;
	}

	printf("Init rx queue...\n");

	init_queue(&rx_queue);

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

	printf("Listening...\n");

	ssize_t len = 0;

	while (1) {
		ppacket_t* ppkt = packet_pool_alloc();

		lock_plk(ppkt);

		len = recvfrom(SOCK, ppkt, sizeof(ppacket_t), 0, (struct sockaddr*)&recv_sockaddr, &addrlen);

		if (len < 0) {
			perror("recvfrom");

			break;
		}

		ppkt->len = len;

		ppkt->recv_interface_idx = recv_sockaddr.sll_ifindex;

		unlock_plk(ppkt);

		// Queue this packet for processing
		enqueue(&rx_queue, ppkt);

		// Signal the consumer to wake up and process packet
		sem_post(&rx_queue.rx_sem);
	}

	pthread_join(worker, NULL);

	return 0;
}

static void* worker_thread(void* arg) {
	(void)arg;

	ppacket_t* packet = NULL;

	while (1) {
		// Wait until there is a packet to process
		sem_wait(&rx_queue.rx_sem);

		// Dequeue the packet
		packet = dequeue(&rx_queue);

		lock_plk(packet);

		// Perform routing, ARP, etc here
		packet_handler(packet);

		unlock_plk(packet);

		// Give it back to the pool after finished processing packet
		free_packet(packet);
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