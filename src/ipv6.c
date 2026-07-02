#include "ipv6.h"

int handle_ipv6_packet(const ppacket_t* ppkt, int socket) {
	(void)ppkt;
	(void)socket;

	// Not supported
	return -1;
}