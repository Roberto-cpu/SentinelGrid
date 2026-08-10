/*
 * @author: Roberto Garzone
 * @date: 08 aug 2026
 *
 * @description: This code defines the security events management logic to monitor the agent functioning.
 */

#include <stdio.h>

#include "security_event.h"
#include "event_codec.h"
#include "buffer_codec.h"
#include "packet_codec.h"
#include "tcp_client.h"

int main(void) {
	printf("SentinelGrid agent started\n");

	SecurityEvent heartbeat = {
		1U,
		1ULL,
		EVENT_HEARTBEAT
	};

	uint8_t packet[EVENT_PACKET_SIZE] = { 0 };
	
	if (!encodeEventPacket(&heartbeat, packet, sizeof packet)) {
		printf("Unable to encode event packet.\n");
		return 1;
	}
	
	printBytes(packet, sizeof packet);

	TcpClient client = { 0 };
	initTcpClient(&client);

	if (!tcpClientConnect(&client, "127.0.0.1", 5050U)) {
		printf("Unable to connect to the engine.\n");
		tcpClientClose(&client);
		return 1;
	}

	if (!tcpClientSendAll(&client, packet, sizeof packet)) {
		printf("Unable to send the packet.\n");
		tcpClientClose(&client);
		return 1;
	}

	printf("Packet correctly sent.\n");
	tcpClientClose(&client);

	/*if (!decodeEventPacket(bytes, EVENT_PACKET_SIZE, &decodedEvent)) {
		printf("Unable to decode event packet.\n");
		return 1;
	}*/

	//printEvent(&decodedEvent);

	return 0;
}