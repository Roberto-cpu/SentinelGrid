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
	
	SecurityEvent login_failed = {
		1U,
		2ULL,
		EVENT_LOGIN_FAILED
	};
	
	SecurityEvent service_stop = {
		1U,
		3ULL,
		EVENT_SERVICE_STOP
	};

	uint8_t packet_h[EVENT_PACKET_SIZE] = { 0 };
	uint8_t packet_l[EVENT_PACKET_SIZE] = { 0 };
	uint8_t packet_s[EVENT_PACKET_SIZE] = { 0 };
	
	TcpClient client = { 0 };
	initTcpClient(&client);

	if (!tcpClientConnect(&client, "127.0.0.1", 5050U)) {
		printf("Unable to connect to the engine.\n");
		tcpClientClose(&client);
		return 1;
	}

	if (!encodeEventPacket(&heartbeat, packet_h, sizeof packet_h)) {
		printf("Unable to encode event packet.\n");
		return 1;
	}

	if (!tcpClientSendAll(&client, packet_h, sizeof packet_h)) {
		printf("Unable to send the packet.\n");
		tcpClientClose(&client);
		return 1;
	}

	printf("Heartbeat packet correctly sent.\n");

	if (!encodeEventPacket(&login_failed, packet_l, sizeof packet_l)) {
		printf("Unable to encode event packet.\n");
		return 1;
	}

	if (!tcpClientSendAll(&client, packet_l, sizeof packet_l)) {
		printf("Unable to send the packet.\n");
		tcpClientClose(&client);
		return 1;
	}

	printf("Login failed packet correctly sent.\n");

	if (!encodeEventPacket(&service_stop, packet_s, sizeof packet_s)) {
		printf("Unable to encode event packet.\n");
		return 1;
	}

	if (!tcpClientSendAll(&client, packet_s, sizeof packet_s)) {
		printf("Unable to send the packet.\n");
		tcpClientClose(&client);
		return 1;
	}

	printf("Service stop packet correctly sent.\n");

	tcpClientClose(&client);
	return 0;
}