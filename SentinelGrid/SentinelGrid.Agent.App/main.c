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

int main(void) {
	printf("SentinelGrid agent started\n");

	SecurityEvent heartbeat = {
		1U,
		1ULL,
		EVENT_HEARTBEAT
	};

	uint8_t bytes[EVENT_PACKET_SIZE] = { 0 };
	SecurityEvent decodedEvent = { 0 };

	if (!encodeEventPacket(&heartbeat, bytes, sizeof bytes)) {
		printf("Unable to encode event packet.\n");
		return 1;
	}

	printBytes(bytes, sizeof bytes);

	if (!decodeEventPacket(bytes, EVENT_PACKET_SIZE, &decodedEvent)) {
		printf("Unable to decode event packet.\n");
		return 1;
	}

	printEvent(&decodedEvent);

	return 0;
}