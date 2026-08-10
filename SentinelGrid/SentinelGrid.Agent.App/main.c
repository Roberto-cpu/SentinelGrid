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

int main(void) {
	//EventBuffer buffer = { 0 };
	//SecurityEvent removedEvent = { 0 };

	printf("SentinelGrid agent started\n");

	/*if (!initializeBuffer(&buffer, 3)) {
		fprintf(stderr, "Unable to allocate events buffer space.\n");
		return 1;
	}*/

	SecurityEvent heartbeat = {
		1U,
		1ULL,
		EVENT_HEARTBEAT
	};

	uint8_t bytes[SERIALIZED_EVENT_SIZE] = { 0 };
	SecurityEvent deserializedEvent = { 0 };

	/*SecurityEvent failedLogin = {
		1U,
		2ULL,
		EVENT_LOGIN_FAILED
	};

	SecurityEvent serviceStop = {
		1U,
		3ULL,
		EVENT_SERVICE_STOP
	};

	SecurityEvent extra = {
		1U,
		4ULL,
		EVENT_HEARTBEAT
	};

	SecurityEvent heartbeat_1 = {
		1U,
		5ULL,
		EVENT_HEARTBEAT
	};

	SecurityEvent failedLogin_1 = {
		1U,
		6ULL,
		EVENT_LOGIN_FAILED
	};


	addEvent(&buffer, heartbeat);
	addEvent(&buffer, failedLogin);
	addEvent(&buffer, serviceStop);

	if (removeOldestEvent(&buffer, &removedEvent)) {
		printf("Oldest event removed\n");
		printEvent(&removedEvent);
	}

	if (!addEvent(&buffer, extra))
		printf("Event \"extra\" rejected: the buffer is full.\n");

	if (removeOldestEvent(&buffer, &removedEvent)) {
		printf("Oldest event removed\n");
		printEvent(&removedEvent);
	}

	if (removeOldestEvent(&buffer, &removedEvent)) {
		printf("Oldest event removed\n");
		printEvent(&removedEvent);
	}

	addEvent(&buffer, heartbeat_1);
	addEvent(&buffer, failedLogin_1);

	printBuffer(&buffer);
	destroyBuffer(&buffer);*/

	if (!serializeEvent(&heartbeat, bytes, sizeof bytes)) {
		printf("Unable to serialize event");
		return 1;
	}

	printBytes(bytes, sizeof bytes);

	if (!deserializeEvent(bytes, SERIALIZED_EVENT_SIZE, &deserializedEvent)) {
		printf("Unable to desiarialize event\n");
		return 1;
	}

	printEvent(&deserializedEvent);

	return 0;
}