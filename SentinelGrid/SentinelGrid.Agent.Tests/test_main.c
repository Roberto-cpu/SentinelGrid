#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "buffer_codec.h"
#include "event_codec.h"
#include "packet_codec.h"
#include "security_event.h"

static int testCount = 0;
static int failCount = 0;

#define EXPECT_TRUE(condition)				\
	do {									\
		testCount++;						\
		if (!(condition)) {					\
			failCount++;					\
			printf(							\
				"[FAIL] Line %d: %s\n",		\
				__LINE__,					\
				#condition					\
			);								\
		}									\
	} while(0)								\

static void testEventTypeValidation(void) {
	printf("Testing event-type validation...\n");

	EXPECT_TRUE(isValidEventType(EVENT_HEARTBEAT));
	EXPECT_TRUE(isValidEventType(EVENT_LOGIN_FAILED));
	EXPECT_TRUE(isValidEventType(EVENT_SERVICE_STOP));

	EXPECT_TRUE(!isValidEventType((EventType)9));
	EXPECT_TRUE(!isValidEventType((EventType)100));
}

static void testSerializationRoundTrip(void) {
	printf("Testing serialiaztion round-trip...\n");

	SecurityEvent originalEvent = {
		42U,
		123456ULL,
		EVENT_LOGIN_FAILED
	};

	SecurityEvent decodedEvent = { 0 };
	uint8_t encodedEvent[SERIALIZED_EVENT_SIZE] = { 0 };

	EXPECT_TRUE(serializeEvent(&originalEvent, encodedEvent, sizeof encodedEvent));
	EXPECT_TRUE(deserializeEvent(encodedEvent, sizeof encodedEvent, &decodedEvent));

	EXPECT_TRUE(decodedEvent.agent_id == originalEvent.agent_id);
	EXPECT_TRUE(decodedEvent.sequence_number == originalEvent.sequence_number);
	EXPECT_TRUE(decodedEvent.type == originalEvent.type);
}

static void testInvalidCodecArgument(void) {
	printf("Testing codec arguments validity checks...\n");

	SecurityEvent event = {
		1U,
		1ULL,
		EVENT_HEARTBEAT
	};

	SecurityEvent decodedEvent = { 0 };
	uint8_t encodedEvent[SERIALIZED_EVENT_SIZE] = { 0 };

	EXPECT_TRUE(!serializeEvent(NULL, encodedEvent, sizeof encodedEvent));
	EXPECT_TRUE(!serializeEvent(&event, NULL, sizeof encodedEvent));
	EXPECT_TRUE(!serializeEvent(&event, encodedEvent, 15));

	EXPECT_TRUE(!deserializeEvent(NULL, sizeof encodedEvent, &decodedEvent));
	EXPECT_TRUE(!deserializeEvent(encodedEvent, sizeof encodedEvent, NULL));
	EXPECT_TRUE(!deserializeEvent(encodedEvent, 15, &decodedEvent));
}

static void testCircularBufferWrapAround(void) {
	printf("Test buffer round-trip...\n");

	EventBuffer buffer = { 0 };
	SecurityEvent removedEvent = { 0 };

	EXPECT_TRUE(initializeBuffer(&buffer, 3));

	SecurityEvent heartbeat = {
		1U,
		1ULL,
		EVENT_HEARTBEAT
	};

	SecurityEvent failedLogin = {
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

	addEvent(&buffer, heartbeat);
	addEvent(&buffer, failedLogin);
	addEvent(&buffer, serviceStop);

	EXPECT_TRUE(!addEvent(&buffer, extra));

	removeOldestEvent(&buffer, &removedEvent);
	EXPECT_TRUE(removedEvent.sequence_number == 1);

	addEvent(&buffer, extra);

	removeOldestEvent(&buffer, &removedEvent);
	EXPECT_TRUE(removedEvent.sequence_number == 2);

	removeOldestEvent(&buffer, &removedEvent);
	EXPECT_TRUE(removedEvent.sequence_number == 3);

	removeOldestEvent(&buffer, &removedEvent);
	EXPECT_TRUE(removedEvent.sequence_number == 4);

	EXPECT_TRUE(!removeOldestEvent(&buffer, &removedEvent));

	destroyBuffer(&buffer);
	EXPECT_TRUE(buffer.items == NULL);
	EXPECT_TRUE(buffer.head == 0);
	EXPECT_TRUE(buffer.tail == 0);
	EXPECT_TRUE(buffer.capacity == 0);
	EXPECT_TRUE(buffer.count == 0);
}

static void testPacketRoundTrip(void) {
	printf("Testing packet encoding round-trip...\n");

	SecurityEvent heartbeat = {
		1U,
		1ULL,
		EVENT_HEARTBEAT
	};

	uint8_t bytes[EVENT_PACKET_SIZE] = { 0 };
	SecurityEvent decodedEvent = { 0 };

	EXPECT_TRUE(encodeEventPacket(&heartbeat, bytes, sizeof bytes));
	EXPECT_TRUE(decodeEventPacket(bytes, sizeof bytes, &decodedEvent));

	EXPECT_TRUE(heartbeat.agent_id == decodedEvent.agent_id);
	EXPECT_TRUE(heartbeat.sequence_number == decodedEvent.sequence_number);
	EXPECT_TRUE(heartbeat.type == decodedEvent.type);
}

static void testInvalidPacketHeader(void) {
	printf("Testing invalid packet header...\n");

	SecurityEvent heartbeat = {
		1U,
		1ULL,
		EVENT_HEARTBEAT
	};

	uint8_t bytes[EVENT_PACKET_SIZE] = { 0 };

	encodeEventPacket(&heartbeat, bytes, sizeof bytes);

	bytes[0] ^= 0x10U;

	SecurityEvent protectedEvent1 = {
		100U,
		100ULL,
		EVENT_SERVICE_STOP
	};

	EXPECT_TRUE(!decodeEventPacket(bytes, sizeof bytes, &protectedEvent1));

	EXPECT_TRUE(protectedEvent1.agent_id == 100U);
	EXPECT_TRUE(protectedEvent1.sequence_number == 100ULL);
	EXPECT_TRUE(protectedEvent1.type == EVENT_SERVICE_STOP);

	EXPECT_TRUE(encodeEventPacket(&heartbeat, bytes, sizeof bytes));

	bytes[4] = 0U;
	bytes[5] = 2U;

	SecurityEvent protectedEvent2 = {
		200U,
		200ULL,
		EVENT_LOGIN_FAILED
	};

	EXPECT_TRUE(!decodeEventPacket(bytes, sizeof bytes, &protectedEvent2));

	EXPECT_TRUE(protectedEvent2.agent_id == 200U);
	EXPECT_TRUE(protectedEvent2.sequence_number == 200ULL);
	EXPECT_TRUE(protectedEvent2.type == EVENT_LOGIN_FAILED);

	EXPECT_TRUE(encodeEventPacket(&heartbeat, bytes, sizeof bytes));

	bytes[6] = 0U;
	bytes[7] = 15U;

	SecurityEvent protectedEvent3 = {
		300U,
		300ULL,
		EVENT_HEARTBEAT
	};

	EXPECT_TRUE(!decodeEventPacket(bytes, sizeof bytes, &protectedEvent3));

	EXPECT_TRUE(protectedEvent3.agent_id == 300U);
	EXPECT_TRUE(protectedEvent3.sequence_number == 300ULL);
	EXPECT_TRUE(protectedEvent3.type == EVENT_HEARTBEAT);
}

static void testTruncatedPacket(void) {
	printf("Testing truncated packet decoding...\n");

	SecurityEvent heartbeat = {
		1U,
		1ULL,
		EVENT_HEARTBEAT
	};

	uint8_t bytes[EVENT_PACKET_SIZE] = { 0 };
	SecurityEvent decodedEvent = { 0 };

	encodeEventPacket(&heartbeat, bytes, sizeof bytes);

	for (size_t size = 0; size < EVENT_PACKET_SIZE; size++)
		EXPECT_TRUE(!decodeEventPacket(bytes, size, &decodedEvent));
}

int main(void) {
	printf("SentinelGrig Agent Tests start\n\n");

	testEventTypeValidation();
	testSerializationRoundTrip();

	testInvalidCodecArgument();
	testCircularBufferWrapAround();

	testPacketRoundTrip();
	testInvalidPacketHeader();
	testTruncatedPacket();

	printf(
		"\nTests Completed: %d checks, %d failures\n",
		testCount,
		failCount
	);

	if (failCount == 0) {
		printf("[PASS] All tests passed.\n");
		return EXIT_SUCCESS;
	}

	printf("[FAIL] Some tests failed.\n");
	return EXIT_FAILURE;
}