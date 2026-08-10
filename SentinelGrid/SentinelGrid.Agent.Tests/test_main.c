#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "buffer_codec.h"
#include "event_codec.h"
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

int main(void) {
	printf("SentinelGrig Agent Tests start\n\n");

	testEventTypeValidation();
	testSerializationRoundTrip();
	testInvalidCodecArgument();
	testCircularBufferWrapAround();

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