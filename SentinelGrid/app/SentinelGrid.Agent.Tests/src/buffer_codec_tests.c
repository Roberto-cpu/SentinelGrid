/*
 * @file buffer_codec_tests.c
 * @brief Implementation of buffer codec related tests.
 *
 * This file contains the implementation of the container function
 * for the buffer codec related tests.
 *
 * @author Roberto Garzone
 * @date 2026-09-12
 */

#include <stdio.h>

#include <buffer_codec_tests.h>
#include <test_framework.h>

#include <agent/codecs/buffer_codec.h>
#include <agent/codecs/security_event.h>

 /**
  * @brief Tests the circular buffer wrap-around behavior.
  *
  * This function tests the circular buffer implementation to ensure that it correctly handles wrap-around scenarios when adding events beyond its capacity.
  */
static void testCircularBufferWrapAround(void) {
	printf("[+] Test buffer round-trip...\n");

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

void runBufferCodecTests(void) {
	printf("\n[Suite] Running buffer codec tests.\n");

	testCircularBufferWrapAround();
}