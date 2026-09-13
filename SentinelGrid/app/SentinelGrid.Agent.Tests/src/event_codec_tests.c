/*
 * @file event_codec_tests.c
 * @brief Implementation of event codec related tests.
 *
 * This file contains the implementation of the container function 
 * for the event codec related tests.
 *
 * @author Roberto Garzone
 * @date 2026-09-12
 */

#include <stdint.h>
#include <stdio.h>

#include <event_codec_tests.h>
#include <test_framework.h>

#include <agent/codecs/event_codec.h>
#include <agent/codecs/security_event.h>

 /**
  * @brief Tests the validation of event types.
  *
  * This function tests the isValidEventType function to ensure that it correctly identifies valid and invalid event types.
  * It checks known valid event types and verifies that invalid event types are rejected.
  */
static void testEventTypeValidation(void) {
	printf("[+] Test event-type validation...\n");

	EXPECT_TRUE(isValidEventType(EVENT_HEARTBEAT));
	EXPECT_TRUE(isValidEventType(EVENT_LOGIN_FAILED));
	EXPECT_TRUE(isValidEventType(EVENT_SERVICE_STOP));

	EXPECT_TRUE(!isValidEventType((EventType)9));
	EXPECT_TRUE(!isValidEventType((EventType)100));
}

/**
 * @brief Tests the serialization and deserialization of security events.
 *
 * This function tests the serialization and deserialization of SecurityEvent structures to ensure that
 * the process is lossless. It creates an original SecurityEvent, serializes it, then deserializes it back
 * and compares the original and decoded events for equality.
 */
static void testSerializationRoundTrip(void) {
	printf("[+] Test serialiaztion round-trip...\n");

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

/**
 * @brief Tests the validity checks for codec arguments.
 *
 * This function tests the argument validation of serialization and deserialization functions to ensure that
 * they correctly handle null pointers and insufficient buffer sizes. It verifies that the functions return
 * false when provided with invalid arguments.
 */
static void testInvalidCodecArgument(void) {
	printf("[+] Test codec arguments validity checks...\n");

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

void runEventCodecTests(void) {
	printf("\n[Suite] Running event codec tests.\n");

	testEventTypeValidation();
	testSerializationRoundTrip();
	testInvalidCodecArgument();
}