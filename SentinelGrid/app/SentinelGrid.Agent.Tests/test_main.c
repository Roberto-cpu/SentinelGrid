/*
 * @file test_main.c
 * @brief Unit tests for SentinelGrid Agent codecs and buffer management.
 *
 * This file contains unit tests for the SentinelGrid Agent, focusing on the validation of event types,
 * serialization and deserialization of security events, circular buffer management, packet encoding and decoding,
 * and HMAC SHA-256 encoding. The tests ensure that the agent's components function correctly and handle edge cases.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <agent/codecs/buffer_codec.h>
#include <agent/codecs/event_codec.h>
#include <agent/protocols/packet_codec.h>
#include <agent/codecs/security_event.h>

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

/**
 * @brief Tests the validation of event types.
 *
 * This function tests the isValidEventType function to ensure that it correctly identifies valid and invalid event types.
 * It checks known valid event types and verifies that invalid event types are rejected.
 */
static void testEventTypeValidation(void) {
	printf("Testing event-type validation...\n");

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

/**
 * @brief Tests the validity checks for codec arguments.
 *
 * This function tests the argument validation of serialization and deserialization functions to ensure that
 * they correctly handle null pointers and insufficient buffer sizes. It verifies that the functions return
 * false when provided with invalid arguments.
 */
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

/**
 * @brief Tests the circular buffer wrap-around behavior.
 *
 * This function tests the circular buffer implementation to ensure that it correctly handles wrap-around scenarios when adding events beyond its capacity.
 */
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

/**
 * @brief Tests the encoding and decoding of event packets.
 *
 * This function tests the encoding and decoding of security event packets to ensure that the process is lossless.
 * It creates an original SecurityEvent, encodes it into a packet, then decodes it back and compares the original
 * and decoded events for equality.
 */
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

/**
 * @brief Tests the decoding of packets with invalid headers.
 *
 * This function tests the decoding of security event packets with intentionally corrupted headers to ensure that
 * the decoder correctly identifies and rejects invalid packets. It verifies that the original event remains unchanged
 * after attempting to decode an invalid packet.
 */
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

/**
 * @brief Tests the decoding of truncated packets.
 *
 * This function tests the decoding of security event packets that are intentionally truncated to ensure that
 * the decoder correctly identifies and rejects incomplete packets. It verifies that the decoder returns false
 * for all truncated packet sizes.
 */
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

/**
 * @brief Tests the HMAC SHA-256 encoding of authenticated event packets.
 *
 * This function tests the encoding of authenticated security event packets using HMAC SHA-256 to ensure that
 * the generated MAC matches the expected value. It verifies that the encoding function returns success and
 * that the computed MAC is correct.
 */
static void testHMAC_SHA256Encoding() {
	printf("Testing MAC SHA-256 encoding...\n");

	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};

	SecurityEvent securityEvent = {
		1U,
		1UL,
		EVENT_SERVICE_STOP
	};

	uint8_t expetedMAC[HMAC_SHA256_SIZE] = {
		0xA5, 0x41, 0x4B, 0x2B,
		0x55, 0x00, 0x7B, 0xB8,
		0x12, 0x9D, 0xA7, 0xA3,
		0xFD, 0xCD, 0x05, 0x6B,
		0xE0, 0xBB, 0xC0, 0x1B,
		0x49, 0xA4, 0xFB, 0x3D,
		0xF7, 0x01, 0x27, 0x82,
		0xCC, 0xC6, 0x80, 0xCE
	};

	uint8_t output[AUTHENTICATED_PACKET_SIZE] = { 0 };
	int encoded = encodeAuthenticatedEvent(&securityEvent, 1U, key, sizeof(key), output);

	EXPECT_TRUE(encoded == 1);
	EXPECT_TRUE(memcmp(output + AUTHENTICATED_DATA_SIZE, expetedMAC, HMAC_SHA256_SIZE) == 0);
}

/**
 * @brief Main function to run all unit tests.
 *
 * This function serves as the entry point for the test suite. It runs all defined test functions and reports
 * the total number of tests executed and the number of failures. The program exits with a success or failure
 * status based on the test results.
 *
 * @return EXIT_SUCCESS if all tests pass, EXIT_FAILURE otherwise.
 */
int main(void) {
	printf("SentinelGrig Agent Tests start\n\n");

	testEventTypeValidation();
	testSerializationRoundTrip();

	testInvalidCodecArgument();
	testCircularBufferWrapAround();

	testPacketRoundTrip();
	testInvalidPacketHeader();
	testTruncatedPacket();

	testHMAC_SHA256Encoding();

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