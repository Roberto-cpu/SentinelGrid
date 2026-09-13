/*
 * @file packet_codec_tests.c
 * @brief Implementation of packet codec related tests.
 *
 * This file contains the implementation of the container function
 * for the packet codec related tests.
 *
 * @author Roberto Garzone
 * @date 2026-09-12
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <test_framework.h>
#include <packet_codec_tests.h>

#include <agent/codecs/security_event.h>
#include <agent/protocols/packet_codec.h>

 /**
  * @brief Tests the encoding and decoding of event packets.
  *
  * This function tests the encoding and decoding of security event packets to ensure that the process is lossless.
  * It creates an original SecurityEvent, encodes it into a packet, then decodes it back and compares the original
  * and decoded events for equality.
  */
static void testPacketRoundTrip(void) {
	printf("[+] Test packet encoding round-trip...\n");

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
	printf("[+] Test invalid packet header...\n");

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
	printf("[+] Test truncated packet decoding...\n");

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
	printf("[+] Test MAC SHA-256 encoding...\n");

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

void runPacketCodecTests(void) {
	printf("\n[Suite] Running packet codec tests.\n");

	testPacketRoundTrip();
	testInvalidPacketHeader();
	testTruncatedPacket();
	testHMAC_SHA256Encoding();
}