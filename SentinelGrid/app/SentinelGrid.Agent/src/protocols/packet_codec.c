/**
 * @file packet_codec.c
 * @brief Implementation of packet encoding and decoding for the SentinelGrid Agent.
 *
 * This file contains the implementation of functions to encode and decode security event packets, including authenticated packets with HMAC SHA-256.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include "../../include/agent/protocols/packet_codec.h"
#include <security/security.h>

#include <Windows.h>
#include <stdio.h>

int encodeEventPacket(const SecurityEvent* event, uint8_t* output, size_t outputSize) {
	if (event == NULL || output == NULL)
		return 0;

	if (outputSize < EVENT_PACKET_SIZE)
		return 0;

	if (!serializeEvent(event, output + PACKET_HEADER_SIZE, outputSize - PACKET_HEADER_SIZE))
		return 0;

	output[0] = (uint8_t)(PACKET_MAGIC >> 24);
	output[1] = (uint8_t)(PACKET_MAGIC >> 16);
	output[2] = (uint8_t)(PACKET_MAGIC >> 8);
	output[3] = (uint8_t)(PACKET_MAGIC);

	output[4] = (uint8_t)(PROTOCOL_VERSION >> 8);
	output[5] = (uint8_t)(PROTOCOL_VERSION);
	
	output[6] = (uint8_t)(SERIALIZED_EVENT_SIZE >> 8);
	output[7] = (uint8_t)(SERIALIZED_EVENT_SIZE);

	return 1;
}

int encodeAuthenticatedEvent(const SecurityEvent* event, uint32_t keyId, const uint8_t* key,
	size_t keyLength, uint8_t output[AUTHENTICATED_PACKET_SIZE]) 
{
	if (event == NULL || key == NULL || output == NULL)
		return 0;

	if (keyLength == 0)
		return 0;

	SecureZeroMemory(output, AUTHENTICATED_PACKET_SIZE);

	if (!serializeEvent(event, output + PACKET_HEADER_SIZE, SERIALIZED_EVENT_SIZE))
		goto failure;

	output[0] = (uint8_t)(PACKET_MAGIC >> 24);
	output[1] = (uint8_t)(PACKET_MAGIC >> 16);
	output[2] = (uint8_t)(PACKET_MAGIC >> 8);
	output[3] = (uint8_t)PACKET_MAGIC;

	output[4] = (uint8_t)(PROTOCOL_VERSION_V2 >> 8);
	output[5] = (uint8_t)PROTOCOL_VERSION_V2;

	output[6] = (uint8_t)(AUTHENTICATED_EVENT_SIZE >> 8);
	output[7] = (uint8_t)AUTHENTICATED_EVENT_SIZE;

	output[EVENT_PACKET_SIZE]	   = (uint8_t)(keyId >> 24);
	output[EVENT_PACKET_SIZE + 1U] = (uint8_t)(keyId >> 16);
	output[EVENT_PACKET_SIZE + 2U] = (uint8_t)(keyId >> 8);
	output[EVENT_PACKET_SIZE + 3U] = (uint8_t)keyId;

	if (!calculateHMacSha256(key, keyLength, output, AUTHENTICATED_DATA_SIZE, output + AUTHENTICATED_DATA_SIZE)) {
		goto failure;
	}

	return 1;

	failure:
		SecureZeroMemory(output, AUTHENTICATED_PACKET_SIZE);
		return 0;
}

int decodeEventPacket(const uint8_t* input, size_t inputSize, SecurityEvent* event) {
	if (input == NULL || event == NULL)
		return 0;

	if (inputSize < EVENT_PACKET_SIZE)
		return 0;

	uint32_t magic =
		((uint32_t)input[0] << 24) |
		((uint32_t)input[1] << 16) |
		((uint32_t)input[2] << 8) |
		((uint32_t)input[3]);

	if (magic != PACKET_MAGIC)
		return 0;

	uint32_t protocol =
		((uint32_t)input[4] << 8) |
		((uint32_t)input[5]);

	if (protocol != PROTOCOL_VERSION)
		return 0;

	uint32_t payload =
		((uint32_t)input[6] << 8) |
		((uint32_t)input[7]);

	if (payload != SERIALIZED_EVENT_SIZE)
		return 0;

	SecurityEvent tempDecodedEvent = { 0 };

	if (!deserializeEvent(input + PACKET_HEADER_SIZE, inputSize - PACKET_HEADER_SIZE, &tempDecodedEvent))
		return 0;

	*event = tempDecodedEvent;
	return 1;
}