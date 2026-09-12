/**
 * @file event_codec.c
 * @brief Implementation of event serialization and deserialization for the SentinelGrid Agent.
 *
 * This file contains the implementation of functions to serialize and deserialize security events, as well as utility functions for printing events and byte arrays.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include "../../include/agent/codecs/event_codec.h"

#include <stdio.h>

int serializeEvent(const SecurityEvent* event, uint8_t* output, size_t outputSize) {
	if (event == NULL || output == NULL)
		return 0;

	if (outputSize < SERIALIZED_EVENT_SIZE)
		return 0;

	if (!isValidEventType(event->type))
		return 0;

	output[0] = (uint8_t)((event->agent_id >> 24) & 0xFF);
	output[1] = (uint8_t)((event->agent_id >> 16) & 0xFF);
	output[2] = (uint8_t)((event->agent_id >> 8) & 0xFF);
	output[3] = (uint8_t)(event->agent_id & 0xFF);

	output[4] = (uint8_t)((event->sequence_number >> 56) & 0xFF);
	output[5] = (uint8_t)((event->sequence_number >> 48) & 0xFF);
	output[6] = (uint8_t)((event->sequence_number >> 40) & 0xFF);
	output[7] = (uint8_t)((event->sequence_number >> 32) & 0xFF);
	output[8] = (uint8_t)((event->sequence_number >> 24) & 0xFF);
	output[9] = (uint8_t)((event->sequence_number >> 16) & 0xFF);
	output[10] = (uint8_t)((event->sequence_number >> 8) & 0xFF);
	output[11] = (uint8_t)(event->sequence_number & 0xFF);

	output[12] = (uint8_t)((event->type >> 24) & 0xFF);
	output[13] = (uint8_t)((event->type >> 16) & 0xFF);
	output[14] = (uint8_t)((event->type >> 8) & 0xFF);
	output[15] = (uint8_t)(event->type & 0xFF);

	return 1;
}

int deserializeEvent(const uint8_t* input, size_t size, SecurityEvent* event) {
	if (input == NULL || event == NULL)
		return 0;

	if (size < SERIALIZED_EVENT_SIZE)
		return 0;

	uint32_t agent_id =
		((uint32_t)input[0] << 24) |
		((uint32_t)input[1] << 16) |
		((uint32_t)input[2] << 8) |
		((uint32_t)input[3]);

	uint64_t sequence =
		((uint64_t)input[4] << 56) |
		((uint64_t)input[5] << 48) |
		((uint64_t)input[6] << 40) |
		((uint64_t)input[7] << 32) |
		((uint64_t)input[8] << 24) |
		((uint64_t)input[9] << 16) |
		((uint64_t)input[10] << 8) |
		((uint64_t)input[11]);

	uint32_t type =
		((uint32_t)input[12] << 24) |
		((uint32_t)input[13] << 16) |
		((uint32_t)input[14] << 8) |
		((uint32_t)input[15]);

	if (type != (uint32_t)EVENT_HEARTBEAT && type != (uint32_t)EVENT_LOGIN_FAILED && type != (uint32_t)EVENT_SERVICE_STOP)
		return 0;

	SecurityEvent decodedEvent = {
		.agent_id = agent_id,
		.sequence_number = sequence,
		.type = (EventType)type
	};

	*event = decodedEvent;

	return 1;
}

void printEvent(const SecurityEvent* event) {
	if (event == NULL)
		return;

	printf(
		"[*] Agent=%u, Sequence=%llu, EventType=%s\n",
		(unsigned)event->agent_id,
		(unsigned long long) event->sequence_number,
		eventTypeToString(event->type)
	);
}

void printBytes(const uint8_t* bytes, size_t size) {
	for (size_t idx = 0; idx < size; idx++)
		printf("[*] %02X ", bytes[idx]);

	printf("\n");
}