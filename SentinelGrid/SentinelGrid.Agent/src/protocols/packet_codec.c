#include "../../include/agent/protocols/packet_codec.h"

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