#ifndef PACKET_CODEC_H
#define PACKET_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "../codecs/event_codec.h"
#include "../codecs/security_event.h"

#define PACKET_MAGIC		0x53475244U
#define PROTOCOL_VERSION	1U
#define PACKET_HEADER_SIZE	8U

#define EVENT_PACKET_SIZE (PACKET_HEADER_SIZE + SERIALIZED_EVENT_SIZE)

// Authenticated Packet
#define PROTOCOL_VERSION_V2		  0x0002U
#define KEY_ID_SIZE				  4U
#define HMAC_SHA256_SIZE		  32U
#define AUTHENTICATED_DATA_SIZE	  28U
#define AUTHENTICATED_PACKET_SIZE 60U

/*
 * @brief Encodes the event data to be sent as TCP packet
 * @param event: the event to encode
 * @param output: the resulting bytes array
 * @param outputSize: the array dimension
 * @returns 1 if the encoding succedes; 0 otherwise
 */
int encodeEventPacket(const SecurityEvent* event, uint8_t* output, size_t outputSize);

/*
 * @brief Encodes the event data to be sent as TCP packet with authentication
 *		logic
 * @param event: the event to encode
 * @param output: the resulting bytes array
 * @param outputSize: the array dimension
 * @returns 1 if the encoding succedes; 0 otherwise
 */
int encodeAuthenticatedEvent(
	const SecurityEvent* event, uint32_t keyId, const uint8_t* key,
	size_t keyLength, uint8_t output[AUTHENTICATED_PACKET_SIZE]
);

/*
 * @brief Decodes a received bytes array into the associated event data
 * @param input: the received bytes array
 * @param inputSize: the array dimension
 * @param: event: the memory address in which store the decoded data
 * @returns 1 if the packet is decoded; 0 otherwise
 */
int decodeEventPacket(const uint8_t* input, size_t inputSize, SecurityEvent* event);

#endif // !PACKET_CODEC_H
