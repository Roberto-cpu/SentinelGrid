#pragma once

/**
 * @file event_codec.h
 * @brief This header file defines functions for encoding and decoding security events.
 *
 * The functions in this header file provide functionality to serialize and deserialize security events,
 * as well as to print event data and byte arrays for debugging purposes.
 *
 * @note The implementation of the encoding and decoding functions is expected to be provided in a corresponding source file (e.g., event_codec.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#ifndef EVENT_CODEC_H
#define EVENT_CODEC_H

#include <stdlib.h>
#include <stddef.h>

#include "security_event.h"

#define SERIALIZED_EVENT_SIZE	 16U
#define AUTHENTICATED_EVENT_SIZE 52U

/*
 * @brief Serializes a given event data into a given bytes array of a 16 byte length
 * @param event: the event to serialize
 * @param output: the bytes array that will contain the serialization result
 * @param outputSize: the array dimension (at least 16)
 * @returns 1 if the serialization succedes; 0 otherwise
 */
int serializeEvent(const SecurityEvent* event, uint8_t* output, size_t outputSize);

/*
 * @brief Deserializes a given bytes array containing the event's data.
 *		The deserialization result is stored into a specified memory address
 * @param input: the bytes array
 * @param size: the array dimension
 * @param event: the address memory in which store the deserialized data
 * @returns 1 if the deserialization succedes; 0 otherwise
 */
int deserializeEvent(const uint8_t* input, size_t size, SecurityEvent* event);

/*
 * @brief Displays the data associated to a given event.
 *		The event type is displayed as string ('Heartbeat', 'Login Failed',
 *		'Service Stop'), by calling eventTypeToString function
 * @param event: the data to display
 */
void printEvent(const SecurityEvent* event);

/*
 * @brief Displays the serializad event's data as bytes.
 * @param bytes: the bytes array to iterate
 * @param size: the array dimension
 */
void printBytes(const uint8_t* bytes, size_t size);

#endif // !EVENT_CODEC_H