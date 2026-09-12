/**
 * @file buffer_codec.c
 * @brief Implementation of the circular buffer for security events.
 *
 * This file contains the implementation of a circular buffer to store security events in a fixed-size array.
 * It provides functions to initialize the buffer, add events, remove the oldest event, print the buffer contents,
 * and destroy the buffer.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include "../../include/agent/codecs/buffer_codec.h"
#include "../../include/agent/codecs/event_codec.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

int initializeBuffer(EventBuffer* buffer, size_t capacity) {
	if (buffer == 0 || capacity == 0)
		return 0;

	if (capacity > SIZE_MAX / sizeof * buffer->items)
		return 0;

	buffer->items = calloc(capacity, sizeof * buffer->items);

	if (buffer->items == NULL)
		return 0;

	buffer->head = 0;
	buffer->tail = 0;
	buffer->capacity = capacity;
	buffer->count = 0;

	return 1;
}

int addEvent(EventBuffer* buffer, SecurityEvent event) {
	if (buffer == NULL || buffer->items == NULL)
		return 0;

	if (buffer->count >= buffer->capacity)
		return 0;

	buffer->items[buffer->tail] = event;
	buffer->tail = (buffer->tail + 1) % buffer->capacity;

	buffer->count++;

	return 1;
}

int removeOldestEvent(EventBuffer* buffer, SecurityEvent* removedEvent) {
	if (buffer == NULL || removedEvent == NULL)
		return 0;

	if (buffer->count == 0) {
		printf("[-] Unable to remove items: the buffer is empty\n");
		return 0;
	}

	*removedEvent = buffer->items[buffer->head];
	buffer->head = (buffer->head + 1) % buffer->capacity;

	buffer->count--;
	//buffer->items[buffer->count] = (SecurityEvent){ 0 };
	return 1;
}

void printBuffer(const EventBuffer* buffer) {
	if (buffer == NULL || buffer->items == NULL)
		return;

	printf(
		"\n[*] Events buffer: %zu/%zu events\n",
		buffer->count,
		buffer->capacity
	);

	size_t index = buffer->head;
	for (size_t i = 0; i < buffer->count; i++) {
		printEvent(&buffer->items[index]);
		index = (index + 1) % buffer->capacity;
	}
}

void destroyBuffer(EventBuffer* buffer) {
	if (buffer == NULL)
		return;

	free(buffer->items);

	buffer->items = NULL;
	buffer->capacity = 0;
	buffer->count = 0;
	buffer->head = 0;
	buffer->tail = 0;
}