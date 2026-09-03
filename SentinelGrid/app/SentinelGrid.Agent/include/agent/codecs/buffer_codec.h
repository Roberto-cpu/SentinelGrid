#pragma once

/**
 * @file buffer_codec.h
 * @brief This header file defines the interface for managing a circular buffer of security events.
 *
 * The functions in this header file provide functionality to initialize, add, remove, and manage a circular buffer
 * that holds security events. It also includes functions to print the buffer contents and deallocate its resources.
 *
 * @note The implementation of the buffer management functions is expected to be provided in a corresponding source file (e.g., buffer_codec.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#ifndef BUFFER_CODEC_H
#define BUFFER_CODEC_H

#include <stddef.h>
#include "security_event.h"

/*
 * @brief Defines the data associated to the events container
 * @param items: the list events
 * @param capacity: the max number of events allowed
 * @param count: the current number of events contained
 */
typedef struct {
	SecurityEvent* items;
	size_t head;
	size_t tail;
	size_t capacity;
	size_t count;
} EventBuffer;

/*
 * @brief Initializes the buffer object structure, by defining 
 *		its memory space and its capacity
 * @param buffer: the memory address in which store the buffer
 * @param capacity: the max number of items allowed
 * @returns 1 if the initialization succedes; 0 otherwise
 */
int initializeBuffer(EventBuffer* buffer, size_t capacity);

/*
 * @brief Appends a new security event into the buffer address
 *		space
 * @param buffer: the address location in which store the event
 * @param event: the event to append
 */
int addEvent(EventBuffer* buffer, SecurityEvent event);

/*
 * @brief Removes the first item of the given buffer and stores it into
 *		a given memory address
 * @param buffer: the buffer from which remove the item
 * @param removedEvent: the memory address in which store the removed item
 * @returns 1 if thw item is removed; 0 otherwise
 */
int removeOldestEvent(EventBuffer* buffer, SecurityEvent* removedEvent);

/*
 * @brief Displays all the contained events data from the given buffer
 * @param buffer: the data to display
 */
void printBuffer(const EventBuffer* buffer);

/*
 * @brief Deallocates the buffer references from the memory
 * @param buffer: the buffer to deallocate
 */
void destroyBuffer(EventBuffer* buffer);

#endif // !BUFFER_CODEC_H
