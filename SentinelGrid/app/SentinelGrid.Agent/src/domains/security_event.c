/**
 * @file security_event.c
 * @brief Implementation of security event management logic for the SentinelGrid Agent.
 *
 * This file contains the implementation of functions related to security events, including validation and string representation of event types.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include "../../include/agent/codecs/security_event.h"

int isValidEventType(EventType type) {
	return type == EVENT_HEARTBEAT || 
		type == EVENT_LOGIN_FAILED || 
		type == EVENT_SERVICE_STOP;
}

const char* eventTypeToString(EventType type) {
	switch (type) {
		case EVENT_HEARTBEAT:
			return "Heartbeat";

		case EVENT_SERVICE_STOP:
			return "Service Stop";

		case EVENT_LOGIN_FAILED:
			return "Login Failed";

		default:
			return "Unknown Event Type";
	}
}