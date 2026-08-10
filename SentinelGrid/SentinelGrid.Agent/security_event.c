#include "security_event.h"

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