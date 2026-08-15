#pragma once

#include <stdint.h>

typedef struct {
	uint32_t agent_id;
} AgentOptions;

int parseAgentOptions(int argc, char* argv[], AgentOptions* options);