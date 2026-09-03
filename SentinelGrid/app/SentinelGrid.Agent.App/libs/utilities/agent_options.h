#pragma once

/**
 * @file agent_options.h
 * @brief This header file defines the AgentOptions structure and the parseAgentOptions function.
 *
 * The AgentOptions structure holds configuration options for the agent, including the agent ID.
 * The parseAgentOptions function is responsible for parsing command-line arguments to populate the AgentOptions structure.
 *
 * @note The implementation of the parseAgentOptions function is expected to be provided in a corresponding source file (e.g., agent_options.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <stdint.h>

 /**
  * @brief Structure to hold agent configuration options.
  *
  * The AgentOptions structure contains configuration options for the agent, including the agent ID.
  */
typedef struct {
	uint32_t agent_id;
} AgentOptions;

/**
 * @brief Parses command-line arguments to populate the AgentOptions structure.
 *
 * This function processes the command-line arguments provided to the agent application and extracts relevant configuration options,
 * such as the agent ID. It populates the provided AgentOptions structure with the parsed values.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line argument strings.
 * @param options A pointer to an AgentOptions structure to be populated with parsed values.
 * @return An integer indicating success (0) or failure (non-zero) of the parsing operation.
 */
int parseAgentOptions(int argc, char* argv[], AgentOptions* options);