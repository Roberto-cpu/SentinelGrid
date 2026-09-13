#pragma once

/*
 * @file windows_agent_sequence_store.h
 * @brief Provides persistent sequence-number management for SentinelGrid agents.
 * 
 * This module reserves monotonically increasing sequence number and stores the latest reserved value
 * in the Windows Registry.
 * The counter preservetion prevents an agent from reusing sequence number after a process or system restart,
 * allowing the engine to successfully detect replayed authenticated packets.
 * 
 * @note The implementation of the key loading function is expected to be provided in a
 *	     corresponding source file (e.g., windows_agent_sequence_store.c).
 *
 * @author Roberto Garzone
 * @date 2026-09-08
 */

#include <stdint.h>

#ifdef _cplusplus
extern "C" {
#endif

/*
	* @brief Describes the result of the sequence number reservation 
	*/
typedef enum AgentSequenceStatus {
	AGENT_SEQUENCE_SUCCESS,
	AGENT_SEQUENCE_INVALID_INPUT,
	AGENT_SEQUENCE_EXHAUSTED,
	AGENT_SEQUENCE_PLATFORM_FAILURE
} AgentSequenceStatus;

/*
	* @brief Contains the reservation result and the eventual generated error code 
	*/
typedef struct AgentSequenceResult {
	AgentSequenceStatus status;
	uint32_t native_error_code;
} AgentSequenceResult;

/*
	* @brief Automatically reservers the next sequence number for an agent.
	* 
	* Reads the last sequence number stored for the specified agent, increments it
	* and persists the new sequence number before returning to its caller.
	* 
	* The destination is cleared before the operation, receiving a non-zero sequence
	* number only when the status is AGENT_SEQUENCE_SUCCESS.
	* 
	* Concurrent lookup, increment and update operations must be protected by the same
	* synchronization lock to prevent duplicate reservations.
	* 
	* @param agentId - non-zero agent identifier whose sequence number is reservecd
	* @param destination - pointer to receive the newly reserved sequence number
	* @returns - the struct containing the operation status and the eventual error code
	*/
AgentSequenceResult reserveNextAgentSequence(uint32_t agentId, uint64_t* destination);

#ifdef _cplusplus
}
#endif