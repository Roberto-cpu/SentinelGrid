#pragma once

/**
 * @file windows_angent_key_store.h
 * @brief This header file defines functions for loading the agent key from the Windows key store.
 *
 * The functions in this header file provide functionality to load the agent key from the Windows key store,
 * handling various error conditions and returning appropriate status codes.
 *
 * @note The implementation of the key loading function is expected to be provided in a 
 *	     corresponding source file (e.g., windows_agent_key_store.c).
 *
 * @author Roberto Garzone
 * @date 2026-09-08
 */

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#ifdef _cplusplus
extern "C" {
#endif

#define SENTINELGRID_AGENT_KEY_SIZE 32U

	/*
	 * @brief Enumerates the possible statuses for loading the agent key from the Windows key store.
	 *
	 * The enumeration defines various statuses that can be returned when attempting to load the agent key,
	 * including success, invalid input, not found, invalid size, access denied, and platform failure.
	 */
	typedef enum AgentKeyLoadStatus {
		AGENT_KEY_LOAD_SUCCESS,
		AGENT_KEY_LOAD_INVALID_INPUT,
		AGENT_KEY_LOAD_NOT_FOUND,
		AGENT_KEY_LOAD_INVALID_SIZE,
		AGENT_KEY_LOAD_ACCESS_DENIED,
		AGENT_KEY_LOAD_PLATFORM_FAILURE
	} AgentKeyLoadStatus;
	
	/*
	 * @brief Structure representing the result of loading the agent key from the Windows key store.
	 *
	 * The structure contains the status of the load operation and the native error code, if applicable.
	 */
	typedef struct AgentKeyLoadResult {
		AgentKeyLoadStatus status;
		uint32_t native_error_code;
	} AgentKeyLoadResult;

	/*
	 * @brief Loads the agent key from the Windows key store.
	 *
	 * This function attempts to load the agent key from the specified target in the Windows key store.
	 * It fills the provided destination buffer with the loaded key if successful.
	 *
	 * @param target The target identifier for the agent key in the Windows key store.
	 * @param destination The buffer where the loaded agent key will be stored.
	 * @param destination_size The size of the destination buffer. Must be at least SENTINELGRID_AGENT_KEY_SIZE bytes.
	 * @return An AgentKeyLoadResult structure containing the status of the load operation and any native error code.
	 */
	AgentKeyLoadResult loadAgentKey(const wchar_t *target, uint8_t *destination, size_t destination_size);

	/*
	 * @brief Securely erases the agent key from memory.
	 *
	 * This function securely erases the agent key from the provided memory buffer, ensuring that sensitive data is not left in memory.
	 *
	 * @param key The buffer containing the agent key to be erased.
	 * @param key_size The size of the key buffer. Must be at least SENTINELGRID_AGENT_KEY_SIZE bytes.
	 */
	void secureEraseAngetKey(uint8_t* key, size_t key_size);

#ifdef _cplusplus
}
#endif
