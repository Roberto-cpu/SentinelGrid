/*
 * @file windows_angent_key_store.c
 * @brief This file contains the implementation of functions for loading the agent key from the Windows key store.
 * 
 * This implementation provides functionality to load the agent key from the Windows key store, 
 * handling various error conditions and returning appropriate status codes.
 * 
 * @author Roberto Garzone
 * @date 2026-09-08
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <wincred.h>
#include <string.h>

#include <windows_agent_key_store.h>

void secureEraseAngetKey(uint8_t* key, size_t key_size) { SecureZeroMemory(key, key_size); }

AgentKeyLoadResult loadAgentKey(const wchar_t* target, uint8_t* destination, size_t destination_size) {

	if (target == NULL || target[0] == L'\0' || destination == NULL || destination_size != SENTINELGRID_AGENT_KEY_SIZE) {
		if (destination != NULL && destination_size > 0) {
			secureEraseAngetKey(destination, destination_size);
		}

		return (AgentKeyLoadResult) {
			AGENT_KEY_LOAD_INVALID_INPUT, 
			ERROR_INVALID_PARAMETER 
		};
	}
	secureEraseAngetKey(destination, destination_size);

	PCREDENTIALW credential = NULL;
	if (!CredReadW(target, CRED_TYPE_GENERIC, 0U, &credential)) {
		DWORD errorCode = GetLastError();

		switch(errorCode) {
			case ERROR_NOT_FOUND:
				return (AgentKeyLoadResult) {
					AGENT_KEY_LOAD_NOT_FOUND,
					(size_t)errorCode
				};
				
			case ERROR_ACCESS_DENIED:
				return (AgentKeyLoadResult) {
					AGENT_KEY_LOAD_ACCESS_DENIED,
					(size_t)errorCode
				};

			default:
				return (AgentKeyLoadResult) {
					AGENT_KEY_LOAD_PLATFORM_FAILURE,
					(size_t)errorCode
				};
		}
	}

	AgentKeyLoadResult result = {
		AGENT_KEY_LOAD_INVALID_SIZE,
		ERROR_INVALID_DATA
	};

	if (credential->CredentialBlob == NULL ||
		credential->CredentialBlobSize != (DWORD)SENTINELGRID_AGENT_KEY_SIZE) {
		goto cleanup;
	}

	memcpy(
		destination,
		credential->CredentialBlob,
		destination_size
	);

	result.status = AGENT_KEY_LOAD_SUCCESS;
	result.native_error_code = ERROR_SUCCESS;

cleanup:
	CredFree(credential);
	credential = NULL;

	if (result.status != AGENT_KEY_LOAD_SUCCESS) {
		secureEraseAngetKey(destination, destination_size);
	}

	return result;
}