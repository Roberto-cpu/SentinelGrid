/*
 * @file windows_agent_sequence_store.c
 * @brief Implementation of the agent sequence number function
 * 
 * This file contains the implementation of sequence number reservation function.
 * It provides function to reserver the next sequence number that a specified agent must use,
 * preventing packet replay protection to block valid packets.
 * 
 * @author Roberto Garzone
 * @date 2026-09-13
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <stdint.h>
#include <wchar.h>

#include <windows_agent_sequence_store.h>

static const wchar_t LAST_SEQUENCE_VALUE_NAME[] = L"LastSequence";

AgentSequenceResult reserveNextAgentSequence(uint32_t agentId, uint64_t* destination) {
	AgentSequenceResult result = {
		AGENT_SEQUENCE_PLATFORM_FAILURE,
		ERROR_GEN_FAILURE
	};
	
	HANDLE hMutex = NULL;
	HKEY hKey = NULL;
	BOOLEAN mutexAcquired = FALSE;

	wchar_t mutexName[96] = { 0 };
	wchar_t registryKey[128] = { 0 };

	if (destination == NULL) {
		printf("[-] Destination pointer cannot be NULL.\n");
		goto invalid_param;
	}

	if (agentId == 0U) {
		printf("[-] Agent ID must be a non-zero value.\n");
		goto invalid_param;
	}

	*destination = 0U;

	const int mutexNameLength = swprintf_s(
		mutexName,
		sizeof mutexName / sizeof mutexName[0],
		L"Local\\SentinelGrid.Agent.Sequence.%u",
		(unsigned int)agentId
	);

	if (mutexNameLength < 0) {
		printf("[-] Unable to store mutex name.\n");
		goto cleanup;
	}

	
	const int registryKeyLength = swprintf_s(
		registryKey,
		sizeof registryKey / sizeof registryKey[0],
		L"Software\\SentinelGrid\\Agents\\%u",
		(unsigned int)agentId
	);

	if (registryKeyLength < 0) {
		printf("[-] Unable to store registry key name.\n");
		goto cleanup;
	}

	hMutex = CreateMutexW(NULL, FALSE, mutexName);
	if (hMutex == NULL) {
		printf("[-] Unable to create mutex");

		result.native_error_code = GetLastError();
		goto cleanup;
	}

	const DWORD waitRes = WaitForSingleObject(hMutex, INFINITE);

	switch (waitRes) {
		case WAIT_OBJECT_0:
		case WAIT_ABANDONED:
			mutexAcquired = TRUE;
			break;

		case WAIT_FAILED:
			result.native_error_code = GetLastError();
			goto cleanup;

		default:
			goto cleanup;
	}

	LSTATUS regKeyRes = RegCreateKeyExW(
		HKEY_CURRENT_USER,
		registryKey,
		0U,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_QUERY_VALUE | KEY_SET_VALUE,
		NULL,
		&hKey,
		NULL
	);

	if (regKeyRes != ERROR_SUCCESS) {
		printf("[-] Unable to create or open registry key for agent %d", agentId);

		result.native_error_code = (uint32_t)regKeyRes;
		goto cleanup;
	}

	uint64_t currSequence = 0U;

	DWORD dwType = 0U;
	DWORD cbData = (DWORD)sizeof currSequence;

	regKeyRes = RegQueryValueExW(
		hKey,
		LAST_SEQUENCE_VALUE_NAME,
		0U,
		&dwType,
		(LPBYTE)&currSequence,
		&cbData
	);

	if (regKeyRes == ERROR_FILE_NOT_FOUND)
		currSequence = 0U;
	else if (regKeyRes != ERROR_SUCCESS) {
		printf("[-] Cannot read last sequence number registry value.\n");

		result.native_error_code = (uint32_t)regKeyRes;
		goto cleanup;
	}
	else if (dwType != REG_QWORD || cbData != sizeof currSequence) {
		printf("[-] Invalid registry key value.\n");

		result.native_error_code = ERROR_INVALID_DATA;
		goto cleanup;

	}

	if (currSequence == UINT64_MAX) {
		result.status = AGENT_SEQUENCE_EXHAUSTED;
		result.native_error_code = ERROR_ARITHMETIC_OVERFLOW;

		goto cleanup;
	}

	const uint64_t nextSequence = currSequence + 1U;
	
	regKeyRes = RegSetValueExW(
		hKey,
		LAST_SEQUENCE_VALUE_NAME,
		0,
		REG_QWORD,
		(const BYTE*)&nextSequence,
		(DWORD)sizeof nextSequence
	);

	if (regKeyRes != ERROR_SUCCESS) {
		printf("[-] Unable to store last sequence into registry key.\n");

		result.native_error_code = regKeyRes;
		goto cleanup;
	}

	*destination = nextSequence;

	result.status = AGENT_SEQUENCE_SUCCESS;
	result.native_error_code = 0U;
	goto cleanup;

invalid_param:
	result.status = AGENT_SEQUENCE_INVALID_INPUT;
	result.native_error_code = ERROR_INVALID_PARAMETER;

	return result;

cleanup:

	if (hKey != NULL)
		RegCloseKey(hKey);

	if (mutexAcquired) {
		if (!ReleaseMutex(hMutex) && result.status == AGENT_SEQUENCE_SUCCESS) {
			printf("[-] Unable to release mutex %s.\n", mutexName);

			result.status = AGENT_SEQUENCE_PLATFORM_FAILURE;
			result.native_error_code = GetLastError();
			
			*destination = 0U;
		}
	}

	if (hMutex != NULL) {
		if (!CloseHandle(hMutex) && result.status == AGENT_SEQUENCE_SUCCESS) {
			result.status = AGENT_SEQUENCE_PLATFORM_FAILURE;
			result.native_error_code = GetLastError();

			*destination = 0U;
		}
	}

	return result;
}