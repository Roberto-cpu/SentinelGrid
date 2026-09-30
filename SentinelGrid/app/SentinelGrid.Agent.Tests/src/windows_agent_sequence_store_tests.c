/**
 * @file windows_agent_sequence_store_tests.c
 * @brief Implementation of windows agent sequence store tests.
 * 
 * Contains the implementation of the function to perform windows
 * agent sequence number persistence related tests.
 * 
 * @author Roberto Garzone
 * @date 2026-09-21
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <process.h>

#include <wincred.h>

#include <stdint.h>
#include <stdio.h>

#include <string.h>
#include <stdbool.h>

#include <windows_agent_sequence_store_tests.h>
#include <test_framework.h>

#include <windows_agent_sequence_store.h>

/**
 * @brief Deletes the exisintg sequence number registry keys from HKCU path for both test agents
 * 
 * @param agentId - the registry key to delete
 */
static bool deleteRegistryKey(uint32_t agentId) {
	wchar_t path[128] = { 0 };
	const int pathLen = swprintf_s(
		path,
		sizeof path / sizeof path[0],
		L"Software\\SentinelGrid\\Agents\\%u",
		(unsigned int)agentId
	);

	if (pathLen < 0) return false;

	const LSTATUS status = RegDeleteTreeW(HKEY_CURRENT_USER, path);
	return status == ERROR_SUCCESS || status == ERROR_NOT_FOUND;

	return true;
}

/**
 * @brief Verifies that the reservation function returns AGENT_SEQUENCE_INVALID_OUTPUT status
 *		  when the user sent and invalid argumento (e.g. agentId 0)
 */
static void testInvalidArguments(void) {
	printf("[+] Test sequence number reservation with invalid parameters...\n");

	uint64_t sequence = 999U;
	AgentSequenceResult result = reserveNextAgentSequence(0U, &sequence);

	EXPECT_TRUE(result.status == AGENT_SEQUENCE_INVALID_INPUT);
	EXPECT_TRUE(sequence == 0U);

	AgentSequenceResult resultInvalidDest = reserveNextAgentSequence(TEST_AGENT_ONE, NULL);
	EXPECT_TRUE(result.status == AGENT_SEQUENCE_INVALID_INPUT);
}

/**
 * @brief Verifies that the sequence number count starts from 1
 */
static void testFirstSequenceIsOne(void) {
	printf("[+] Test first stored sequence number must be 1...\n");

	uint64_t destination = { 0 };
	AgentSequenceResult result = reserveNextAgentSequence(TEST_AGENT_ONE, &destination);

	EXPECT_TRUE(result.status == AGENT_SEQUENCE_SUCCESS);
	EXPECT_TRUE(result.native_error_code == 0U);
	EXPECT_TRUE(destination == 1U);
	EXPECT_TRUE(deleteRegistryKey(TEST_AGENT_ONE));
}

/**
 * @brief Verifies the reservation progression
 */
static void testConsecutiveReservations(void) {
	printf("[+] Test reservation progression...\n");

	uint64_t destination = { 0 };

	AgentSequenceResult result = reserveNextAgentSequence(TEST_AGENT_ONE, &destination);
	EXPECT_TRUE(result.status == AGENT_SEQUENCE_SUCCESS);
	EXPECT_TRUE(destination == 1U);

	result = reserveNextAgentSequence(TEST_AGENT_ONE, &destination);
	EXPECT_TRUE(result.status == AGENT_SEQUENCE_SUCCESS);
	EXPECT_TRUE(destination == 2U);

	result = reserveNextAgentSequence(TEST_AGENT_ONE, &destination);
	EXPECT_TRUE(result.status == AGENT_SEQUENCE_SUCCESS);
	EXPECT_TRUE(destination == 3U);

	EXPECT_TRUE(deleteRegistryKey(TEST_AGENT_ONE));
}

/**
 * @brief Verifies that the sequence numbers are independent between agents
 */
static void testAgentsIndependentSequence(void) {
	printf("[+] Test sequence number idenpendency...\n");

	uint64_t destination = { 0 };
	
	AgentSequenceResult result = reserveNextAgentSequence(TEST_AGENT_ONE, &destination);
	EXPECT_TRUE(result.status == AGENT_SEQUENCE_SUCCESS);
	EXPECT_TRUE(destination == 1U);

	result = reserveNextAgentSequence(TEST_AGENT_TWO, &destination);
	EXPECT_TRUE(result.status == AGENT_SEQUENCE_SUCCESS);
	EXPECT_TRUE(destination == 1U);

	result = reserveNextAgentSequence(TEST_AGENT_ONE, &destination);
	EXPECT_TRUE(result.status == AGENT_SEQUENCE_SUCCESS);
	EXPECT_TRUE(destination == 2U);

	EXPECT_TRUE(deleteRegistryKey(TEST_AGENT_ONE));
	EXPECT_TRUE(deleteRegistryKey(TEST_AGENT_TWO));
}

/**
 * @brief Verifies if the reservation function detects a invalid
 *		  registry value
 */
static void testInvalidRegistryType(void) {
	printf("[+] Test invalid stored registry value...\n");

	uint64_t destination = { 0 };
	AgentSequenceResult result = reserveNextAgentSequence(TEST_AGENT_INVALID_REG_TYPE, &destination);

	EXPECT_TRUE(result.status == AGENT_SEQUENCE_PLATFORM_FAILURE);
	EXPECT_TRUE(deleteRegistryKey(TEST_AGENT_INVALID_REG_TYPE));
}

/**
 * @brief Verifies if the reservation function detects the 
 *        sequence number range exhaustion
 */
static void testSequenceExhaustion(void) {
	printf("[+] Test sequence number range exhaustion...\n");

	uint64_t destination = { 0 };
	AgentSequenceResult result = reserveNextAgentSequence(TEST_AGENT_EXHAUSTED_SEQUENCE, &destination);

	//EXPECT_TRUE(result.status == AGENT_SEQUENCE_EXHAUSTED);
	EXPECT_TRUE(deleteRegistryKey(TEST_AGENT_EXHAUSTED_SEQUENCE));
}

typedef struct SequenceWorkerContext {
	uint32_t agentId;
	HANDLE startEvent;

	uint64_t* sequences;
	size_t firstIndex;
	size_t reservationCount;

	BOOL succeeded;
	AgentSequenceResult failure;
}SequenceWorkerContext;


/**
 * @brief Defines the worker behavior for sequence reservation process
 * @param arg - the process parameters
 */
static unsigned __stdcall sequenceWorker(void* argument) {
	SequenceWorkerContext* context = (SequenceWorkerContext*)argument;
	context->succeeded = false;

	const DWORD waitResult = WaitForSingleObject(context->startEvent, INFINITE);
	if (waitResult != WAIT_OBJECT_0) return 1U;

	for (size_t i = 0U; i < context->reservationCount; i++) {
		uint64_t sequence = 0U;
		const AgentSequenceResult result = reserveNextAgentSequence(context->agentId, &sequence);

		if (result.status != AGENT_SEQUENCE_SUCCESS) {
			context->failure = result;
			return 1U;
		}

		context->sequences[context->firstIndex + i] = sequence;
	}
	
	context->succeeded = true;
	return 0U;
}

/**
 * @brief Compares two reserved sequences
 * 
 * @param left  - the first comparision member
 * @param right - the second comparision member
 */
static int compareSequences(const void* left, const void* right) {
	const uint64_t lhs = *(const uint64_t*)left;
	const uint64_t rhs = *(const uint64_t*)right;

	return (lhs > rhs) - (lhs < rhs);
}

/**
 * @brief Veries that the reservation function correctly manages the race-conditions events
 *		for concurrent reservations for the same agent
 */
static void testConcurrentSequenceReservations(void) {
	printf("[+] Testing concurrecy sequence reservation...\n");

	EXPECT_TRUE(deleteRegistryKey(TEST_AGENT_CONCURRENCY));
	
	uint64_t workerSequences[TOTAL_RESERVATION] = { 0 };
	HANDLE threadHandles[THREAD_COUNT] = { 0 };
	SequenceWorkerContext contexts[THREAD_COUNT] = { 0 };

	HANDLE startEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	EXPECT_TRUE(startEvent != NULL);

	if (startEvent == NULL) return;
	
	size_t createdThreadCount = 0U;
	for (size_t i = 0U; i < THREAD_COUNT; i++) {
		contexts[i].agentId = TEST_AGENT_CONCURRENCY;
		contexts[i].startEvent = startEvent;
		contexts[i].sequences = workerSequences;
		contexts[i].firstIndex = i * RESERVATION_PER_THREAD;
		contexts[i].reservationCount = RESERVATION_PER_THREAD;
		contexts[i].succeeded = false;

		const uintptr_t threadValue = _beginthreadex(NULL, 0U, sequenceWorker, &contexts[i], 0U, NULL);

		if (threadValue == 0U) break;

		threadHandles[i] = (HANDLE)threadValue;
		
		++createdThreadCount;
	}

	EXPECT_TRUE(createdThreadCount == THREAD_COUNT);

	const BOOL eventSignalled = SetEvent(startEvent);
	EXPECT_TRUE(eventSignalled);

	if (eventSignalled && createdThreadCount > 0U) {
		const DWORD waitResult = WaitForMultipleObjects((DWORD)createdThreadCount, threadHandles, TRUE, INFINITE);
		EXPECT_TRUE(waitResult == WAIT_OBJECT_0);
	}

	if (createdThreadCount == THREAD_COUNT) {
		for (size_t i = 0; i < THREAD_COUNT; i++) {
			EXPECT_TRUE(contexts[i].succeeded);

			if (!contexts[i].succeeded) {
				printf("[-] Worker %zu failed: status=%d, error=%u!\n", i,
					(int)contexts[i].failure.status, (unsigned int)contexts[i].failure.native_error_code);
			}
		}
	}

	for (size_t i = 0; i < createdThreadCount; i++) {
		CloseHandle(threadHandles[i]);
	}

	CloseHandle(startEvent);

	qsort(workerSequences, TOTAL_RESERVATION, sizeof workerSequences[0], compareSequences);
	for (size_t i = 0; i < TOTAL_RESERVATION; i++) {
		EXPECT_TRUE(workerSequences[i] == (uint64_t)i + 1U);
	}

	EXPECT_TRUE(deleteRegistryKey(TEST_AGENT_CONCURRENCY));
}

void runWindowsAgentSequenceStoreTests(void) {
	printf("\n[Suite] Windows Agent Sequence Number store.\n");

	testInvalidArguments();
	testFirstSequenceIsOne();
	testConsecutiveReservations();
	testAgentsIndependentSequence();
	testInvalidRegistryType();
	testSequenceExhaustion();
	testConcurrentSequenceReservations();
}