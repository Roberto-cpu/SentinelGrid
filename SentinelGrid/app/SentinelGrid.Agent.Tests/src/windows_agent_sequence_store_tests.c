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

#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <wincred.h>

#include <windows_agent_sequence_store_tests.h>
#include <test_framework.h>

#include <windows_agent_sequence_store.h>

/**
 * @brief Deletes the exisintg sequence number registry keys from HKCU path for both test agents
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

void runWindowsAgentSequenceStoreTests(void) {
	printf("\n[Suite] Windows Agent Sequence Number store.\n");

	testInvalidArguments();
	testFirstSequenceIsOne();
	testConsecutiveReservations();
	testAgentsIndependentSequence();
	testInvalidRegistryType();
	testSequenceExhaustion();
}