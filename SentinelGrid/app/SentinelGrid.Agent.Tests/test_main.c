/*
 * @file test_main.c
 * @brief Unit tests for SentinelGrid Agent codecs and buffer management.
 *
 * This file contains unit tests for the SentinelGrid Agent, focusing on the validation of event types,
 * serialization and deserialization of security events, circular buffer management, packet encoding and decoding,
 * and HMAC SHA-256 encoding. The tests ensure that the agent's components function correctly and handle edge cases.
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <test_framework.h>
#include <event_codec_tests.h>
#include <buffer_codec_tests.h>
#include <packet_codec_tests.h>
#include <windows_agent_key_store_tests.h>

/**
 * @brief Main function to run all unit tests.
 *
 * This function serves as the entry point for the test suite. It runs all defined test functions and reports
 * the total number of tests executed and the number of failures. The program exits with a success or failure
 * status based on the test results.
 *
 * @return EXIT_SUCCESS if all tests pass, EXIT_FAILURE otherwise.
 */
int main(void) {
	printf("SentinelGrig Agent Tests start\n\n");

	runEventCodecTests();
	runBufferCodecTests();
	runPacketCodecTests();
	runWindowsAgentKeyStoreTests();

	printTestSummary();
	return EXIT_SUCCESS;
}