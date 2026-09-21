#pragma once

/**
 * @file windows_agent_sequence_store_tests.h
 * @brief Defines the container function for the sequence number registry key persistence tests
 *
 * @note The implementation of runWindowsAgentSequenceStoreTests function is expecte to be provided
 *		 in a corresponding source file (e.g. windows_agent_sequence_store_tests.c)
 *
 * @author Roberto Garzone
 * @date 2026-09-21
 */

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_AGENT_ONE				  0xFFFF0001U
#define TEST_AGENT_TWO				  0xFFFF0002U
#define TEST_AGENT_INVALID_REG_TYPE	  0xFFFF0003U
#define TEST_AGENT_EXHAUSTED_SEQUENCE 0xFFFF0004U

	/** @brief The windows agent sequence store tests related container */
	void runWindowsAgentSequenceStoreTests(void);

#ifdef __cplusplus
}
#endif