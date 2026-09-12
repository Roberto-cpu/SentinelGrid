#pragma once

/*
 * @file windows_agent_key_store_tests.h
 * @brief This header file defines the container function for the windows agent key store related tests
 *
 * @note The of the runWindowsAgentKeyStoreTests function is expected to be provided in a correspoding
 *			source file (e.g., windows_agent_key_store_tests.c)
 *
 * @author Roberto Garzone
 * @date 2026-09-12
 */

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_CREDENTIAL_TARGET \
    L"SentinelGrid/Tests/AgentKeyLoader"
#define TEST_CREDENTIAL_USERNAME \
	L"Tests/AgentKeyLoader"

	/*
	 * @brief The windows agent key store tests reltated container
	 *
	 * Contains all the tests related to the windows agent key store logic
	 */
	void runWindowsAgentKeyStoreTests(void);

#ifdef __cplusplus
}
#endif