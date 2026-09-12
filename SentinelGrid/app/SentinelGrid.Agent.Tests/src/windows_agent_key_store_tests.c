/*
 * @file windows_agent_key_store_tests.c
 * @brief Implementation of windows agent key store tests.
 *
 * This file contains the implementation of the function 
 * to perform windows agent key store related tests.
 *
 * @author Roberto Garzone
 * @date 2026-09-12
 */

#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <wincred.h>

#include <windows_agent_key_store_tests.h>
#include <test_framework.h>

#include <windows_agent_key_store.h>

/*
 * @brief Creates a new credential
 * 
 * Insert a new credential into Windows Credential Manager application
 * 
 * @param key - the key to store
 * @param keySize - the space to guarantee
 * @returns TRUE if the credential is correctly created; FALSE otherwise
 */
static bool registerCredential(uint8_t* key, size_t keySize) {
	CREDENTIALW credential = { 0 };

	credential.Type = CRED_TYPE_GENERIC;
	credential.TargetName = (LPWSTR)TEST_CREDENTIAL_TARGET;
	credential.UserName = (LPWSTR)TEST_CREDENTIAL_USERNAME;

	credential.CredentialBlob = (LPBYTE)key;
	credential.CredentialBlobSize = (DWORD)keySize;
	credential.Persist = CRED_PERSIST_SESSION;

	return CredWriteW(&credential, 0) != FALSE;
}

/*
 * @brief Resets the test status to the start\
 * 
 * Flush the destination memory address and erase the created credential for
 * the next test
 * 
 * @param loadedKey - the memory address to clean
 * @param loadedKeySize - the occupied memory space
 * @param toDelete - if it's necessary to delete the credential from che Credential Manager.
 */
static void resetCredential(uint8_t* loadedKey, size_t loadedKeySize, bool toDelete) {
	secureEraseAngetKey(loadedKey, loadedKeySize);

	if (toDelete) {
		const bool deleted = CredDeleteW(TEST_CREDENTIAL_TARGET, CRED_TYPE_GENERIC, 0U);
		EXPECT_TRUE(deleted);
	}
}

/*
 * @brief Tests the loading of a existing valid credential
 */
static void testLoadAgentKeyValidCredential(void)
{
	printf("[+] Testing valid agent key credential loading...\n");

	uint8_t key[SENTINELGRID_AGENT_KEY_SIZE] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B,
		0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B,
		0x1C, 0x1D, 0x1E, 0x1F
	};

	bool keyRegister = registerCredential(key, sizeof key);
	EXPECT_TRUE(keyRegister);

	if (!keyRegister)
		return;

	uint8_t destination[SENTINELGRID_AGENT_KEY_SIZE] = { 0 };
	AgentKeyLoadResult loadResult = loadAgentKey(TEST_CREDENTIAL_TARGET, destination, sizeof destination);

	EXPECT_TRUE(loadResult.status == AGENT_KEY_LOAD_SUCCESS);
	EXPECT_TRUE(memcmp(key, destination, sizeof destination) == 0);

	resetCredential(destination, sizeof destination, true);
}

/*
 * @brief Tests the loading of a non-existent credential
 * 
 * Checks if the system raises an error when the agent tries
 * to load a not eixstent credential.
 */
static void testLoadAgentKeyMissingCredential(void)
{
	printf("[+] Testing credential load for missing credential...\n");

	uint8_t destination[SENTINELGRID_AGENT_KEY_SIZE] = { 0 };
	AgentKeyLoadResult loadResult = loadAgentKey(TEST_CREDENTIAL_TARGET, destination, sizeof destination);

	EXPECT_TRUE(loadResult.status == AGENT_KEY_LOAD_NOT_FOUND);
	resetCredential(destination, sizeof destination, false);
}

static void testLoadAgentKeyRejectsShortKey(void)
{
    /* Test implementation. */
}

static void testLoadAgentKeyRejectsLongKey(void)
{
    /* Test implementation. */
}

void runWindowsAgentKeyStoreTests(void)
{
    printf("\n[Suite] Windows agent-key store\n");

    testLoadAgentKeyValidCredential();
    testLoadAgentKeyMissingCredential();
    //testLoadAgentKeyRejectsShortKey();
    //testLoadAgentKeyRejectsLongKey();
}