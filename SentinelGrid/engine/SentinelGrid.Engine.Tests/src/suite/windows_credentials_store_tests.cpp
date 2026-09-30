/*
 * @file windows_credentials_store_tests.cpp
 * @brief Implementation of windows credentials store test runner.
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <wincred.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>

#include <security/agent_key_registry.hpp>
#include <security/windows_credential_store.hpp>

#include <tests/test_framework.hpp>
#include <tests/suites/windows_credentials_store_tests.hpp>

namespace sentinelgrid::engine::tests::credential {

	namespace {
		/**
			 * @brief: Registers a credential in the Windows Credential Manager.
			 * @param credentialBlob: The credential blob to register.
			 * @return: True if the credential was successfully registered, false otherwise.
			 */
		static bool registerCredential(std::span<std::uint8_t> credentialBlob) {
			std::wstring targetName{ L"SentinelGrid/Agent/1" };
			std::wstring username{ L"Agent/1" };

			CREDENTIALW credential{};

			credential.Type = CRED_TYPE_GENERIC;
			credential.TargetName = const_cast<LPWSTR>(targetName.data());
			credential.UserName = const_cast<LPWSTR>(username.data());

			credential.CredentialBlob = const_cast<LPBYTE>(credentialBlob.data());
			credential.CredentialBlobSize = static_cast<DWORD>(credentialBlob.size());

			credential.Persist = CRED_PERSIST_SESSION;

			return CredWriteW(&credential, 0);
		}

		/**
		 * @brief: Tests the retrieval of a valid key from the Windows Credential Manager.
		 */
		static void testValidKeyRetrieval() {

			std::cout << "[+] Valid key...\n";

			security::AgentKey key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			if (!registerCredential(key))
				return;

			security::AgentKey loadedKey{};
			const auto readRes = security::loadAgentKey(L"SentinelGrid/Agent/1", loadedKey);
			EXPECT_TRUE(readRes.isSuccess());
			EXPECT_TRUE(std::ranges::equal(loadedKey, key));

			security::secureErase(loadedKey);
			const bool deleted = CredDeleteW(L"SentinelGrid/Agent/1", CRED_TYPE_GENERIC, 0U);
			EXPECT_TRUE(deleted);
		}

		/**
		 * @brief: Tests the behavior when trying to retrieve a key that does not exist in the Windows Credential Manager.
		 */
		static void testMissingCredentials() {

			std::cout << "[+] Missing credentials...\n";

			security::AgentKey key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			if (!registerCredential(key))
				return;

			static_cast<void>(CredDeleteW(L"SentinelGrid/Agent/1", CRED_TYPE_GENERIC, 0U));

			security::AgentKey loadedKey{};
			loadedKey.fill(0xA5U);
			const auto readRes = security::loadAgentKey(L"SentinelGrid/Agent/1", loadedKey);
			EXPECT_TRUE(readRes.status == security::CredentialLoadStatus::not_found);
			EXPECT_TRUE(std::ranges::all_of(loadedKey, [](std::uint8_t byte) { return byte == 0U; }));
		}

		/**
		 * @brief: Tests the behavior when trying to retrieve a key with an invalid size from the Windows Credential Manager.
		 */
		static void testInvalidSizeKey() {

			std::cout << "[+] Key size of 31 or 33 bytes returns empty AgentKet destination...\n";

			security::AgentKey key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			std::array<std::uint8_t, security::AgentKeySize - 1U> key31Bytes{};
			std::array<std::uint8_t, security::AgentKeySize + 1U> key33Bytes{};

			const auto testInvalidBlob = [](auto& invalidKey) {
				if (!registerCredential(std::span{ invalidKey }))
					return;

				security::AgentKey destination{};
				destination.fill(0xA5U);

				security::AgentKey loadedKey{};
				const auto readRes = security::loadAgentKey(L"SentinelGrid/Agent/1", destination);
				EXPECT_TRUE(readRes.status == security::CredentialLoadStatus::invalid_key_size);
				EXPECT_TRUE(std::ranges::all_of(loadedKey, [](std::uint8_t byte) { return byte == 0U; }));

				security::secureErase(loadedKey);
				const bool deleted = CredDeleteW(L"SentinelGrid/Agent/1", CRED_TYPE_GENERIC, 0U);
				EXPECT_TRUE(deleted);
				};

			testInvalidBlob(key31Bytes);
			testInvalidBlob(key33Bytes);
		}

		/**
		 * @brief: Tests the behavior of generating a valid key.
		 */
		static void testValidKeyGeneration() {
			std::cout << "[+] Valid key generation...\n";

			security::AgentKey destinationKey{};
			const auto generatedKey = security::generateAgentKey(destinationKey);

			EXPECT_TRUE(generatedKey.isSuccess());

			security::secureErase(destinationKey);
		}

		/**
		 * @brief: Tests the behavior of storing and loading a valid key.
		 */
		static void testStoreAndLoadValidKey() {
			std::cout << "[+] Valid key store and load...\n";

			security::AgentKey generatedAgentKey{};
			const auto generatedKey = security::generateAgentKey(generatedAgentKey);

			EXPECT_TRUE(generatedKey.isSuccess());
			if (!generatedKey.isSuccess()) return;

			const auto storedKey = security::storeAgentKey(
				L"SentinelGrid/Store/Load",
				L"Agent/Store/Load",
				generatedAgentKey,
				security::CredentialPersistence::session,
				false
			);

			EXPECT_TRUE(storedKey.isSuccess());
			if (!storedKey.isSuccess()) return;

			security::AgentKey loadedAgentKey{};
			const auto loadedKey = security::loadAgentKey(L"SentinelGrid/Store/Load", loadedAgentKey);

			EXPECT_TRUE(loadedKey.isSuccess());
			EXPECT_TRUE(std::ranges::equal(generatedAgentKey, loadedAgentKey));

			security::secureErase(loadedAgentKey);
			const bool deleted = CredDeleteW(L"SentinelGrid/Store/Load", CRED_TYPE_GENERIC, 0U);
			EXPECT_TRUE(deleted);
		}

		/**
		 * @brief: Tests the behavior of storing a key when a key already exists and overwrite is not allowed.
		 */
		static void testAlreadyExistsWithoutOverwrite() {
			std::cout << "[+] Already exists error if overwrite not set...\n";

			security::AgentKey generatedAgentOneKey{};
			const auto generatedKeyOne = security::generateAgentKey(generatedAgentOneKey);

			EXPECT_TRUE(generatedKeyOne.isSuccess());
			if (!generatedKeyOne.isSuccess()) return;

			security::AgentKey generatedAgentTwoKey{};
			const auto generatedKeyTwo = security::generateAgentKey(generatedAgentTwoKey);

			EXPECT_TRUE(generatedKeyTwo.isSuccess());
			if (!generatedKeyTwo.isSuccess()) return;

			const auto storedKeyOne = security::storeAgentKey(
				L"SentinelGrid/Overwrite/Not/Allowed",
				L"Agent/Overwrite/Not/Allowed",
				generatedAgentOneKey,
				security::CredentialPersistence::session,
				false
			);

			EXPECT_TRUE(storedKeyOne.isSuccess());
			if (!storedKeyOne.isSuccess()) return;

			const auto storedKeyTwo = security::storeAgentKey(
				L"SentinelGrid/Overwrite/Not/Allowed",
				L"Agent/Overwrite/Not/Allowed",
				generatedAgentTwoKey,
				security::CredentialPersistence::session,
				false
			);

			EXPECT_TRUE(!storedKeyTwo.isSuccess());
			EXPECT_TRUE(storedKeyTwo.status == security::CredentialWriteStatus::already_exists);

			security::AgentKey loadedAgentKey{};
			const auto loadedKey = security::loadAgentKey(L"SentinelGrid/Overwrite/Not/Allowed", loadedAgentKey);

			EXPECT_TRUE(loadedKey.isSuccess());
			EXPECT_TRUE(std::ranges::equal(generatedAgentOneKey, loadedAgentKey));

			security::secureErase(generatedAgentOneKey);
			security::secureErase(generatedAgentTwoKey);
			security::secureErase(loadedAgentKey);
			const bool deleted = CredDeleteW(L"SentinelGrid/Overwrite/Not/Allowed", CRED_TYPE_GENERIC, 0U);
			EXPECT_TRUE(deleted);
		}

		/**
		 * @brief: Tests the behavior of storing a key when a key already exists and overwrite is allowed.
		 */
		static void testAlreadyExistsWithOverwrite() {
			std::cout << "[+] Overwrite key...\n";

			security::AgentKey generatedAgentOneKey{};
			const auto generatedKeyOne = security::generateAgentKey(generatedAgentOneKey);

			EXPECT_TRUE(generatedKeyOne.isSuccess());
			if (!generatedKeyOne.isSuccess()) return;

			security::AgentKey generatedAgentTwoKey{};
			const auto generatedKeyTwo = security::generateAgentKey(generatedAgentTwoKey);

			EXPECT_TRUE(generatedKeyTwo.isSuccess());
			if (!generatedKeyTwo.isSuccess()) return;

			const auto storedKeyOne = security::storeAgentKey(
				L"SentinelGrid/Overwrite/Allowed",
				L"Agent/Overwrite/Allowed",
				generatedAgentOneKey,
				security::CredentialPersistence::session,
				false
			);

			EXPECT_TRUE(storedKeyOne.isSuccess());
			if (!storedKeyOne.isSuccess()) return;


			const auto storedKeyTwo = security::storeAgentKey(
				L"SentinelGrid/Overwrite/Allowed",
				L"Agent/Overwrite/Allowed",
				generatedAgentTwoKey,
				security::CredentialPersistence::session,
				true
			);

			EXPECT_TRUE(storedKeyTwo.isSuccess());
			if (!storedKeyTwo.isSuccess()) return;

			security::AgentKey loadedAgentKey{};
			const auto loadedKey = security::loadAgentKey(L"SentinelGrid/Overwrite/Allowed", loadedAgentKey);

			EXPECT_TRUE(loadedKey.isSuccess());
			EXPECT_TRUE(std::ranges::equal(generatedAgentTwoKey, loadedAgentKey));

			security::secureErase(generatedAgentOneKey);
			security::secureErase(generatedAgentTwoKey);
			security::secureErase(loadedAgentKey);
			const bool deleted = CredDeleteW(L"SentinelGrid/Overwrite/Allowed", CRED_TYPE_GENERIC, 0U);
			EXPECT_TRUE(deleted);
		}

		/**
		 * @brief: Tests the behavior of storing a key with no target name or username.
		 */
		static void testNoTargetInput() {
			std::cout << "[+] Store with no target...\n";

			security::AgentKey generatedAgentKey{};
			const auto generatedKey = security::generateAgentKey(generatedAgentKey);

			EXPECT_TRUE(generatedKey.isSuccess());
			if (!generatedKey.isSuccess()) return;

			const auto storedKey = security::storeAgentKey(
				L"",
				L"",
				generatedAgentKey,
				security::CredentialPersistence::session,
				false
			);

			EXPECT_TRUE(!storedKey.isSuccess());
			EXPECT_TRUE(storedKey.status == security::CredentialWriteStatus::invalid_input);

			security::secureErase(generatedAgentKey);
		}

		/**
		 * @brief: Tests the behavior of storing a key with an invalid size.
		 */
		static void testStoreKeyWithInvalidSize() {
			std::cout << "[+] Store invalid key size...\n";

			std::array<std::uint8_t, security::AgentKeySize - 1U> key31Bytes{};
			std::array<std::uint8_t, security::AgentKeySize + 1U> key33Bytes{};

			const auto testInvalidBlob = [&](auto& invalidKey) {

				security::AgentKey storedKey{};
				const auto readRes = security::storeAgentKey(L"SentinelGrid/InvalidSize", L"Agent/InvalidSize", invalidKey, security::CredentialPersistence::session);
				EXPECT_TRUE(readRes.status == security::CredentialWriteStatus::invalid_input);
				};

			testInvalidBlob(key31Bytes);
			testInvalidBlob(key33Bytes);
		}
	}

	void runTests() {
		std::cout << "\n[Suite] Windows Credentials Store Tests...\n";

		testValidKeyRetrieval();
		testMissingCredentials();
		testInvalidSizeKey();
		testValidKeyGeneration();
		testStoreAndLoadValidKey();
		testAlreadyExistsWithoutOverwrite();
		testAlreadyExistsWithOverwrite();
		testNoTargetInput();
		testStoreKeyWithInvalidSize();

	}
}