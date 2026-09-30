/*
 * @file agent_key_registry_tests.cpp
 * @brief Implementation of agent registry key management test runner.
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <variant>

#include <codecs/packet_decoder.hpp>
#include <security/agent_key_registry.hpp>

#include <tests/test_framework.hpp>
#include <tests/suites/agent_key_registry_tests.hpp>

namespace sentinelgrid::engine::tests::registry_key {

	namespace {
		/**
		 * @brief: Tests the successful registration of a key.
		 */
		static void testKeyRegistrationSuccess() {
			std::cout << "[+] New key registration...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;

			bool registered = keyRegistry.registerKey(keyId, 1U, key);

			EXPECT_TRUE(registered);
		}

		/**
		 * @brief: Tests the registration of a key with an existing ID.
		 */
		static void testKeyRegistrationTwice() {
			std::cout << "[+] Register two times the same key ID...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<std::uint8_t, 32> key2{
				0x00, 0x01, 0x02, 0x00,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;

			bool registered1 = keyRegistry.registerKey(keyId, 1U, key1);
			bool registered2 = keyRegistry.registerKey(keyId, 2U, key2);

			EXPECT_TRUE(registered1 && !registered2);
		}

		/**
		 * @brief: Tests the finding of an existent key.
		 */
		static void testFindExistentKey() {
			std::cout << "[+] Find existent key...\n";

			constexpr std::uint32_t keyId = 1U;

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;

			bool registered = keyRegistry.registerKey(keyId, 1U, key);
			EXPECT_TRUE(registered);

			const auto foundKey = keyRegistry.findCredential(keyId);
			EXPECT_TRUE(foundKey.has_value() && std::ranges::equal(foundKey.value().key, key));
		}

		/**
		 * @brief: Tests the finding of a non-existent key.
		 */
		static void testFindNotExistentKey() {
			std::cout << "[+] Find not existent key...\n";

			security::AgentKeyRegistry keyRegistry;
			const auto foundKey = keyRegistry.findCredential(1U);

			EXPECT_TRUE(!foundKey.has_value());
		}

		/**
		 * @brief: Tests the finding of two different keys.
		 */
		static void testFindForTwoDifferentKeys() {
			std::cout << "[+] Find for key ID returns only the associated key...\n";

			constexpr std::uint32_t keyId1 = 1U;
			constexpr std::uint32_t keyId2 = 2U;

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<std::uint8_t, 32> key2{
				0x00, 0x01, 0x02, 0x00,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;

			bool registered1 = keyRegistry.registerKey(keyId1, 1U, key1);
			bool registered2 = keyRegistry.registerKey(keyId2, 2U, key2);

			EXPECT_TRUE(registered1 && registered2);

			const auto foundKey1 = keyRegistry.findCredential(keyId1);
			const auto foundKey2 = keyRegistry.findCredential(keyId2);

			EXPECT_TRUE(foundKey1.has_value() && std::ranges::equal(foundKey1.value().key, key1));
			EXPECT_TRUE(foundKey2.has_value() && std::ranges::equal(foundKey2.value().key, key2));
		}

		/**
		 * @brief: Tests the behavior when trying to decode a packet with a key that is not registered.
		 */
		static void testDecodePacketWithAnotherKey() {
			std::cout << "[+] Cannot decode a packet with another packet's key...\n";

			constexpr std::uint32_t keyId1 = 2U;

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;

			bool registered1 = keyRegistry.registerKey(keyId1, 1U, key1);
			EXPECT_TRUE(registered1);

			const auto foundKey1 = keyRegistry.findCredential(keyId1);
			EXPECT_TRUE(foundKey1.has_value() && std::ranges::equal(foundKey1.value().key, key1));

			const auto result = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&result);

			EXPECT_TRUE(*err == DecodeError::authenticationFailed);
		}

		/**
		 * @brief: Tests the behavior when the key ID and agent ID match.
		 */
		static void testMatchingKeyAndAgent() {
			std::cout << "[+] Matching key ID and agent ID...\n";

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(1U, 1U, key);
			EXPECT_TRUE(registered);

			const auto result = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* securityEvent = std::get_if<SecurityEvent>(&result);

			EXPECT_TRUE(securityEvent->agent_id == 1U);
		}

		/**
		 * @brief: Tests the behavior when the key ID is unknown.
		 */
		static void testUnknownKeyID() {
			std::cout << "[+] Unknown key ID...\n";

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(2U, 1U, key1);
			EXPECT_TRUE(registered);

			const auto result = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&result);

			EXPECT_TRUE(*err == DecodeError::authenticationFailed);
		}

		/**
		 * @brief: Tests the behavior when the HMAC is valid but the agent ID is different.
		 */
		static void testHmacForAnotherAgent() {
			std::cout << "[+] Valid HMAC claiming another agent ID...\n";

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> packet{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x01,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				// HMAC-SHA-256
				0xA5, 0x41, 0x4B, 0x2B,
				0x55, 0x00, 0x7B, 0xB8,
				0x12, 0x9D, 0xA7, 0xA3,
				0xFD, 0xCD, 0x05, 0x6B,
				0xE0, 0xBB, 0xC0, 0x1B,
				0x49, 0xA4, 0xFB, 0x3D,
				0xF7, 0x01, 0x27, 0x82,
				0xCC, 0xC6, 0x80, 0xCE
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(1U, 2U, key1);
			EXPECT_TRUE(registered);

			const auto result = decodeAuthenticatedEventPacket(packet, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&result);

			EXPECT_TRUE(*err == DecodeError::authenticationFailed);
		}

		/**
		 * @brief: Tests the behavior when an agent tries to impersonate another agent.
		 */
		static void testAgentImpersonification() {
			std::cout << "[+] Agent 2 cannot impersonate agent 1 ...\n";

			constexpr std::array<std::uint8_t, 32> key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			constexpr std::array<
				std::uint8_t,
				sentinelgrid::engine::AuthenticatedPacketSize> impersonedPacket{
				// Header: SGRD, version 2, body length 52
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x02,
				0x00, 0x34,

				// Agent ID: 1
				0x00, 0x00, 0x00, 0x02,

				// Sequence number: 1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,

				// Event type: login_failed (3)
				0x00, 0x00, 0x00, 0x03,

				// Key ID: 1
				0x00, 0x00, 0x00, 0x01,

				0x65, 0xCE, 0x14, 0xB8,
				0x76, 0xA8, 0x9B, 0xEE,
				0xD7, 0x68, 0x32, 0x01,
				0xC5, 0x79, 0xE0, 0x29,
				0x85, 0x8E, 0x2C, 0x9E,
				0xBA, 0x52, 0x78, 0xCE,
				0x1B, 0x05, 0x53, 0x20,
				0x43, 0xA1, 0x5D, 0xA8
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(1U, 1U, key);
			EXPECT_TRUE(registered);

			if (!registered) return;

			const auto result = decodeAuthenticatedEventPacket(impersonedPacket, keyRegistry);
			const auto* err = std::get_if<DecodeError>(&result);

			EXPECT_TRUE(*err == DecodeError::authenticationFailed);
		}

		/**
		 * @brief: Tests the behavior when trying to register a key with an already registered key ID.
		 */
		static void testDuplicatedKeyID() {
			std::cout << "[+] Reject duplicated key ID...\n";

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered1 = keyRegistry.registerKey(2U, 1U, key1);
			bool registered2 = keyRegistry.registerKey(2U, 2U, key1);
			EXPECT_TRUE(registered1 && !registered2);
		}

		static void testOneAgentWithTwoKeyIDs() {
			std::cout << "[+] An agent can have multiple key IDs...\n";

			constexpr std::array<std::uint8_t, 32> key1{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered1 = keyRegistry.registerKey(1U, 1U, key1);
			bool registered2 = keyRegistry.registerKey(2U, 1U, key1);
			EXPECT_TRUE(registered1 && registered2);
		}

		/**
		 * @brief: Tests the behavior when looking up a key ID multiple times.
		 */
		static void testCredentialsLookupReturnesStoredKeysView() {
			std::cout << "[+] Credential lookup returns stored key view...\n";

			constexpr std::uint32_t keyId{ 1U };
			constexpr std::uint32_t agentId{ 42U };

			const security::AgentKey key{
				0x00, 0x01, 0x02, 0x03,
				0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B,
				0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1A, 0x1B,
				0x1C, 0x1D, 0x1E, 0x1F
			};

			security::AgentKeyRegistry keyRegistry;
			bool registered = keyRegistry.registerKey(keyId, agentId, key);
			EXPECT_TRUE(registered);

			if (!registered) return;

			const auto firstLookup = keyRegistry.findCredential(keyId);
			EXPECT_TRUE(firstLookup.has_value());

			if (!firstLookup.has_value()) return;

			EXPECT_TRUE(firstLookup->agent_id == agentId);
			EXPECT_TRUE(firstLookup->key.size() == key.size());
			EXPECT_TRUE(std::ranges::equal(firstLookup->key, key));

			EXPECT_TRUE(firstLookup->key.data() != key.data());

			const auto secondLookup = keyRegistry.findCredential(keyId);
			EXPECT_TRUE(secondLookup.has_value());

			if (!secondLookup.has_value()) return;

			EXPECT_TRUE(firstLookup->key.data() == secondLookup->key.data());
			EXPECT_TRUE(std::ranges::equal(secondLookup->key, key));
		}
	}

	void runTests() {
		std::cout << "\n[Suite] Agent Registry Key Tests...\n";

		testKeyRegistrationSuccess();
		testKeyRegistrationTwice();
		testFindExistentKey();
		testFindNotExistentKey();
		testFindForTwoDifferentKeys();
		testDecodePacketWithAnotherKey();
		testMatchingKeyAndAgent();
		testUnknownKeyID();
		testHmacForAnotherAgent();
		testAgentImpersonification();
		testDuplicatedKeyID();
		testCredentialsLookupReturnesStoredKeysView();

	}
}