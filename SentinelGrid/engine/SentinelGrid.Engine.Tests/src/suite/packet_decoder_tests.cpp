/*
 * @file packet_decoder_tests.cpp
 * @brief Implementation of packet decoder test runner.
 *
 * @author Roberto Garzone
 * @date 2026-09-30
 */

#include <array>
#include <variant>
#include <cstdint>
#include <span>
#include <iostream>

#include <codecs/packet_decoder.hpp>
#include <codecs/security_event.hpp>

#include <tests/test_framework.hpp>
#include <tests/suites/packet_decoder_tests.hpp>

namespace sentinelgrid::engine::tests::decode {

	namespace {
		/**
		 * @brief: Expects a decode error for the given packet.
		 * @param packet: The packet to decode.
		 * @param expectedError: The expected decode error.
		 */
		static void expectedDecodeError(std::span<const std::uint8_t> packet, DecodeError expectedError) {
			const auto result = decodeEventPacket(packet);

			EXPECT_TRUE(std::holds_alternative<DecodeError>(result));

			if (const auto* error = std::get_if<DecodeError>(&result))
				EXPECT_TRUE(*error == expectedError);
		}

		static std::array<std::uint8_t, EventPacketSize> getBytesPacket() {
			return {
				0x53, 0x47, 0x52, 0x44,
				0x00, 0x01,
				0x00, 0x10,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x01
			};
		}

		/**
		 * @brief: Tests the packet decoder with a valid packet.
		 */
		static void testValidPacket() {
			std::cout << "[+] Packet correctly decode...\n";

			const auto heartbeatPacket = getBytesPacket();

			const auto result = decodeEventPacket(heartbeatPacket);
			EXPECT_TRUE(std::holds_alternative<SecurityEvent>(result));

			if (std::holds_alternative<SecurityEvent>(result)) {
				const auto& event = std::get<SecurityEvent>(result);

				EXPECT_TRUE(event.agent_id == 1U);
				EXPECT_TRUE(event.sequence_number == 1ULL);
				EXPECT_TRUE(event.type == EventType::heartbeat);
			}
		}

		/**
		 * @brief: Tests the packet decoder with truncated packets.
		 */
		static void testTruncatedPacket() {
			std::cout << "[+] Truncated packets...\n";

			const auto eventPacket = getBytesPacket();
			for (size_t i = 0; i < EventPacketSize; ++i) {
				expectedDecodeError(std::span{ eventPacket.data(), i }, DecodeError::packetTooSmall);
			}
		}

		/**
		 * @brief: Tests the packet decoder with invalid headers.
		 */
		static void testInvalidHeaders() {
			std::cout << "[+] Invalid headers...\n";

			const auto validPacket = getBytesPacket();

			auto invalidMagic = validPacket;
			invalidMagic[0] ^= 0x10;
			expectedDecodeError(invalidMagic, DecodeError::invalidMagic);

			auto invalidVersion = validPacket;
			invalidVersion[4] = 0x00;
			invalidVersion[5] = 0x02;
			expectedDecodeError(invalidVersion, DecodeError::unsupportedVersion);

			auto invalidPacketLength = validPacket;
			invalidPacketLength[6] = 0x00;
			invalidPacketLength[7] = 0x0F;
			expectedDecodeError(invalidPacketLength, DecodeError::invalidPayloadLength);

			auto invalidPacketType = validPacket;
			invalidPacketType[20] = 0x00;
			invalidPacketType[21] = 0x00;
			invalidPacketType[22] = 0x00;
			invalidPacketType[23] = 0x63;
			expectedDecodeError(invalidPacketType, DecodeError::invalidEventType);
		}
	}

	void runTests() {
		std::cout << "\n[Suite] Packer Decoder Tests...\n";

		testValidPacket();
		testTruncatedPacket();
		testInvalidHeaders();
	}
}