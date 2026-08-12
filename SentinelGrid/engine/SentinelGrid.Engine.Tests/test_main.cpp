#include <cstdint>
#include <cstdio>
#include <iostream>
#include <variant>
#include <array>

#include "packet_decoder.hpp"

static int testCount = 0;
static int failCount = 0;

#define EXPECT_TRUE(condition)				\
	do {									\
		testCount++;						\
		if (!(condition)) {					\
			failCount++;					\
			printf(							\
				"[FAIL] Line %d: %s\n",		\
				__LINE__,					\
				#condition					\
			);								\
		}									\
	} while(0)								\

namespace sentinelgrid::engine {

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

	static void testPacketDecoder() {
		std::cout << "Testing packet decoder...\n";

		const auto heartbeatPacket = getBytesPacket();

		const auto result = sentinelgrid::engine::decodeEventPacket(heartbeatPacket);
		EXPECT_TRUE(std::holds_alternative<sentinelgrid::engine::SecurityEvent>(result));

		if (std::holds_alternative<sentinelgrid::engine::SecurityEvent>(result)) {
			const auto& event = std::get<sentinelgrid::engine::SecurityEvent>(result);

			EXPECT_TRUE(event.agent_id == 1U);
			EXPECT_TRUE(event.sequence_number == 1ULL);
			EXPECT_TRUE(event.type == sentinelgrid::engine::EventType::heartbeat);
		}
	}

	static void testTruncatedPacket() {
		std::cout << "Testing truncated packets...\n";

		const auto eventPacket = getBytesPacket();
		for (size_t i = 0; i < EventPacketSize; ++i) {
			expectedDecodeError(std::span{ eventPacket.data(), i }, DecodeError::packetTooSmall);
		}
	}

	static void testInvalidHeaders() {
		std::cout << "Testing invalid headers...\n";

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

int main(void) {
	std::cout << "Start SentinelGrid Engine Unit Tests.\n\n";

	sentinelgrid::engine::testPacketDecoder();
	sentinelgrid::engine::testTruncatedPacket();
	sentinelgrid::engine::testInvalidHeaders();

	std::cout << "\nTests Completed: " << testCount << " checks, " << failCount << " failures.\n";
		
	if (failCount == 0) {
		std::cout << "[PASS] All tests passed.\n";
		return EXIT_SUCCESS;
	}

	std::cout << "[FAIL] Some tests failed.\n";
	return EXIT_FAILURE;
}