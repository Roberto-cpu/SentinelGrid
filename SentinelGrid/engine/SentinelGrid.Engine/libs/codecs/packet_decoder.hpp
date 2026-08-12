#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>

#include "security_event.hpp"

namespace sentinelgrid::engine {
	inline constexpr std::uint32_t PacketMagic		= 0x53475244U;
	inline constexpr std::uint16_t ProtocolVersion	= 1U;
	inline constexpr std::uint16_t EventPayloadSize = 16U;
	inline constexpr std::size_t   PacketHeaderSize = 8U;
	inline constexpr std::size_t   EventPacketSize	= 24U;

	enum class DecodeError {
		packetTooSmall,
		invalidMagic,
		unsupportedVersion,
		invalidPayloadLength,
		invalidEventType
	};

	using DecodeResult = std::variant<SecurityEvent, DecodeError>;

	[[nodiscard]]
	DecodeResult decodeEventPacket(std::span<const std::uint8_t> packet) noexcept;
}