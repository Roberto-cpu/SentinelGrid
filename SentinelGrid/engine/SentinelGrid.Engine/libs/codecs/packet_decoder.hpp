#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <string_view>

#include "security_event.hpp"
#include <alerts/security_alerts.hpp>

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

	[[nodiscard]]
	std::string_view eventTypeToString(EventType type) noexcept;

	[[nodiscard]]
	std::string_view decodeErrorToString(DecodeError err) noexcept;

	[[nodiscard]]
	std::string_view alertTypeToString(AlertType type) noexcept;

	[[nodiscard]]
	std::string_view alertSeverityToString(AlertSeverity severity) noexcept;
}