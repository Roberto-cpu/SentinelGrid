#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <string_view>

#include "security_event.hpp"
#include <alerts/security_alerts.hpp>
#include <security/agent_key_registry.hpp>

namespace sentinelgrid::engine {
	inline constexpr std::uint32_t PacketMagic		= 0x53475244U;
	inline constexpr std::uint16_t ProtocolVersion	= 1U;
	inline constexpr std::uint16_t EventPayloadSize = 16U;
	inline constexpr std::size_t   PacketHeaderSize = 8U;
	inline constexpr std::size_t   EventPacketSize	= 24U;

	inline constexpr std::uint32_t ProtocolVersionV2	   = 0x0002U;
	inline constexpr std::uint16_t KeyIdSize			   = 4U;
	inline constexpr std::uint16_t AuthenticatedBodySize   = 52U;
	inline constexpr std::size_t   AuthenticatedPacketSize = 60U;
	inline constexpr std::size_t   KeyIdOffset			   = 24U;
	inline constexpr std::size_t   HmacSha256Offset		   = 28U;

	enum class DecodeError {
		packetTooSmall = 1,
		invalidMagic = 2,
		unsupportedVersion = 3,
		invalidPayloadLength = 4,
		invalidEventType = 5,
		authenticationFailed = 6,
		cryptographicFailure = 7,
		invalidPacketSize = 8
	};

	using DecodeResult = std::variant<SecurityEvent, DecodeError>;

	[[nodiscard]]
	DecodeResult decodeEventPacket(std::span<const std::uint8_t> packet) noexcept;

	[[nodiscard]] 
	DecodeResult decodeAuthenticatedEventPacket(
		std::span<const std::uint8_t> packet,
		const security::AgentKeyRegistry& keyRegistry) noexcept;
		
	[[nodiscard]]
	std::string_view eventTypeToString(EventType type) noexcept;

	[[nodiscard]]
	std::string_view decodeErrorToString(DecodeError err) noexcept;

	[[nodiscard]]
	std::string_view alertTypeToString(AlertType type) noexcept;

	[[nodiscard]]
	std::string_view alertSeverityToString(AlertSeverity severity) noexcept;
}