#pragma once

/**
 * @file packet_decoder.hpp
 * @brief This header file defines functions for decoding security event packets.
 *
 * The functions in this header file provide functionality to decode security event packets received from agents,
 * including support for authenticated packets using agent keys.
 *
 * @note The implementation of the decoding functions is expected to be provided in a corresponding source file (e.g., packet_decoder.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

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

	/**
	 * @brief An enumeration representing possible decoding errors.
	 */
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
	
	/**
	 * @brief Decodes a security event packet.
	 * @param packet The input packet to decode.
	 * @return A DecodeResult containing either a SecurityEvent or a DecodeError.
	 */
	[[nodiscard]]
	DecodeResult decodeEventPacket(std::span<const std::uint8_t> packet) noexcept;

	/**
	 * @brief Decodes an authenticated security event packet.
	 * @param packet The input authenticated packet to decode.
	 * @param keyRegistry The registry containing agent keys for authentication.
	 * @return A DecodeResult containing either a SecurityEvent or a DecodeError.
	 */
	[[nodiscard]] 
	DecodeResult decodeAuthenticatedEventPacket(
		std::span<const std::uint8_t> packet,
		const security::AgentKeyRegistry& keyRegistry) noexcept;
		
	/**
	 * @brief Converts an EventType to its string representation.
	 * @param type The EventType to convert.
	 * @return A string_view representing the EventType.
	 */
	[[nodiscard]]
	std::string_view eventTypeToString(EventType type) noexcept;

	/**
	 * @brief Converts a DecodeError to its string representation.
	 * @param err The DecodeError to convert.
	 * @return A string_view representing the DecodeError.
	 */
	[[nodiscard]]
	std::string_view decodeErrorToString(DecodeError err) noexcept;

	/**
	 * @brief Converts an AlertType to its string representation.
	 * @param type The AlertType to convert.
	 * @return A string_view representing the AlertType.
	 */
	[[nodiscard]]
	std::string_view alertTypeToString(AlertType type) noexcept;
	
	/**
	 * @brief Converts an AlertSeverity to its string representation.
	 * @param severity The AlertSeverity to convert.
	 * @return A string_view representing the AlertSeverity.
	 */
	[[nodiscard]]
	std::string_view alertSeverityToString(AlertSeverity severity) noexcept;
}