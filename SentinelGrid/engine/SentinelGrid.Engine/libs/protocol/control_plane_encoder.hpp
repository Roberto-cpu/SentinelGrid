#pragma once

/**
 * @file control_plane_encoder.hpp
 * @brief This header file defines functions for encoding control plane messages.
 *
 * The functions in this header file provide functionality to encode security events and alerts into a specific binary format
 * for transmission over the control plane.
 *
 * @note The implementation of the encoding functions is expected to be provided in a corresponding source file (e.g., control_plane_encoder.cpp).
 *
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <cstddef>
#include <cstdint>
#include <span>

#include <alerts/security_alerts.hpp>
#include <codecs/security_event.hpp>

namespace sentinelgrid::engine::protocol {

	inline constexpr std::uint32_t ControlPlaneMagic{ 0x53475244U };
	inline constexpr std::uint16_t ControlPlaneVersion{ 1U };

	inline constexpr std::size_t ControlPlaneHeaderSize{ 12U };
	inline constexpr std::size_t EventPayloadSize{ 16U };
	inline constexpr std::size_t AlertPayloadSize{ 24U };

	inline constexpr std::size_t EventPacketSize{ ControlPlaneHeaderSize + EventPayloadSize };
	inline constexpr std::size_t AlertPacketSize{ ControlPlaneHeaderSize + AlertPayloadSize };

	/**
	 * @brief An enumeration representing the types of messages in the control plane.
	 */
	enum class EngineMessageType : std::uint16_t {
		security_event = 1,
		security_alert = 2
	};

	/**
	 * @brief An enumeration representing possible encoding errors.
	 */
	enum class EncodeError {
		none,
		output_too_small,
		invalid_agent_id,
		invalid_sequence_number,
		invalid_event_type,
		invalid_alert_type,
		invalid_severity,
		invalid_failure_count
	};

	/**
	 * @brief A structure representing the result of an encoding operation.
	 */
	struct EncodeResult {
		EncodeError error{ EncodeError::none };
		std::size_t byte_written{ 0 };

		/**
		 * @brief Checks if the encoding operation was successful.
		 * @return true if the encoding was successful (no error), false otherwise.
		 */
		[[nodiscard]]
		bool is_success() const noexcept {
			return error == EncodeError::none;
		}
	};

	/**
	 * @brief Encodes a SecurityEvent into a binary format for transmission over the control plane.
	 * @param event The SecurityEvent to encode.
	 * @param output The output span where the encoded data will be written.
	 * @return An EncodeResult indicating the success or failure of the encoding operation.
	 */
	[[nodiscard]]
	EncodeResult encodeControlPlaneMessage(const SecurityEvent& event, std::span<std::uint8_t> output);

	/**
	 * @brief Encodes a SecurityAlert into a binary format for transmission over the control plane.
	 * @param alert The SecurityAlert to encode.
	 * @param output The output span where the encoded data will be written.
	 * @return An EncodeResult indicating the success or failure of the encoding operation.
	 */
	[[nodiscard]]
	EncodeResult encodeControlPlaneMessage(const SecurityAlert& alert, std::span<std::uint8_t> output);
}