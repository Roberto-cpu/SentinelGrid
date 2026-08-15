#pragma once

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

	enum class EngineMessageType : std::uint16_t {
		security_event = 1,
		security_alert = 2
	};

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

	struct EncodeResult {
		EncodeError error{ EncodeError::none };
		std::size_t byte_written{ 0 };

		[[nodiscard]]
		bool is_success() const noexcept {
			return error == EncodeError::none;
		}
	};

	[[nodiscard]]
	EncodeResult encodeControlPlaneMessage(const SecurityEvent& event, std::span<std::uint8_t> output);

	[[nodiscard]]
	EncodeResult encodeControlPlaneMessage(const SecurityAlert& alert, std::span<std::uint8_t> output);
}