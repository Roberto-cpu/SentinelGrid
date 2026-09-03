/**
 * @file control_plane_encoder.cpp
 * @brief This file contains the implementation of functions for encoding control plane messages.
 * 
 * This file provides functions to encode security events and alerts into a specific binary format for transmission over the control plane.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

#include <set>

#include <protocol/control_plane_encoder.hpp>


namespace sentinelgrid::engine::protocol {

	/**
	 * @brief Writes a 16-bit unsigned integer to the output span in big-endian format.
	 * @param output The output span where the value will be written.
	 * @param offset The offset in the output span where the value will be written.
	 * @param value The 16-bit unsigned integer value to write.
	 */
	void writeUint16BigEndian(std::span<std::uint8_t>output, std::size_t offset, std::uint16_t value) {
		output[offset]     = static_cast<std::uint8_t>((value >> 8) & 0xFF);
		output[offset + 1] = static_cast<std::uint8_t>(value & 0xFF);
	}

	/**
	 * @brief Writes a 32-bit unsigned integer to the output span in big-endian format.
	 * @param output The output span where the value will be written.
	 * @param offset The offset in the output span where the value will be written.
	 * @param value The 32-bit unsigned integer value to write.
	 */
	void writeUint32BigEndian(std::span<uint8_t>output, std::size_t offset, std::uint32_t value) {
		output[offset]     = static_cast<std::uint8_t>((value >> 24) & 0xFF);
		output[offset + 1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
		output[offset + 2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
		output[offset + 3] = static_cast<std::uint8_t>(value & 0xFF);
	}

	/**
	 * @brief Writes a 64-bit unsigned integer to the output span in big-endian format.
	 * @param output The output span where the value will be written.
	 * @param offset The offset in the output span where the value will be written.
	 * @param value The 64-bit unsigned integer value to write.
	 */
	void writeUint64BigEndian(std::span<uint8_t>output, std::size_t offset, std::uint64_t value) {
		output[offset]	   = static_cast<std::uint8_t>((value >> 56) & 0xFF);
		output[offset + 1] = static_cast<std::uint8_t>((value >> 48) & 0xFF);
		output[offset + 2] = static_cast<std::uint8_t>((value >> 40) & 0xFF);
		output[offset + 3] = static_cast<std::uint8_t>((value >> 32) & 0xFF);
		output[offset + 4] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
		output[offset + 5] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
		output[offset + 6] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
		output[offset + 7] = static_cast<std::uint8_t>(value & 0xFF);
	}

	EncodeResult encodeControlPlaneMessage(const SecurityEvent& event, std::span<std::uint8_t> output) {
		if (output.size() < EventPacketSize)
			return EncodeResult{ EncodeError::output_too_small, 0U };

		if (event.agent_id == 0U)
			return EncodeResult{ EncodeError::invalid_agent_id, 0U };

		if (event.sequence_number == 0ULL)
			return EncodeResult{ EncodeError::invalid_sequence_number, 0U };

		static const std::set<EventType> eventTypes{ EventType::heartbeat, EventType::login_failed, EventType::service_stop };
		if (!eventTypes.contains(event.type))
			return EncodeResult{ EncodeError::invalid_event_type, 0U };

		std::size_t offset{ 0 };
		writeUint32BigEndian(output, offset, ControlPlaneMagic);

		offset += sizeof(std::uint32_t);
		writeUint16BigEndian(output, offset, ControlPlaneVersion);

		offset += sizeof(std::uint16_t);
		writeUint16BigEndian(output, offset, static_cast<std::uint16_t>(EngineMessageType::security_event));

		offset += sizeof(std::uint16_t);
		writeUint32BigEndian(output, offset, EventPayloadSize);

		offset += sizeof(std::uint32_t);
		writeUint32BigEndian(output, offset, static_cast<std::uint32_t>(event.agent_id));

		offset += sizeof(std::uint32_t);
		writeUint64BigEndian(output, offset, static_cast<std::uint64_t>(event.sequence_number));

		offset += sizeof(std::uint64_t);
		writeUint32BigEndian(output, offset, static_cast<std::uint32_t>(event.type));

		return EncodeResult{ EncodeError::none, EventPacketSize };
	}

	EncodeResult encodeControlPlaneMessage(const SecurityAlert& alert, std::span<std::uint8_t> output) {
		if (output.size() < AlertPacketSize)
			return EncodeResult{ EncodeError::output_too_small, 0U };

		static const std::set<AlertType> alertTypes{ AlertType::repeated_login_failure };
		if (!alertTypes.contains(alert.type))
			return EncodeResult{ EncodeError::invalid_alert_type, 0U };

		static const std::set<AlertSeverity> alertSeverities{ AlertSeverity::low, AlertSeverity::medium, AlertSeverity::high, AlertSeverity::critical };
		if (!alertSeverities.contains(alert.severity))
			return EncodeResult{ EncodeError::invalid_severity, 0U };

		if (alert.agent_id == 0U)
			return EncodeResult{ EncodeError::invalid_agent_id, 0U };

		if (alert.triggering_sequence == 0ULL)
			return EncodeResult{ EncodeError::invalid_sequence_number, 0U };

		if (alert.failure_count == 0U || alert.failure_count > std::numeric_limits<std::uint32_t>::max())
			return EncodeResult{ EncodeError::invalid_failure_count, 0U };

		std::size_t offset{ 0 };
		writeUint32BigEndian(output, offset, ControlPlaneMagic);

		offset += sizeof(std::uint32_t);
		writeUint16BigEndian(output, offset, ControlPlaneVersion);

		offset += sizeof(std::uint16_t);
		writeUint16BigEndian(output, offset, static_cast<std::uint16_t>(EngineMessageType::security_alert));

		offset += sizeof(std::uint16_t);
		writeUint32BigEndian(output, offset, AlertPayloadSize);

		offset += sizeof(std::uint32_t);
		writeUint32BigEndian(output, offset, static_cast<std::uint32_t>(alert.type));

		offset += sizeof(std::uint32_t);
		writeUint32BigEndian(output, offset, static_cast<std::uint32_t>(alert.severity));

		offset += sizeof(std::uint32_t);
		writeUint32BigEndian(output, offset, static_cast<std::uint32_t>(alert.agent_id));

		offset += sizeof(std::uint32_t);
		writeUint64BigEndian(output, offset, static_cast<std::uint64_t>(alert.triggering_sequence));

		offset += sizeof(std::uint64_t);
		writeUint32BigEndian(output, offset, static_cast<std::size_t>(alert.failure_count));

		return EncodeResult{ EncodeError::none, AlertPacketSize };
	}
}