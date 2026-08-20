#include <cstdint>
#include <cstdio>
#include <span>
#include <variant>
#include <string_view>

#include "../../libs/codecs/packet_decoder.hpp"
#include "../../libs/codecs/security_event.hpp"

namespace {
	std::uint16_t readUint16BigEndian(std::span<const uint8_t> bytes, std::size_t offset) noexcept {
		const auto byte0 = static_cast<std::uint16_t>(bytes[offset]);
		const auto byte1 = static_cast<std::uint16_t>(bytes[offset + 1]);

		return static_cast<std::uint16_t>((byte0 << 8) | byte1);
	}
	
	std::uint32_t readUint32BigEndian(std::span<const uint8_t> bytes, std::size_t offset) noexcept {
		const auto byte0 = static_cast<std::uint32_t>(bytes[offset]);
		const auto byte1 = static_cast<std::uint32_t>(bytes[offset + 1]);
		const auto byte2 = static_cast<std::uint32_t>(bytes[offset + 2]);
		const auto byte3 = static_cast<std::uint32_t>(bytes[offset + 3]);

		return static_cast<std::uint32_t>((byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3);
	}

	std::uint64_t readUint64BigEndian(std::span<const uint8_t> bytes, std::size_t offset) noexcept {
		const auto byte0 = static_cast<std::uint64_t>(bytes[offset]);
		const auto byte1 = static_cast<std::uint64_t>(bytes[offset + 1]);
		const auto byte2 = static_cast<std::uint64_t>(bytes[offset + 2]);
		const auto byte3 = static_cast<std::uint64_t>(bytes[offset + 3]);
		const auto byte4 = static_cast<std::uint64_t>(bytes[offset + 4]);
		const auto byte5 = static_cast<std::uint64_t>(bytes[offset + 5]);
		const auto byte6 = static_cast<std::uint64_t>(bytes[offset + 6]);
		const auto byte7 = static_cast<std::uint64_t>(bytes[offset + 7]);

		return static_cast<std::uint16_t>(
			(byte0 << 56) | (byte1 << 48) | (byte2 << 40) |
			(byte3 << 32) | (byte4 << 24) | (byte5 << 16) |
			(byte6 << 8)  | byte7
			);
	}
}

namespace sentinelgrid::engine {

	DecodeResult decodeEventPacket(std::span<const std::uint8_t> packet) noexcept {
		if (packet.size() < EventPacketSize || (packet.size() - PacketHeaderSize) < EventPayloadSize)
			return DecodeError::packetTooSmall;

		std::uint32_t magic = readUint32BigEndian(packet, 0);
		if (magic != PacketMagic)
			return DecodeError::invalidMagic;

		std::uint16_t protocolVersion = readUint16BigEndian(packet, 4);
		if (protocolVersion != ProtocolVersion)
			return DecodeError::unsupportedVersion;

		std::uint16_t payloadLength = readUint16BigEndian(packet, 6);
		if (payloadLength != EventPayloadSize)
			return DecodeError::invalidPayloadLength;

		std::uint32_t agent_id = readUint32BigEndian(packet, 8);
		std::uint64_t sequence_number = readUint64BigEndian(packet, 12);
		std::uint32_t type = readUint32BigEndian(packet, 20);

		if (type != static_cast<std::uint32_t>(EventType::heartbeat) &&
			type != static_cast<std::uint32_t>(EventType::login_failed) &&
			type != static_cast<std::uint32_t>(EventType::service_stop))
			return DecodeError::invalidEventType;

		const auto eventType = static_cast<EventType>(type);

		return SecurityEvent{
			.agent_id = agent_id,
			.sequence_number = sequence_number,
			.type = eventType
		};
	}

	std::string_view eventTypeToString(EventType type) noexcept {
		switch (type) {
			case EventType::heartbeat: 
				return "HEARTBEAT";
			case EventType::login_failed:
				return "LOGIN FAILED";
			case EventType::service_stop:
				return "SERVICE STOP";
			default:
				return "UNKNOWN";
		}
	}

	std::string_view decodeErrorToString(DecodeError err) noexcept {
		switch (err) {
			case DecodeError::packetTooSmall:
				return "Packet Too Small";
			case DecodeError::invalidMagic:
				return "Inalid Magic";
			case DecodeError::unsupportedVersion:
				return "Unsupported Protocol Version";
			case DecodeError::invalidPayloadLength:
				return "Invalid Payload Length";
			case DecodeError::invalidEventType:
				return "Invalid Event Type";
			default:
				return "Unknown Error";
		}
	}

	std::string_view alertTypeToString(AlertType type) noexcept {
		switch (type) {
			case AlertType::repeated_login_failure:
				return "Repeated Login Failures";
			default:
				return "Unknown Alert Type";
		}
	}
	
	std::string_view alertSeverityToString(AlertSeverity severity) noexcept {
		switch (severity) {
			case AlertSeverity::low:
				return "Low";
			case AlertSeverity::medium:
				return "Medium";
			case AlertSeverity::high:
				return "High";
			case AlertSeverity::critical:
				return "Critical";
			default:
				return "Unkonwn Alert Severity";
		}
	}
}

