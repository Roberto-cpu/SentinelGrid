#include <cstdint>
#include <cstdio>
#include <span>
#include <variant>
#include <string_view>

#include <codecs/packet_decoder.hpp>
#include <codecs/security_event.hpp>
#include <hmac_sha256_verifier.hpp>

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

		return static_cast<std::uint64_t>(
			(byte0 << 56) | (byte1 << 48) | (byte2 << 40) |
			(byte3 << 32) | (byte4 << 24) | (byte5 << 16) |
			(byte6 << 8)  | byte7
			);
	}
}

namespace sentinelgrid::engine {

	DecodeResult decodeEventPacket(std::span<const std::uint8_t> packet) noexcept 
	{
		if (packet.size() < EventPacketSize)
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

	DecodeResult decodeAuthenticatedEventPacket(
		std::span<const std::uint8_t> packet,
		std::uint32_t expectedKeyId,
		std::span<const std::uint8_t> key) noexcept {
		
		if (packet.size() < AuthenticatedPacketSize || (packet.size() - PacketHeaderSize) < AuthenticatedBodySize)
			return DecodeError::packetTooSmall;

		std::uint32_t magic = readUint32BigEndian(packet, 0U);

		if (magic != PacketMagic)
			return DecodeError::invalidMagic;

		std::uint16_t protocol = readUint16BigEndian(packet, 4U);

		if (protocol != ProtocolVersionV2)
			return DecodeError::unsupportedVersion;

		std::uint16_t bodyLength = readUint16BigEndian(packet, 6U);

		if (bodyLength != AuthenticatedBodySize)
			return DecodeError::invalidPayloadLength;

		std::size_t keyId = readUint32BigEndian(packet, KeyIdOffset);
		if (keyId != expectedKeyId)
			return DecodeError::authenticationFailed;

		const auto authenticatedData = packet.first(security::authenticatedDataSize);
		const auto receivedMac = packet.subspan(HmacSha256Offset, security::hmacSha256Size);

		const auto authResult = security::verifyHmacSha256(key, authenticatedData, receivedMac);
		switch (authResult) {
			case security::HmacVerificationResult::valid:
				break;

			case security::HmacVerificationResult::calculation_failed:
				return DecodeError::cryptographicFailure;

			case security::HmacVerificationResult::mismatch:
			case security::HmacVerificationResult::invalid_input:

			default:
				return DecodeError::authenticationFailed;
		}

		std::uint32_t agent_id = readUint32BigEndian(packet, 8U);
		
		std::uint64_t sequence = readUint64BigEndian(packet, 12U);
		
		std::uint32_t eventType = readUint32BigEndian(packet, 20U);

		if (eventType != static_cast<std::uint32_t>(EventType::heartbeat)	 &&
			eventType != static_cast<std::uint32_t>(EventType::login_failed) &&
			eventType != static_cast<std::uint32_t>(EventType::service_stop))
			return DecodeError::invalidEventType;

		const auto type = static_cast<EventType>(eventType);
		return SecurityEvent{
			.agent_id = agent_id,
			.sequence_number = sequence,
			.type = type
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

