/**
 * @file EngineMessageDecoder.cs
 * @brief Contains the EngineMessageDecoder class for decoding engine messages in the SentinelGrid Control Plane protocol.
 *
 * The EngineMessageDecoder class provides methods for decoding engine messages received in the SentinelGrid Control Plane protocol.
 * It validates the message structure, extracts relevant information, and returns the decoded result along with any potential errors.
 * 
 * @author Roberto Garzone
 * @date 2026-09-03
 */

using SentinelGrid.ControlPlane.Domain;
using System.Buffers.Binary;

namespace SentinelGrid.ControlPlane.Protocol;

/**
 * @class EngineMessageDecoder
 * @brief A static class that provides methods for decoding engine messages in the SentinelGrid Control Plane protocol.
 *
 * The EngineMessageDecoder class contains methods for decoding engine messages received in the SentinelGrid Control Plane protocol.
 * It validates the message structure, extracts relevant information, and returns the decoded result along with any potential errors.
 */
public static class EngineMessageDecoder
{
    /**
     * @brief Decodes an engine message from a byte span.
     * @param packet The byte span containing the engine message to decode.
     * @returns An EngineDecodeResult containing the decoded message and any potential errors.
     *
     * This method decodes an engine message from the provided byte span. It validates the message structure,
     * extracts relevant information, and returns the decoded result along with any potential errors.
     */
    public static EngineDecodeResult Decode(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < EngineProtocolConstants.HeaderSize)
            return new EngineDecodeResult(null, EngineDecodeError.PacketTooSmall);

        int offset = 0;

        uint magic = BinaryPrimitives.ReadUInt32BigEndian(packet);
        if (magic != EngineProtocolConstants.MagicNumber)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidMagic);

        offset += sizeof(uint);

        ushort version = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset, sizeof(ushort)));
        if (version != EngineProtocolConstants.SupportedVersion)
            return new EngineDecodeResult(null, EngineDecodeError.UnsupportedVersion);

        offset += sizeof(ushort);

        ushort rawMessageType = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset, sizeof(ushort)));
        EngineMessageTypes messageType = (EngineMessageTypes) rawMessageType;
        if (Enum.IsDefined<EngineMessageTypes>((EngineMessageTypes) messageType) is false)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidMessageType);

        offset += sizeof(ushort);
        uint declaredPayloadSize = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(offset, sizeof(uint)));

        uint expectedPayloadSize = messageType switch
        {
            EngineMessageTypes.SecurityEvent => EngineProtocolConstants.EventPayloadSize,
            EngineMessageTypes.SecurityAlert => EngineProtocolConstants.AlertPayloadSize,
            _ => 0
        };

        if (declaredPayloadSize != expectedPayloadSize)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidPayloadLength);

        if (packet.Length != expectedPayloadSize + EngineProtocolConstants.HeaderSize)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidPacketSize);

        offset += sizeof(uint);

        ReadOnlySpan<byte> payload = packet.Slice(offset, (int)expectedPayloadSize);

        return messageType switch
        {
            EngineMessageTypes.SecurityEvent => DecodeEvent(payload),
            EngineMessageTypes.SecurityAlert => DecodeAlert(payload),
            _ => new EngineDecodeResult(null, EngineDecodeError.InvalidMessageType)
        };
    }

    /**
     * @brief Decodes a security event from a byte span.
     * @param payload The byte span containing the security event payload to decode.
     * @returns An EngineDecodeResult containing the decoded SecurityEvent and any potential errors.
     *
     * This method decodes a security event from the provided byte span. It validates the event structure,
     * extracts relevant information, and returns the decoded result along with any potential errors.
     */
    private static EngineDecodeResult DecodeEvent(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        uint agentId = BinaryPrimitives.ReadUInt32BigEndian(payload);
        if (agentId == 0)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidAgentId);

        offset += sizeof(uint);
        ulong sequence = BinaryPrimitives.ReadUInt64BigEndian(payload.Slice(offset, sizeof(ulong)));
        if (sequence == 0)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidSequenceNumber);

        offset += sizeof(ulong);
        uint eventType = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset, sizeof(uint)));
        if (Enum.IsDefined<EventTypes>((EventTypes) eventType) is false)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidEventType);

        return new EngineDecodeResult(new SecurityEvent(agentId, sequence, (EventTypes) eventType), EngineDecodeError.None);
    }

    /**
     * @brief Decodes a security alert from a byte span.
     * @param payload The byte span containing the security alert payload to decode.
     * @returns An EngineDecodeResult containing the decoded SecurityAlert and any potential errors.
     *
     * This method decodes a security alert from the provided byte span. It validates the alert structure,
     * extracts relevant information, and returns the decoded result along with any potential errors.
     */
    private static EngineDecodeResult DecodeAlert(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        uint alertType = BinaryPrimitives.ReadUInt32BigEndian(payload);
        if (Enum.IsDefined<AlertTypes>((AlertTypes) alertType) is false)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidAlertType);

        offset += sizeof(uint);
        uint alertSeverity = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset, sizeof(uint)));
        if (Enum.IsDefined<AlertSeverities>((AlertSeverities)alertSeverity) is false)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidSeverity);

        offset += sizeof(uint);
        uint agentId = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset, sizeof(uint)));
        if (agentId == 0)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidAgentId);

        offset += sizeof(uint);
        ulong sequence = BinaryPrimitives.ReadUInt64BigEndian(payload.Slice(offset, sizeof(ulong)));
        if (sequence == 0)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidSequenceNumber);

        offset += sizeof(ulong);
        uint failures = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(offset, sizeof(uint)));
        if (failures == 0)
            return new EngineDecodeResult(null, EngineDecodeError.InvalidFailureCount);

        return new EngineDecodeResult(new SecurityAlert((AlertTypes) alertType, (AlertSeverities) alertSeverity, agentId, sequence, failures), EngineDecodeError.None);
    }
}
