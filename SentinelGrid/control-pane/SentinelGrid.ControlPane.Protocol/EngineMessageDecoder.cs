using SentinelGrid.ControlPane.Domain;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace SentinelGrid.ControlPane.Protocol;

public static class EngineMessageDecoder
{
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
