using System;
using System.Collections.Generic;
using System.Text;

namespace SentinelGrid.ControlPlane.Protocol;

public enum EngineDecodeError
{
    None,
    PacketTooSmall,
    InvalidPacketSize,
    InvalidMagic,
    UnsupportedVersion,
    InvalidMessageType,
    InvalidPayloadLength,
    InvalidAgentId,
    InvalidSequenceNumber,
    InvalidEventType,
    InvalidAlertType,
    InvalidSeverity,
    InvalidFailureCount
}
